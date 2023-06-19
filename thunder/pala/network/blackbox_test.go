// Use a different package to ensure we only test the public API.
package network_test

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/msggroup"
	. "github.com/ethereum/go-ethereum/thunder/pala/network"
	"github.com/ethereum/go-ethereum/thunder/pala/testutils"
	"github.com/ethereum/go-ethereum/thunder/pala/testutils/detector"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"

	"github.com/stretchr/testify/require"
)

const networkId = uint64(123)

func getNextPort() string {
	return fmt.Sprintf("%d", testutils.NextTestingPort(testutils.TestGroupNetwork))
}

func verifyHandshakeError(req *require.Assertions, ch chan *Message, expectedError error) {
	select {
	case m := <-ch:
		req.Equal(AttrHandshakeError, m.GetAttribute())
		req.IsType(expectedError, m.GetError())
	case <-time.NewTimer(100 * time.Millisecond).C:
		req.FailNow("no error message")
	}
}

func waitOneMessage(req *require.Assertions, ch chan *Message) *Message {
	select {
	case m := <-ch:
		return m
	case <-time.NewTimer(100 * time.Millisecond).C:
		req.FailNow("no message")
	}
	return nil
}

func verifyOpen(req *require.Assertions, ch chan *Message) ConsensusId {
	m := waitOneMessage(req, ch)
	req.Equal(AttrOpen, m.GetAttribute())
	return m.GetId()
}

func verifyClosed(req *require.Assertions, ch chan *Message) ConsensusId {
	m := waitOneMessage(req, ch)
	req.Equal(AttrClosed, m.GetAttribute())
	return m.GetId()
}

func verifyMessage(
	req *require.Assertions, ch chan *Message, expected *Message, expectedId ConsensusId) {
	select {
	case m := <-ch:
		req.Equal(expectedId, m.GetId(), m.GetId())
		req.Equal(expected.GetType(), m.GetType(), m.GetId())
		req.Equal(expected.GetBlob(), m.GetBlob(), m.GetId())
	case <-time.NewTimer(100 * time.Millisecond).C:
		req.FailNow("no message")
	}
}

type builder struct {
	id          ConsensusId
	config      Config
	fakeNetwork bool
	ch          chan *Message
}

func newBuilder(id string) *builder {
	sink := NewMultiplexer()
	ch := MakeChannelForAllMessages(sink)
	myId := ConsensusId(id)
	cfg := Config{
		LoggingId:          id,
		ProtocolVersion:    ProtocolVersion,
		NetworkId:          networkId,
		Role:               RoleHub,
		ConnectingConfig:   DefaultConnectingConfig,
		Authenticator:      &AuthenticatorFake{myId},
		Sink:               sink,
		Clock:              NewClock(),
		ClientPuzzleMgrCfg: GetClientPuzzleMgrCfgForTest(),
	}
	return &builder{id: myId, config: cfg, ch: ch}
}

func (b *builder) asSpoke() *builder {
	b.config.Role = RoleSpoke
	return b
}

func (b *builder) useFakeNetwork() *builder {
	b.fakeNetwork = true
	return b
}

func (b *builder) setProtocolVersion(v uint16) *builder {
	b.config.ProtocolVersion = v
	return b
}

func (b *builder) setNetworkId(nid uint64) *builder {
	b.config.NetworkId = nid
	return b
}

func (b *builder) setResolver(r DomainNameResolver) *builder {
	b.config.DomainNameResolver = r
	return b
}

func (b *builder) setClientPuzzleMgrCfg(cfg *ClientPuzzleMgrCfg) *builder {
	b.config.ClientPuzzleMgrCfg = cfg
	return b
}

func (b *builder) build() (*hostForTest, error) {
	h := NewHost(b.config)
	if b.config.Role == RoleHub && !b.fakeNetwork {
		if err := h.StartAccepting("127.0.0.1:" + getNextPort()); err != nil {
			return nil, err
		}
	}
	return &hostForTest{h, b.id, b.ch, h.GetBoundIPPort()}, nil
}

//------------------------------------------------------------------------------

func TestBroadcast(t *testing.T) {
	d := detector.NewBundleDetector()
	d.SetTrace()
	defer d.Verify(t)

	//
	// Prepare
	//
	req := require.New(t)

	var hubSinks []chan *Message
	var hubs []*Host
	for i := 0; i < 3; i++ {
		h, _ := newBuilder(fmt.Sprintf("h%d", i)).useFakeNetwork().build()
		hubSinks = append(hubSinks, h.ch)
		hubs = append(hubs, h.host)

		// Prepare connections between hubs
		for j := 0; j < i; j++ {
			FakeConnect(hubs[j], hubs[i])
			m := <-hubSinks[j]
			req.Equal(AttrOpen, m.GetAttribute(), fmt.Sprintf("%d -> %d", j, i))

			m = <-hubSinks[i]
			req.Equal(AttrOpen, m.GetAttribute())
		}
	}

	defer func() {
		for _, hub := range hubs {
			hub.CloseAllConnections()
		}
	}()

	// Prepare spokes
	var hubSpokePairs []ConnectionFakePair
	var spokeSinks []chan *Message
	var spokes []*Host
	for i := 0; i < 4; i++ {
		h, _ := newBuilder(fmt.Sprintf("s%d", i)).asSpoke().useFakeNetwork().build()
		spokeSinks = append(spokeSinks, h.ch)
		// Prepare connections between hubs and spokes.
		for j := 0; j < len(hubs); j++ {
			pair := FakeConnect(h.host, hubs[j])
			m := <-hubSinks[j]
			req.Equal(AttrOpen, m.GetAttribute())

			m = <-h.ch
			req.Equal(AttrOpen, m.GetAttribute())

			hubSpokePairs = append(hubSpokePairs, pair)
		}

		spokes = append(spokes, h.host)
	}

	for i := 0; i < len(hubs); i++ {
		req.Equal(len(hubs)-1+len(spokes), hubs[i].GetNumConnections())
	}

	for i := 0; i < len(spokes); i++ {
		req.Equal(len(hubs), spokes[i].GetNumConnections())
	}

	// Test
	t.Run("direct broadcast", func(t *testing.T) {
		req := require.New(t)
		senderIndex := 1
		inputs := []string{"hello", "world"}
		for i := 0; i < len(inputs); i++ {
			m := NewMessage(1, 0, []byte(inputs[i]))
			n, err := hubs[senderIndex].Broadcast(m, nil)
			req.NoError(err)
			req.Equal(uint(len(hubs)+len(spokes)-1), n)
		}

		// Verify hubs.
		for i := 0; i < len(hubSinks); i++ {
			if i == senderIndex {
				continue
			}
			for j := 0; j < len(inputs); j++ {
				m := <-hubSinks[i]
				req.Equal(inputs[j], string(m.GetBlob()))
			}
		}

		// Verify spokes.
		for i := 0; i < len(spokeSinks); i++ {
			for j := 0; j < len(inputs); j++ {
				m := <-spokeSinks[i]
				req.Equal(inputs[j], string(m.GetBlob()))
			}
		}
	})

	t.Run("direct send", func(t *testing.T) {
		req := require.New(t)
		inputs := []string{"send hello", "send world"}
		senderIndex := 1
		for i := 0; i < len(inputs); i++ {
			m := NewMessage(1, 0, []byte(inputs[i]))
			err := spokes[senderIndex].Send("h0", m)
			req.NoError(err)
		}

		// Verify hub.
		for i := 0; i < len(inputs); i++ {
			// Expect hubSinks[0] receives the message because we call SendToFirstHubForTest().
			m := <-hubSinks[0]
			req.Equal(inputs[i], string(m.GetBlob()))
		}
		for i := 0; i < len(hubSinks); i++ {
			select {
			case <-hubSinks[i]:
				req.FailNow("received data from a hub")
			case <-time.After(10 * time.Millisecond):
				// Expect no data. Pass.
			}
		}

		// Verify spokes.
		for i := 0; i < len(spokeSinks); i++ {
			select {
			case <-spokeSinks[i]:
				req.FailNow("received data from a spoke")
			case <-time.After(10 * time.Millisecond):
				// Expect no data. Pass.
			}
		}
	})

	t.Run("close", func(t *testing.T) {
		req := require.New(t)

		for _, pair := range hubSpokePairs {
			pair.Close()
		}

		// Wait for the end of the read goroutines.
		for i := 0; i < len(hubSinks); i++ {
			for j := 0; j < len(spokes); j++ {
				m := <-hubSinks[i]
				req.Equal(AttrClosed, m.GetAttribute())
			}
		}
		for i := 0; i < len(spokeSinks); i++ {
			for j := 0; j < len(hubs); j++ {
				m := <-spokeSinks[i]
				req.Equal(AttrClosed, m.GetAttribute())
			}
		}

		for i := 0; i < len(hubs); i++ {
			req.Equal(len(hubs)-1, hubs[i].GetNumConnections(), "hub %d", i)
		}

		for i := 0; i < len(spokes); i++ {
			req.Equal(0, spokes[i].GetNumConnections(), "spoke %d", i)
		}
	})
}

func TestBroadcastWithoutAnyHost(t *testing.T) {
	d := detector.NewBundleDetector()
	d.SetTrace()
	defer d.Verify(t)

	req := require.New(t)

	// Test spoke
	h, _ := newBuilder("s1").asSpoke().useFakeNetwork().build()
	m := NewMessage(1, 0, []byte("hello"))
	n, err := h.host.Broadcast(m, nil)
	req.Error(err)
	req.Zero(n)

	// Test hub
	h, _ = newBuilder("s1").useFakeNetwork().build()
	n, err = h.host.Broadcast(m, nil)
	req.Error(err)
	req.Zero(n)
}

func TestMain(m *testing.M) {
	original, _ := lgr.GetLogLevel("/")
	lgr.SetLogLevel("/", lgr.LvlWarning)
	defer func() {
		lgr.SetLogLevel("/", original)
	}()
	os.Exit(m.Run())
}

func TestUsingSockets(t *testing.T) {
	req := require.New(t)

	h, err := newBuilder("h1").build()
	req.NoError(err)
	hub, hubCh, address := h.host, h.ch, h.addr
	defer func() {
		err := hub.StopAccepting()
		req.NoError(err)
		hub.CloseAllConnections()
		verifyClosed(req, hubCh)
	}()

	// Prepare spokes
	var spokeSinks []chan *Message
	var spokes []*Host
	for i := 0; i < 2; i++ {
		h, _ := newBuilder(fmt.Sprintf("s%d", i)).asSpoke().build()
		err := h.host.ConnectForTest("h1", address, OneInGroup)
		req.NoError(err)

		m := <-hubCh
		req.Equal(AttrOpen, m.GetAttribute())

		m = <-h.ch
		req.Equal(AttrOpen, m.GetAttribute())

		spokes = append(spokes, h.host)
	}

	// Broadcast.
	inputs := []string{"hello", "world"}
	for i := 0; i < len(inputs); i++ {
		m := NewMessage(1, 0, []byte(inputs[i]))
		n, err := hub.Broadcast(m, nil)
		req.NoError(err)
		req.Equal(uint(2), n)
	}

	// Verify spokes.
	for i := 0; i < len(spokeSinks); i++ {
		for j := 0; j < len(inputs); j++ {
			m := <-spokeSinks[i]
			req.Equal(inputs[j], string(m.GetBlob()))
		}
	}

	for _, spoke := range spokes {
		spoke.CloseAllConnections()
	}

	for _, sink := range spokeSinks {
		verifyClosed(req, sink)
	}
}

type hostForTest struct {
	host *Host
	id   ConsensusId
	ch   chan *Message
	addr string
}

type MitmHost struct {
	req             *require.Assertions
	remoteAddr      string
	listenAddr      string
	swapCertificate bool
	listener        net.Listener
	in              net.Conn
	out             net.Conn
	clk             Clock
}

func newMitmHost(req *require.Assertions, address string, swapCertificate bool) *MitmHost {
	return &MitmHost{
		req:             req,
		remoteAddr:      address,
		swapCertificate: swapCertificate,
		clk:             NewClock(),
	}
}

func (h *MitmHost) StartAccepting(address string) error {
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return err
	}

	var mitmAddr string
	if h.swapCertificate {
		mitmAddr, err = h.dialMitmConnection(addr)
		if err != nil {
			return err
		}
	} else {
		mitmAddr, err = h.dialTCPProxy(addr)
		if err != nil {
			return err
		}
	}

	h.listenAddr = mitmAddr
	return nil
}

func (h *MitmHost) dialTCPProxy(addr *net.TCPAddr) (string, error) {

	listener, err := net.Listen("tcp", addr.String())
	if err != nil {
		return "", err
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				break
			}
			h.handleTCPProxy(conn)
		}
	}()

	h.listener = listener
	return listener.Addr().String(), nil
}

func (h *MitmHost) dialMitmConnection(addr *net.TCPAddr) (string, error) {
	_, certPem, privPem, err := GenerateSelfSignedCert(h.clk, "thunderServer2")
	if err != nil {
		return "", err
	}

	cert, err := tls.X509KeyPair(certPem, privPem)
	if err != nil {
		return "", err
	}

	listener, err := tls.Listen(
		"tcp",
		addr.String(),
		&tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	)
	if err != nil {
		return "", err
	}

	go func() {
		conn, _ := listener.Accept()
		h.handleMitmConnection(conn, cert)
	}()

	h.listener = listener
	return listener.Addr().String(), nil
}

func (h *MitmHost) handleMitmConnection(conn net.Conn, cert tls.Certificate) {
	// Create a connection to attack addr with new cert.
	var (
		err     error
		outConn *tls.Conn
	)

	for {
		outConn, err = tls.Dial(
			"tcp",
			h.remoteAddr,
			&tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{cert},
			},
		)

		if err == nil {
			break
		}
	}

	go h.copyConn(conn, outConn)
}

func (h *MitmHost) handleTCPProxy(conn net.Conn) {
	var (
		err     error
		outConn net.Conn
	)

	for {
		outConn, err = net.Dial("tcp", h.remoteAddr)

		if err == nil {
			break
		}
	}

	go h.copyConn(conn, outConn)
}

func (h *MitmHost) copyConn(in, out net.Conn) {
	req := h.req
	var wg sync.WaitGroup
	// Records connections into struct in order to be close by `Done` function.
	h.in = in
	h.out = out

	wg.Add(1)
	go func() {
		defer in.Close()
		defer out.Close()
		_, err := io.Copy(in, out)
		if !IsClosedError(err) {
			req.NoError(err)
		}
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		defer in.Close()
		defer out.Close()
		_, err := io.Copy(out, in)
		if !IsClosedError(err) {
			req.NoError(err)
		}
		wg.Done()
	}()

	wg.Wait()
}

func (h *MitmHost) Done() {
	h.listener.Close()
	h.in.Close()
	h.out.Close()
}

func TestHandshake(t *testing.T) {
	createHub := func(req *require.Assertions, id string, protocolVersion uint16, networkId uint64,
		clientPuzzleMgrCfg *ClientPuzzleMgrCfg,
	) (*Host, chan *Message, string) {
		host, err := newBuilder(id).setProtocolVersion(protocolVersion).setNetworkId(networkId).
			setClientPuzzleMgrCfg(clientPuzzleMgrCfg).build()
		req.NoError(err)
		return host.host, host.ch, host.addr
	}

	createMitmHub := func(req *require.Assertions, attackAddr string, swapCertificate bool) *MitmHost {
		mitmHost := newMitmHost(req, attackAddr, swapCertificate)
		err := mitmHost.StartAccepting("127.0.0.1:" + getNextPort())
		req.NoError(err)
		return mitmHost
	}

	createSpoke := func(id string, protocolVersion uint16, networkId uint64,
		clientPuzzleMgrCfg *ClientPuzzleMgrCfg,
	) (*Host, chan *Message) {
		host, _ := newBuilder(id).setProtocolVersion(protocolVersion).setNetworkId(networkId).
			setClientPuzzleMgrCfg(clientPuzzleMgrCfg).asSpoke().build()
		return host.host, host.ch
	}

	t.Run("normal", func(t *testing.T) {
		d := detector.NewBundleDetector()
		d.SetTrace()
		defer d.Verify(t)

		req := require.New(t)

		hub, hubSink, address := createHub(req, "h1", 1, 123, GetClientPuzzleMgrCfgForTest())
		spoke, spokeSink := createSpoke("s1", 1, 123, GetClientPuzzleMgrCfgForTest())

		defer func() {
			err := hub.StopAccepting()
			req.NoError(err)

			hub.CloseAllConnections()
			spoke.CloseAllConnections()
			verifyClosed(req, hubSink)
			verifyClosed(req, spokeSink)
		}()

		err := spoke.ConnectForTest("h1", address, OneInGroup)
		req.NoError(err)

		verifyOpen(req, hubSink)
		verifyOpen(req, spokeSink)
	})

	t.Run("check protocol version", func(t *testing.T) {
		d := detector.NewBundleDetector()
		d.SetTrace()
		defer d.Verify(t)

		req := require.New(t)

		version := uint16(3)
		hub, hubSink, address := createHub(req, "h1", version, 123, GetClientPuzzleMgrCfgForTest())
		defer func() {
			err := hub.StopAccepting()
			req.NoError(err)
			hub.CloseAllConnections()
		}()

		// version-1 is compatible.
		version--
		spoke, spokeSink := createSpoke("s1", version, 123, GetClientPuzzleMgrCfgForTest())
		err := spoke.ConnectForTest("h1", address, OneInGroup)
		req.NoError(err)

		verifyOpen(req, hubSink)
		verifyOpen(req, spokeSink)

		// version-2 is not compatible.
		version--
		spoke, spokeSink = createSpoke("s2", version, 123, GetClientPuzzleMgrCfgForTest())
		err = spoke.ConnectForTest("h1", address, OneInGroup)
		req.NoError(err)

		verifyHandshakeError(req, hubSink, HandShakeError{})
		verifyHandshakeError(req, spokeSink, HandShakeError{})
	})

	t.Run("check network id", func(t *testing.T) {
		d := detector.NewBundleDetector()
		d.SetTrace()
		defer d.Verify(t)

		req := require.New(t)

		hub, hubSink, address := createHub(req, "h1", 0, 123, GetClientPuzzleMgrCfgForTest())
		defer func() {
			err := hub.StopAccepting()
			req.NoError(err)
		}()

		spoke, spokeSink := createSpoke("s1", 0, 456, GetClientPuzzleMgrCfgForTest())

		err := spoke.ConnectForTest("h1", address, OneInGroup)
		req.NoError(err)

		verifyHandshakeError(req, hubSink, HandShakeError{})
		verifyHandshakeError(req, spokeSink, HandShakeError{})
	})

	t.Run("check client puzzle", func(t *testing.T) {
		d := detector.NewBundleDetector()
		d.SetTrace()
		defer d.Verify(t)

		req := require.New(t)

		clientPuzzleMgrCfg := &ClientPuzzleMgrCfg{
			Preference: []string{FailingPuzzleName},
			Difficulty: 0,
		}
		hub, hubSink, address := createHub(req, "h1", 0, 123, clientPuzzleMgrCfg)
		defer func() {
			err := hub.StopAccepting()
			req.NoError(err)
		}()

		spoke, spokeSink := createSpoke("s1", 0, 123, clientPuzzleMgrCfg)

		err := spoke.ConnectForTest("h1", address, OneInGroup)
		req.NoError(err)

		verifyHandshakeError(req, hubSink, ClientPuzzleError{})
		verifyHandshakeError(req, spokeSink, TLSVerifyError{})
	})

	t.Run("check man-in-the-middle attacks with changed cert", func(t *testing.T) {
		d := detector.NewBundleDetector()
		d.SetTrace()
		defer d.Verify(t)

		req := require.New(t)

		hub, hubSink, hubAddr := createHub(req, "h1", 1, 123, GetClientPuzzleMgrCfgForTest())
		defer func() {
			err := hub.StopAccepting()
			req.NoError(err)
		}()

		mitmHub := createMitmHub(req, hubAddr, true)
		defer mitmHub.Done()

		spoke, spokeSink := createSpoke("s1", 1, 123, GetClientPuzzleMgrCfgForTest())

		err := spoke.ConnectForTest("h1", mitmHub.listenAddr, OneInGroup)
		req.NoError(err)

		verifyHandshakeError(req, hubSink, TLSVerifyError{})
		verifyHandshakeError(req, spokeSink, TLSVerifyError{})
	})

	t.Run("check man-in-the-middle attacks with original cert", func(t *testing.T) {
		d := detector.NewBundleDetector()
		d.SetTrace()
		defer d.Verify(t)

		req := require.New(t)

		hub, hubSink, hubAddr := createHub(req, "h1", 1, 123, GetClientPuzzleMgrCfgForTest())
		defer func() {
			err := hub.StopAccepting()
			req.NoError(err)
		}()

		mitmHub := createMitmHub(req, hubAddr, false)
		defer mitmHub.Done()

		spoke, spokeSink := createSpoke("s1", 1, 123, GetClientPuzzleMgrCfgForTest())

		err := spoke.ConnectForTest("h1", mitmHub.listenAddr, OneInGroup)
		req.NoError(err)

		verifyOpen(req, hubSink)
		verifyOpen(req, spokeSink)
	})
}

// TestClientHandshakeCancel tests the scenario where the PaLa
// challenge-response handshake blocks and the connecting side cancels.
func TestClientHandshakeCancel(t *testing.T) {
	req := require.New(t)
	port := 4567
	address := fmt.Sprintf("localhost:%d", port)

	l, err := net.Listen("tcp", address)
	req.NoError(err)

	sink := NewMultiplexer()
	eventCh := make(chan *Message, 1024)
	err = sink.Subscribe(msggroup.NetworkMsg, eventCh)
	req.NoError(err)
	id := ConsensusId("s0")
	h := NewHost(Config{
		LoggingId:                      string(id),
		NetworkId:                      123,
		Role:                           RoleSpoke,
		ConnectingConfig:               DefaultConnectingConfig,
		Authenticator:                  &AuthenticatorFake{id},
		Sink:                           sink,
		Clock:                          NewClock(),
		SendUnverifiedConnectionEvents: true,
		ClientPuzzleMgrCfg:             GetClientPuzzleMgrCfgForTest(),
	})

	wg := sync.WaitGroup{}

	wg.Add(1)
	go func(l net.Listener, h *Host) {
		defer wg.Done()
		_, err := l.Accept()
		req.NoError(err)
		h.CloseAllConnections()
	}(l, h)

	h.ConnectAsync("h0", address, OneInGroup)
	m := <-eventCh
	req.Equal(m.GetAttribute(), AttrUnverifiedConnection)

	wg.Wait()
}

// TestServerHandshakeCancel tests the scenario where the PaLa
// challenge-response handshake blocks and the accepting side cancels.
func TestServerHandshakeCancel(t *testing.T) {
	req := require.New(t)
	port := 4568
	address := fmt.Sprintf("localhost:%d", port)

	sink := NewMultiplexer()
	eventCh := make(chan *Message, 1024)
	err := sink.Subscribe(msggroup.NetworkMsg, eventCh)
	req.NoError(err)
	id := ConsensusId("h0")
	h := NewHost(Config{
		LoggingId:                      string(id),
		NetworkId:                      123,
		Role:                           RoleHub,
		ConnectingConfig:               DefaultConnectingConfig,
		Authenticator:                  &AuthenticatorFake{id},
		Sink:                           sink,
		Clock:                          NewClock(),
		SendUnverifiedConnectionEvents: true,
		ClientPuzzleMgrCfg:             GetClientPuzzleMgrCfgForTest(),
	})

	d := &net.Dialer{}

	wg := sync.WaitGroup{}
	err = h.StartAccepting(address)
	req.NoError(err)

	wg.Add(1)
	go func(d *net.Dialer, h *Host) {
		defer wg.Done()
		m := <-eventCh
		req.Equal(m.GetAttribute(), AttrUnverifiedConnection)
		h.CloseAllConnections()
	}(d, h)

	for {
		_, err = d.Dial("tcp", address)
		if err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}

	wg.Wait()
}

func TestDuplicatedConnections(t *testing.T) {
	req := require.New(t)

	// ids[1] and ids[2] use the same id.
	ids := []ConsensusId{"h0", "h1", "h1"}
	var hs []*hostForTest
	for i := 0; i < len(ids); i++ {
		id := ids[i]
		host, err := newBuilder(string(id)).build()
		req.NoError(err)
		defer func() {
			err := host.host.StopAccepting()
			req.NoError(err)
			host.host.CloseAllConnections()
		}()
		hs = append(hs, host)
	}

	err := hs[0].host.ConnectForTest(ids[1], hs[1].addr, OneInGroup)
	req.NoError(err)

	verifyOpen(req, hs[0].ch)
	verifyOpen(req, hs[1].ch)

	//
	// Test connecting twice.
	//
	err = hs[0].host.ConnectForTest(ids[2], hs[2].addr, OneInGroup)
	req.Error(err) // Reject due to the same connect id.

	// Skip connect id to cause duplciated connections.
	err = hs[0].host.ConnectForTest("", hs[1].addr, OneInGroup)
	req.Error(err) // Reject due to the same addr.

	//
	// Test connecting to each other.
	//
	err = hs[1].host.ConnectForTest(ids[0], hs[0].addr, OneInGroup)
	req.Error(err) // Reject due to the same connect id.

	// Skip connect id to cause duplciated connections.
	err = hs[1].host.ConnectForTest("", hs[0].addr, OneInGroup)
	req.NoError(err)

	verifyClosed(req, hs[0].ch)
	verifyOpen(req, hs[0].ch)

	verifyClosed(req, hs[1].ch)
	verifyOpen(req, hs[1].ch)

	//
	// Test connecting to each other.
	//
	err = hs[0].host.ConnectForTest("", hs[1].addr, OneInGroup)
	req.Error(err) // Reject due to the same address (remembered in the last connection).
}

func TestGroupConnectedness(t *testing.T) {
	d := detector.NewBundleDetector()
	d.SetTrace()
	defer d.Verify(t)

	newHosts := func(idPrefix string, numNodes int, domainNameAddress string, r *DomainNameResolverFake,
	) ([]*hostForTest, error) {
		var hs []*hostForTest
		for i := 0; i < numNodes; i++ {
			h, err := newBuilder(fmt.Sprintf("%s%d", idPrefix, i)).setResolver(r).build()
			if err != nil {
				return nil, err
			}
			r.Add(domainNameAddress, h.host.GetBoundIPPort())
			hs = append(hs, h)
		}
		return hs, nil
	}

	t.Run("one host and one group connect to each other", func(t *testing.T) {
		req := require.New(t)

		const address = "test.b.com"

		r := NewDomainNameResolverFake()
		a, err := newBuilder("a0").setResolver(r).build()
		defer func() {
			a.host.StopAccepting()
			a.host.CloseAllConnections()
		}()
		req.NoError(err)
		bs, err := newHosts("b", 2, address, r.(*DomainNameResolverFake))
		req.NoError(err)
		defer func() {
			for i := 0; i < len(bs); i++ {
				bs[i].host.StopAccepting()
				bs[i].host.CloseAllConnections()
			}
		}()

		// Test connection: a -> bi
		err = a.host.ConnectForTest("", address, AllInGroup)
		req.NoError(err)
		for i := 0; i < len(bs); i++ {
			verifyOpen(req, a.ch)
			verifyOpen(req, bs[i].ch)
		}

		verifyBroadcastMessages := func(msg string) {
			m := NewMessage(1, 0, []byte(msg))
			n, err := a.host.Broadcast(m, nil)
			req.NoError(err)
			req.Equal(len(bs), int(n))

			for _, b := range bs {
				verifyMessage(req, b.ch, m, a.id)
			}
		}

		verifyBroadcastMessages("hello")

		// Test duplicated connections: bi -> a
		// Since the connecting direction is reverse, the new connection will be established
		// and the old one will be dropped.
		for _, b := range bs {
			err := b.host.ConnectForTest("", a.addr, OneInGroup)
			req.NoError(err)
			verifyClosed(req, a.ch)
			verifyOpen(req, a.ch)
		}

		for _, b := range bs {
			verifyClosed(req, b.ch)
			verifyOpen(req, b.ch)
		}
		verifyBroadcastMessages("world")

		// Test duplicated connections: a -> bi
		// Since a <-> bi has connected to each other once, both of them know the other side's
		// connecting address and verified id, so the connect will fail at the beginning.
		err = a.host.ConnectForTest("", address, AllInGroup)
		req.Error(err)

		// Test duplicated connections: bi -> a
		// The connect will fail at the beginning. The reason is the same as above.
		for _, b := range bs {
			err := b.host.ConnectForTest("", a.addr, OneInGroup)
			req.Error(err)
		}

		// Test that domain name records are updated.
		// Add a new one.
		b, err := newBuilder(fmt.Sprintf("b%d", len(bs))).setResolver(r).build()
		req.NoError(err)
		defer func() {
			b.host.StopAccepting()
			b.host.CloseAllConnections()
		}()
		bs = append(bs, b)
		r.(*DomainNameResolverFake).Add(address, b.host.GetBoundIPPort())
		// Remove an old one. Note that this does NOT affect the result.
		// To simplify the implementation, nodes don't drop connections after the DNS record is removed.
		r.(*DomainNameResolverFake).Remove(address, bs[0].addr)

		err = a.host.ConnectForTest("", address, AllInGroup)
		req.Error(err)
		cerr, ok := err.(*ConnectError)
		req.True(ok)
		// One old record is removed and one new record is added.
		// The remaining addresses result in duplicated connection errors.
		req.Equal(len(bs)-1-1, len(cerr.Errors))
		id := verifyOpen(req, a.ch)
		req.Equal(b.id, id)

		verifyOpen(req, b.ch)
		verifyBroadcastMessages("hello world")
	})

	t.Run("two groups connect to each other", func(t *testing.T) {
		req := require.New(t)

		const (
			addressA = "test.a.com"
			addressB = "test.b.com"
		)

		r := NewDomainNameResolverFake()
		as, err := newHosts("a", 2, addressA, r.(*DomainNameResolverFake))
		req.NoError(err)
		bs, err := newHosts("b", 3, addressB, r.(*DomainNameResolverFake))
		req.NoError(err)

		// Test connection: ai -> bi
		for i := 0; i < len(as); i++ {
			err = as[i].host.ConnectForTest("", addressB, AllInGroup)
			req.NoError(err)
			for j := 0; j < len(bs); j++ {
				verifyOpen(req, as[i].ch)
			}
		}
		defer func() {
			for i := 0; i < len(as); i++ {
				as[i].host.StopAccepting()
				as[i].host.CloseAllConnections()
			}
			for i := 0; i < len(bs); i++ {
				bs[i].host.StopAccepting()
				bs[i].host.CloseAllConnections()
			}
		}()

		for i := 0; i < len(bs); i++ {
			for j := 0; j < len(as); j++ {
				verifyOpen(req, bs[i].ch)
			}
		}

		verifyBroadcastMessages := func() {
			a := as[0]
			m := NewMessage(1, 0, []byte("hello"))
			n, err := a.host.Broadcast(m, nil)
			req.NoError(err)
			req.Equal(len(bs), int(n))
			for _, b := range bs {
				verifyMessage(req, b.ch, m, a.id)
			}

			a = as[1]
			m = NewMessage(1, 0, []byte("world"))
			n, err = a.host.Broadcast(m, nil)
			req.NoError(err)
			req.Equal(len(bs), int(n))
			for _, b := range bs {
				verifyMessage(req, b.ch, m, a.id)
			}
		}

		verifyBroadcastMessages()

		// Test connection: bi -> ai
		for i := 0; i < len(bs); i++ {
			err = bs[i].host.ConnectForTest("", addressA, AllInGroup)
			req.NoError(err)
			// The order may be "Closed, Open, Closed Open"
			// or "Closed, Closed, Open, Open". We skip the detailed verification to simplify tests.
			for j := 0; j < len(as)*2; j++ {
				m := waitOneMessage(req, bs[i].ch)
				attr := m.GetAttribute()
				req.True(attr == AttrOpen || attr == AttrClosed)
			}
		}

		for i := 0; i < len(as); i++ {
			for j := 0; j < len(bs)*2; j++ {
				m := waitOneMessage(req, as[i].ch)
				attr := m.GetAttribute()
				req.True(attr == AttrOpen || attr == AttrClosed)
			}
		}

		verifyBroadcastMessages()

		// Test connection: ai -> bi
		// This is NOP because each end has remembered the remote end's connect IP.
		for i := 0; i < len(as); i++ {
			err = as[i].host.ConnectForTest("", addressB, AllInGroup)
			req.Error(err)
		}

		// Test connection: bi -> ai
		// This is NOP because each end has remembered the remote end's connect IP.
		for i := 0; i < len(bs); i++ {
			err = bs[i].host.ConnectForTest("", addressA, AllInGroup)
			req.Error(err)
		}
	})

	t.Run("connect to my group", func(t *testing.T) {
		req := require.New(t)

		const address = "test.a.com"

		r := NewDomainNameResolverFake()
		as, err := newHosts("a", 3, address, r.(*DomainNameResolverFake))
		req.NoError(err)
		defer func() {
			for i := 0; i < len(as); i++ {
				as[i].host.StopAccepting()
				as[i].host.CloseAllConnections()
			}
		}()

		as[0].host.ConnectForTest("", address, AllInGroup)
		for i, a := range as {
			if i == 0 {
				continue
			}
			verifyOpen(req, a.ch)
		}
		numHandshakeErrors := 0
		for i := 0; i < len(as)+1; i++ {
			m := waitOneMessage(req, as[0].ch)
			attr := m.GetAttribute()
			req.True(attr == AttrOpen || attr == AttrHandshakeError)
			if attr == AttrHandshakeError {
				numHandshakeErrors++
				req.Equal(ErrConnectedToSelf, m.GetError())
			}
		}
		// One error from "connect" and the other error from "accept".
		req.Equal(2, numHandshakeErrors)

		m := NewMessage(1, 0, []byte("hello"))
		n, err := as[0].host.Broadcast(m, nil)
		req.NoError(err)
		req.Equal(len(as)-1, int(n))

		for i, a := range as {
			if i == 0 {
				continue
			}
			verifyMessage(req, a.ch, m, as[0].id)
		}
	})
}
