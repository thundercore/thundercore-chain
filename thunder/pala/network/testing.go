// Put the fake implementations used by the production code for the integration test.
package network

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/msggroup"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/petar/GoLLRB/llrb"
	"golang.org/x/xerrors"
)

// All operations of connectionFake are goroutine-safe.
type connectionFake struct {
	connectId      ConsensusId
	verifiedId     ConsensusId
	connectAddress string
	debugInfo      string
	role           Role
	reader         <-chan *packet

	peer *connectionFake

	// Protect member fields below
	mutex  utils.CheckedLock
	closed bool
	writer chan<- *packet
}

type ConnectionFakePair struct {
	connections []connection
}

type Filter func(from ConsensusId, to ConsensusId, typ uint8, blob []byte) *FilterAction

type FilterAction struct {
	// Called before the packet arrives. Return Dropped to drop the connection.
	PreCallback Callback
	// Called after the packet arrives. Return Dropped to drop the connection.
	PostCallback Callback
}

type Callback func(from ConsensusId, to ConsensusId, typ uint8, blob []byte) PassedOrDropped

type PassedOrDropped int

// Add more parameter when needed.
type Delay struct {
	Mean time.Duration
}

type item struct {
	time    time.Time
	packets []*packet
}

var (
	Passed  = PassedOrDropped(0)
	Dropped = PassedOrDropped(1)
)

var ConnectionDropper = func(from ConsensusId, to ConsensusId, typ uint8, blob []byte,
) PassedOrDropped {
	return Dropped
}

func EmptyFilter(from ConsensusId, to ConsensusId, typ uint8, blob []byte) *FilterAction {
	return &FilterAction{}
}

//--------------------------------------------------------------------

// FakeConnect simulates that a node connects to another node.
// After the connection is done, each node will have a new connection object.
func FakeConnect(src *Host, dst *Host) ConnectionFakePair {
	return FakeConnectWithFilter(src, dst, nil, nil, Delay{}, nil)
}

// FakeConnectWithFilter uses |filter| to sniff all packages and act based on the response
// of |filter|. If |filter| is set, |wg| and |stopChan| must be set as well.
// |wg| and |stopChan| allows the client of the fake connection to know
// whether the sniffer goroutine ends.
func FakeConnectWithFilter(
	src *Host, dst *Host, wg *sync.WaitGroup, stopChan chan interface{},
	delay Delay, filter Filter,
) ConnectionFakePair {
	if (!delay.IsNil() || filter != nil) && (filter == nil || wg == nil || stopChan == nil) {
		debug.Bug("invalid arguments")
	}

	srcToDst := make(chan *packet, 1024)
	dstToSrc := make(chan *packet, 1024)

	srcId := ConsensusId(src.loggingId)
	dstId := ConsensusId(dst.loggingId)
	dstConn := connectionFake{
		debugInfo:  fmt.Sprintf("%s<-%s", dst.loggingId, src.loggingId),
		verifiedId: srcId,
		role:       src.GetRole(),
		reader:     srcToDst,
		writer:     dstToSrc,
	}
	srcConn := connectionFake{
		debugInfo:      fmt.Sprintf("%s<-%s", src.loggingId, dst.loggingId),
		connectId:      dstId,
		verifiedId:     dstId,
		connectAddress: dst.loggingId,
		role:           dst.GetRole(),
		reader:         dstToSrc,
		writer:         srcToDst,
	}
	dstConn.peer = &srcConn
	srcConn.peer = &dstConn

	if !delay.IsNil() || filter != nil {
		addManInTheMiddle(srcId, dstId, delay, filter, &srcConn, wg, stopChan)
		addManInTheMiddle(dstId, srcId, delay, filter, &dstConn, wg, stopChan)
	}

	// Skip the handshake and call addConnection().
	src.addConnection(src.getConnectCtx(), &srcConn)
	dst.addConnection(dst.getConnectCtx(), &dstConn)

	return ConnectionFakePair{[]connection{&dstConn, &srcConn}}
}

func addManInTheMiddle(
	srcId ConsensusId, dstId ConsensusId, delay Delay, filter Filter, conn *connectionFake,
	wg *sync.WaitGroup, stopChan chan interface{},
) {
	middle := make(chan *packet, 1024)
	writer := conn.writer
	conn.writer = middle
	wg.Add(1)
	go func() {
		defer func() {
			wg.Done()
		}()

		packets := llrb.New()
		timer := time.NewTimer(time.Millisecond)
	Loop:
		for {
			select {
			case <-stopChan:
				return
			case p, ok := <-middle:
				if !ok {
					// closed.
					break Loop
				}
				if p == nil {
					debug.Bug("receive nil")
					writer <- p
					continue
				}

				targetTime := time.Now().Add(delay.Mean)
				// Use millisecond as the base unit.
				targetTime = targetTime.Round(time.Millisecond)
				key := &item{targetTime, nil}
				var ps *item
				if tmp := packets.Get(key); tmp != nil {
					ps = tmp.(*item)
				} else {
					ps = &item{time: targetTime}
					packets.ReplaceOrInsert(ps)
				}
				ps.packets = append(ps.packets, p)

				setupTimer(timer, packets)
			case now := <-timer.C:
				next, closed := processPackets(now, filter, packets, srcId, dstId, writer, conn)
				if closed {
					return
				}
				if next.IsZero() {
					continue
				}
				delay := next.Sub(now)
				timer.Reset(delay)
			}
		}

		// Process the rest of packets.
		for packets.Len() > 0 {
			setupTimer(timer, packets)
			now := <-timer.C
			next, closed := processPackets(now, filter, packets, srcId, dstId, writer, conn)
			if closed {
				return
			}
			if next.IsZero() {
				continue
			}
			delay := next.Sub(now)
			timer.Reset(delay)
		}

		// if we didn't explicitly close the writer after calling processPackets, close it now
		close(writer)
	}()
}

func setupTimer(timer *time.Timer, packets *llrb.LLRB) {
	now := time.Now().Round(time.Millisecond)
	next := packets.Min().(*item).time
	delay := time.Duration(0)
	if next.After(now) {
		delay = next.Sub(now)
	}
	timer.Reset(delay)
}

// process |packets| whose arrival time <= |now|.
// The first return value is the closet packets to process next time.
// If there is no packet, return 0.
// The second return value indicates whether the connection is already closed.
func processPackets(
	now time.Time, filter Filter, packets *llrb.LLRB,
	srcId ConsensusId, dstId ConsensusId, writer chan<- *packet, conn *connectionFake,
) (time.Time, bool) {
	// Use millisecond as the base unit.
	now = now.Round(time.Millisecond)
	for packets.Len() > 0 {
		min := packets.Min()
		ps := min.(*item)
		if ps.time.After(now) {
			return ps.time, false
		}

		for _, p := range ps.packets {
			action := filter(srcId, dstId, p.typ, p.blob)
			if action == nil {
				writer <- p
				continue
			}

			if action.PreCallback != nil &&
				action.PreCallback(srcId, dstId, p.typ, p.blob) == Dropped {
				if err := conn.close(); err != nil {
					logger.Warn("failed to close: %s", err)
				}
				close(writer)
				return time.Time{}, true
			}

			writer <- p

			if action.PostCallback != nil &&
				action.PostCallback(srcId, dstId, p.typ, p.blob) == Dropped {
				if err := conn.close(); err != nil {
					logger.Warn("failed to close: %s", err)
				}
				close(writer)
				return time.Time{}, true
			}
		}

		packets.DeleteMin()
	}
	return time.Time{}, false
}

func (p ConnectionFakePair) Close() {
	// The other end will be closed after close one end.
	if err := p.connections[0].close(); err != nil {
		logger.Warn("failed to close: %s", err)
	}
}

func (c *connectionFake) read() (*Message, error) {
	p, ok := <-c.reader
	if !ok {
		return nil, xerrors.New("closed")
	}

	m, err := newMessageByPacket(p, c)
	if err != nil {
		return nil, err
	}

	return m, nil
}

func (c *connectionFake) write(msg *Message) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.closed {
		return xerrors.Errorf("write to closed connection (%s)", c.debugInfo)
	}
	c.writer <- newPacket(msg)
	return nil
}

func (c *connectionFake) asyncWrite(msg *Message) {
	c.write(msg)
}

func (c *connectionFake) close() error {
	c.mutex.Lock()
	if c.closed {
		c.mutex.Unlock()
		return nil
	}
	c.closed = true
	close(c.writer)
	c.mutex.Unlock()
	return c.peer.close()
}

func (c *connectionFake) isClosed() bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.closed
}

func (c *connectionFake) getConnectId() ConsensusId {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.connectId
}

func (c *connectionFake) getVerifiedId() ConsensusId {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.verifiedId
}

func (c *connectionFake) getRole() Role {
	return c.role
}

func (c *connectionFake) isCapable(feature int) bool {
	return true
}

func (c *connectionFake) getAddress() string {
	i := strings.Index(c.debugInfo, "<-")
	return c.debugInfo[i:]
}

func (c *connectionFake) getConnectAddress() string {
	return c.connectAddress
}

func (c *connectionFake) setConnectAddress(addr string) {
	c.connectAddress = addr
}

func (c *connectionFake) getDebugInfo() string {
	return c.debugInfo
}

func (c *connectionFake) getRemoteLoggingId() string {
	return c.connectAddress
}

//--------------------------------------------------------------------

type AuthenticatorFake struct {
	Id ConsensusId
}

func (a *AuthenticatorFake) Sign(input []byte) (ConsensusId, []byte, error) {
	out := utils.Uint16ToBytes(uint16(len(a.Id)))
	out = append(out, []byte(a.Id)...)
	out = append(out, utils.Uint16ToBytes(uint16(len(input)))...)
	out = append(out, input...)
	return a.Id, out, nil
}

func (a *AuthenticatorFake) Verify(remoteIsServer bool, connectId ConsensusId, input []byte, expected []byte) (
	verifiedRemoteId ConsensusId, err error) {
	idSize, bs, err := utils.BytesToUint16(input)
	if err != nil {
		return "", err
	}

	if int(idSize) > len(bs) {
		return "", xerrors.New("length too short")
	}

	idFromInput := ConsensusId(string(bs[:idSize]))
	/*
		if connectId != idFromInput {
			return "", xerrors.Errorf("identity mismatched (%s != %s)", connectId, idFromInput)
		}
	*/

	sigSize, bs, err := utils.BytesToUint16(bs[idSize:])
	if err != nil {
		return "", err
	}

	if int(sigSize) > len(bs) {
		return "", xerrors.New("length too short")
	}

	// TODO: make bootnode and fullnode IDs based on BLS key pairs and remove the idPrefix scheme

	signature := bs[:sigSize]

	if !bytes.Equal(expected, signature) {
		return "", xerrors.Errorf("signature mismatched (%v != %v)", expected, signature)
	}

	return idFromInput, nil
}

func (a *AuthenticatorFake) GetSigningId() ConsensusId {
	return a.Id
}

//--------------------------------------------------------------------

func (d Delay) IsNil() bool {
	return d.Mean == 0
}

func (d Delay) String() string {
	return fmt.Sprintf("mean:%s", d.Mean)
}

func (d Delay) Add(other Delay) Delay {
	return Delay{
		Mean: d.Mean + other.Mean,
	}
}

func (i item) Less(i2 llrb.Item) bool {
	return i.time.Before(i2.(*item).time)
}

func NewConnectionOpenMessageFake(connectId, verifiedId ConsensusId, connectAddress string) *Message {
	return &Message{
		attribute: AttrOpen,
		source:    newFakeSource(connectId, verifiedId, connectAddress),
	}
}

func NewConnectionClosedMessageFake(connectId, verifiedId ConsensusId) *Message {
	return &Message{
		attribute: AttrClosed,
		source:    newFakeSource(connectId, verifiedId, ""),
	}
}

func NewMessageFake(typ uint8, attribute uint16, connectId, verifiedId ConsensusId, blob []byte) *Message {
	if attribute&AttrOpen != 0 {
		debug.Bug("use NewConnectionOpenMessageFake instead")
	}
	if attribute&AttrClosed != 0 {
		debug.Bug("use NewConnectionClosedMessageFake instead")
	}
	return &Message{
		typ:       typ,
		attribute: attribute,
		source:    newFakeSource(connectId, verifiedId, ""),
		blob:      blob,
	}
}

type fakeSource struct {
	mutex          sync.Mutex
	connectId      ConsensusId
	verifiedId     ConsensusId
	connectAddress string
	closed         bool
}

func (s *fakeSource) read() (*Message, error) { debug.NotImplemented(""); return nil, nil }
func (s *fakeSource) asyncWrite(msg *Message) { debug.NotImplemented("") }
func (s *fakeSource) close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.closed = true
	return nil
}

func (s *fakeSource) isClosed() bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.closed
}

func (s *fakeSource) getConnectId() ConsensusId {
	return s.connectId
}

func (s *fakeSource) getVerifiedId() ConsensusId {
	return s.verifiedId
}

func (s *fakeSource) setId(id ConsensusId)       { debug.NotImplemented("") }
func (s *fakeSource) getRole() Role              { debug.NotImplemented(""); return RoleHub }
func (s *fakeSource) isCapable(feature int) bool { debug.NotImplemented(""); return false }
func (s *fakeSource) getAddress() string {
	return "address:" + string(s.verifiedId)
}

func (s *fakeSource) getConnectAddress() string {
	return s.connectAddress
}
func (s *fakeSource) setConnectAddress(addr string) {
	s.connectAddress = addr
}

func (s *fakeSource) getRemoteLoggingId() string {
	return s.connectAddress
}
func (s *fakeSource) getDebugInfo() string { debug.NotImplemented(""); return "" }

func newFakeSource(connectId, verifiedId ConsensusId, connectAddress string) connection {
	return &fakeSource{
		connectId:      connectId,
		verifiedId:     verifiedId,
		connectAddress: connectAddress,
	}
}

//--------------------------------------------------------------------

func MakeChannelForAllMessages(mul *Multiplexer) chan *Message {
	ch := make(chan *Message, 1024)
	for i := 0; i < 16; i++ {
		mul.Subscribe(msggroup.Group(i<<4), ch)
	}
	return ch
}

//--------------------------------------------------------------------

type DomainNameResolverFake struct {
	records map[string][]string
}

func NewDomainNameResolverFake() DomainNameResolver {
	return &DomainNameResolverFake{records: make(map[string][]string)}
}

func (r *DomainNameResolverFake) LookupHost(
	ctx context.Context, host string) (addrs []string, err error) {
	if addrs, ok := r.records[host]; ok {
		return addrs, nil
	}
	return []string{host}, nil
}

func (r *DomainNameResolverFake) Add(address, ip string) {
	addrs := r.records[address]
	addrs = append(addrs, ip)
	r.records[address] = addrs
}

func (r *DomainNameResolverFake) Remove(address, targetIp string) {
	addrs, ok := r.records[address]
	if !ok {
		return
	}
	for i, ip := range addrs {
		if ip == targetIp {
			addrs[i] = addrs[len(addrs)-1]
			addrs = addrs[:len(addrs)-1]
			break
		}
	}
	r.records[address] = addrs
}
