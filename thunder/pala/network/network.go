package network

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptoRand "crypto/rand" // we also import "math.rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"path"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/backoff"
	"github.com/ethereum/go-ethereum/thunder/pala/metrics"
	"github.com/ethereum/go-ethereum/thunder/pala/types"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"golang.org/x/xerrors"
)

var (
	logger = lgr.NewLgr("/network")

	ErrIsConnected     = xerrors.New("already connected")
	ErrConnectedToSelf = xerrors.New("connect to self")
)

type ConsensusId = types.ConsensusId

type Config struct {
	LoggingId                      string
	ProtocolVersion                uint16
	NetworkId                      uint64
	Role                           Role
	ReadTimeout                    time.Duration
	WriteTimeout                   time.Duration
	ConnectingConfig               ConnectingConfig
	ThrottlingConfig               ThrottlingConfig
	ConnectionObserver             ConnectionObserver
	Authenticator                  Authenticator
	DomainNameResolver             DomainNameResolver
	Sink                           Sink
	Metrics                        metrics.PalaMetrics
	SendUnverifiedConnectionEvents bool
	Clock                          Clock
	ClientPuzzleMgrCfg             *ClientPuzzleMgrCfg
}

type ConnectingConfig struct {
	WaitingTime  time.Duration
	RetryTime    time.Duration
	BackOffBegin time.Duration
	BackOffEnd   time.Duration
}

type ThrottlingConfig struct {
	// Throttling by bytes. TotalReadBytesThresholdPerSecond is >= ReadBytesPerSecond.
	// If TotalReadBytesThresholdPerSecond is smaller than ReadBytesPerSecond,
	// it becomes ReadBytesPerSecond.
	TotalReadBytesThresholdPerSecond uint // Start doing throttling after total read bytes exceeding this.
	ReadBytesPerSecond               uint // 0 means no throttling
	// Throttling by count.
	MessageCountPerSecond uint // 0 means no throttling
}

type Clock interface {
	Now() time.Time
	Sleep(time.Duration)
}

type Role int

const (
	RoleHub   = Role(1)
	RoleSpoke = Role(2)
)

const (
	// NOTE: Due to a design error, PaLa R1 only accepts the same protocol version.
	// After all nodes are updated, we can increase the version then.
	ProtocolVersion = 1
	// Special bit indices in the reserved bytes.
	// NOTE: CapabilityX are feature flags. We use them to be backward compatible with
	// the current and the last version.
	CapabilityHub          = 0
	CapabilityChainSyncV2  = 1 // Used in protocol version 1. Remove it after no node runs version 1.
	CapabilitySnappy       = 2 // Used in protocol version 1. Remove it after no node runs version 1.
	CapabilityClientPuzzle = 3 // Used in protocol version 1. Remove it after no node runs version 1.
	CapabilityLoggingId    = 4 // Used in protocol version 1. Remove it after no node runs version 1.
)

// DefaultConnectingConfig has the default values used by Host.Connect().
var DefaultConnectingConfig = ConnectingConfig{
	// Note: RetryTime > WaitingTime > BackOffEnd
	RetryTime:    time.Second * 15,
	WaitingTime:  time.Second * 5,
	BackOffBegin: time.Millisecond * 100,
	BackOffEnd:   time.Millisecond * 2000,
}

const (
	DefaultReadTimeout  = 30 * time.Second
	DefaultWriteTimeout = 30 * time.Second
)

type handshakeMessage struct {
	version   uint16
	networkId uint64
	// Used to set capabilities, etc.
	reserved [6]byte
}

const handshakeMessageLength = 2 + 8 + 6

type GroupConectedNess int

const (
	// Connect to one node in the group.
	OneInGroup = GroupConectedNess(0)
	// Connect to all nodes in the group.
	AllInGroup = GroupConectedNess(1)
)

func (g GroupConectedNess) String() string {
	switch g {
	case OneInGroup:
		return "one-in-group"
	case AllInGroup:
		return "all-in-group"
	default:
		return "unknown"
	}
}

type Sink interface {
	Send(*Message, Blockingness)
}

// All operations of Host are go-routine safe.
// * All public methods hold mutex by themselves.
// * Private methods may assume the caller holds the mutex. Please see their comments.
type Host struct {
	// Member fields below are set once
	loggingId                      string
	protocolVersion                uint16
	networkId                      uint64
	config                         ConnectingConfig
	readTimeout                    time.Duration
	writeTimeout                   time.Duration
	connectionObserver             ConnectionObserver
	authenticator                  Authenticator
	domainNameResolver             DomainNameResolver
	sendUnverifiedConnectionEvents bool
	sink                           Sink
	clk                            Clock
	clientPuzzleMgr                *ClientPuzzleMgr

	// Protect member fields below
	mutex                   utils.CheckedLock
	role                    Role
	unverifiedConns         []io.Closer // connections that haven't passed the `handshake` challenge
	verifiedIdToConnections map[ConsensusId]connection
	connectIdToConnections  map[ConsensusId]connection
	addressToConnections    map[string]connection
	listener                net.Listener
	metrics                 metrics.PalaMetrics
	connectCtx              context.Context
	cancelConnects          context.CancelFunc // cancels `connectCtx`
	throttler               *throttler
}

// Authenticator helps do the challenge-response authentication.
// All operations are goroutine-safe.
type Authenticator interface {
	// Sign uses the identity of `id` to sign `input` and returns the signature.
	Sign(input []byte) (ConsensusId, []byte, error)
	// Verify that `signature` is signed by `id`. Expect the decoded `signature` is `expected`.
	// `remoteIsServer` means whether the remote side is the server. This may affect the
	// result of some authenticator implementation.
	// Return nil if there is no error.
	Verify(remoteIsServer bool, connectId ConsensusId, signature []byte, expected []byte) (
		verifiedRemoteId ConsensusId, err error)
	// GetSigningId returns the identity used to sign.
	GetSigningId() ConsensusId
}

type ConnectionObserver interface {
	OnConnected(connectAddress string, connectId, verifiedId ConsensusId)
	OnDisconnected(connectAddress string, connectId, verifiedId ConsensusId)
}

type Message struct {
	typ       uint8
	attribute uint16
	source    connection
	// NOTE: Assume the size is not large (say, <10M),
	// Preparing a large array is inefficient.
	// Use some other data structure when needed.
	blob  []byte
	extra interface{}

	// Only valid when attribute `AttrHandshakeError` is set.
	err error
}

// Use one packet to represent one message.
// If we want to support prioritized packets, use multiple packets to
// represent one message and let high priority packets be able to preempt.
const packetHeaderSize = 4 + 1 + 2

type packet struct {
	size      uint32 // The number of bytes of the packet including |size| itself.
	typ       uint8
	attribute uint16
	blob      []byte
}

const (
	// NOTE:
	// 1. geth sends a block as a message ( ref. peer.SendNewBlock() -> ... -> MsgWriter.WriteMsg() ).
	//    The max message size in RLPx is 2^24 ( ref. rlpxFrameRW.ReadMsg() -> readInt24() ).
	//    However, current block gas limit in Ethereum is about 1/10 of ours ( 9757812 / 100000000 ).
	//    Thus, this is not a good reference for setting the max message size.
	// 2. One AB tx is ~100 bytes. One block can include at most 4759 AB txs -> ~500KB
	//    If we want to let the chain syncing send >= 10 blocks, the max message size requires >= 5MB.
	// 3. One tx can have at most ~23.8 MB by filling all payload as zero. For K=1, chain syncing
	//    needs to send at most two notarized blocks to update the peer's freshest notarized head.
	//    If we want to send two blocks in one message, the max message size requires >= ~48MB.
	// 4. We cannot set the size arbitrary large; otherwise, attackers can fake a large message size
	//    and occupy our memory.
	//
	// Use 64 MB as a reaonsable bound. The consensus layer must divide the data into small messages
	// if one message size exceeds the bound.
	MaxMessageBodySize = 1 << 26

	// A new connection is established.
	AttrOpen = uint16(1 << 0)
	// A connection is closed.
	AttrClosed = uint16(1 << 1)
	// A connection handshake error (
	AttrHandshakeError = uint16(1 << 2)
	// A new, unverified connection was established
	AttrUnverifiedConnection = uint16(1 << 3)
	// The payload is compressed.
	AttrCompressed = uint16(1 << 4)
)

var (
	ErrExceedMaxMessageSize = xerrors.New("exceed max message size")
)

type ConnectError struct {
	Errors []error
}

func (e *ConnectError) Error() string {
	return fmt.Sprintf("there are %d errors; the first one is %s",
		len(e.Errors), e.Errors[0])
}

//------------------------------------------------------------------------------

func NewHost(cfg Config) *Host {
	// To support testing, allow setting the ProtocolVersion from the caller.
	if cfg.ProtocolVersion == 0 {
		cfg.ProtocolVersion = ProtocolVersion
	} else {
		utils.EnsureRunningInTestCode()
	}

	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = DefaultReadTimeout
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = DefaultWriteTimeout
	}
	if cfg.DomainNameResolver == nil {
		cfg.DomainNameResolver = NewDomainNameResolver()
	}
	h := &Host{
		loggingId:                      cfg.LoggingId,
		protocolVersion:                cfg.ProtocolVersion,
		networkId:                      cfg.NetworkId,
		role:                           cfg.Role,
		readTimeout:                    cfg.ReadTimeout,
		writeTimeout:                   cfg.WriteTimeout,
		config:                         cfg.ConnectingConfig,
		connectionObserver:             cfg.ConnectionObserver,
		authenticator:                  cfg.Authenticator,
		domainNameResolver:             cfg.DomainNameResolver,
		sink:                           cfg.Sink,
		clk:                            cfg.Clock,
		metrics:                        cfg.Metrics,
		verifiedIdToConnections:        make(map[ConsensusId]connection),
		connectIdToConnections:         make(map[ConsensusId]connection),
		addressToConnections:           make(map[string]connection),
		sendUnverifiedConnectionEvents: cfg.SendUnverifiedConnectionEvents,
		throttler:                      newThrottler(cfg.ThrottlingConfig, cfg.Clock),
		clientPuzzleMgr:                NewClientPuzzleMgr(cfg.ClientPuzzleMgrCfg),
	}
	_ = h.resetConnectCtx()
	return h
}

const (
	certValidFor     = 10 * 365 * 24 * time.Hour
	organizationName = "ThunderCore"
)

// Regarding the security design, see comments in Host.Connect().
func GenerateSelfSignedCert(clk Clock, domainName string) (publicKeyRaw, certPem, privPem []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), cryptoRand.Reader)
	if err != nil {
		logger.Critical("ecdsa.GenerateKey: %s", err)
		return nil, nil, nil, err
	}

	publicKeyRaw, err = x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		logger.Critical("x509.MarshalPKIPublicKey: %s", err)
		return nil, nil, nil, err
	}

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		logger.Critical("x509.MarshalECPrivateKey: %s", err)
		return nil, nil, nil, err
	}
	privPem = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	notBefore := clk.Now()
	notAfter := notBefore.Add(certValidFor)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := cryptoRand.Int(cryptoRand.Reader, serialNumberLimit)
	if err != nil {
		logger.Critical("failed to generate serial number: %s", err)
		return nil, nil, nil, err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{organizationName},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domainName},
	}
	derBytes, err := x509.CreateCertificate(cryptoRand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		logger.Critical("Failed to create certificate: %s", err)
		return nil, nil, nil, err
	}
	certPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	return publicKeyRaw, certPem, privPem, nil
}

// StartAccepting starts a background goroutine to listen to |address| and accept connections.
// The new connection's role is RoleHub if the other side is a hub; otherwise, it's RoleSpoke.
func (h *Host) StartAccepting(address string) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.listener != nil {
		return xerrors.New("already accepting connections")
	}

	// FIXME: context and cancellation support
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return err
	}

	tlsPublicKey, certPem, privPem, err := GenerateSelfSignedCert(h.clk, "thunderServer")
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(certPem, privPem)
	if err != nil {
		logger.Error("tls.X509KeyPair: %s", err)
		return err
	}
	l, err := net.Listen("tcp", addr.String())
	if err != nil {
		return err
	}
	h.listener = l // cancelling `h.connectCtx` should now close `h.listener`
	logger.Info("[%s] started accepting connections (%s)", h.loggingId, h.getBoundIPPort())
	h.startAccepting(h.connectCtx, l, cert, tlsPublicKey)

	return nil
}

// Use a new method to limit the variables outside the closure.
func (h *Host) startAccepting(ctx context.Context, l net.Listener, cert tls.Certificate, tlsPublicKey []byte) {
	go func() {
		for {
			// NOTE: access a local variable l instead of the member field to avoid a data race.
			tcpConn, err := l.Accept()
			if err != nil {
				logger.Error("[%s] accept failed: %s", h.loggingId, err)
				break
			}
			logger.Info("[%s] accept %s", h.loggingId, tcpConn.RemoteAddr())
			h.mutex.Lock()
			h.unverifiedConns = append(h.unverifiedConns, tcpConn)
			h.mutex.Unlock()
			if h.sendUnverifiedConnectionEvents {
				h.sink.Send(&Message{attribute: AttrUnverifiedConnection}, PanicIfBlockCall)
			}

			conn := tls.Server(tcpConn, &tls.Config{
				Certificates: []tls.Certificate{cert},
			})
			// `(*Host).handshake` would acquire the Host lock as necessary
			go h.handshake(ctx, "", "", conn, tlsPublicKey, tcpConn)
		}
	}()
}

func (h *Host) removeUnverifiedConn(c net.Conn) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	index := -1
	for i, c0 := range h.unverifiedConns {
		if c0 == c {
			index = i
			break
		}
	}
	if index == -1 {
		debug.Bug("[%s] trying to remove unknown unverified connection: %#v, %#v", h.loggingId, c, h.unverifiedConns)
	}

	remove := func(s []io.Closer, i int) []io.Closer {
		end := len(s) - 1
		s[end], s[i] = s[i], s[end]
		return s[:end]
	}
	h.unverifiedConns = remove(h.unverifiedConns, index)
}

// handshake called by both the server and the client.
// connectId is only set when it's called in the client side.
// The other arguments are required.
func (h *Host) handshake(
	ctx context.Context, connectAddress string, connectId ConsensusId,
	conn net.Conn, tlsPublicKey []byte, connToRemove net.Conn) {
	defer h.removeUnverifiedConn(connToRemove)
	remoteAddress := conn.RemoteAddr().String()
	logger.Info("[%s] handshake: begin with %s", h.loggingId, remoteAddress)
	// Expect the handshake is finished in 10s.
	begin := h.clk.Now()
	// NOTE: we cannot use the fake time since conn uses the real time internally.
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Write the protocol handshake message.
	var p handshakeMessage
	p.version = h.protocolVersion
	p.networkId = h.networkId
	p.setCapability(CapabilityHub, h.GetRole() == RoleHub)
	p.setCapability(CapabilityChainSyncV2, true)
	p.setCapability(CapabilitySnappy, true)
	p.setCapability(CapabilityClientPuzzle, true)
	p.setCapability(CapabilityLoggingId, true)
	_, err := conn.Write(marshalHandshakeMessage(&p))
	if err != nil {
		logger.Error("[%s] handshake: failed to write protocol handshake message; err=%s (%s); ",
			h.loggingId, err, remoteAddress)
		_ = conn.Close()
		return
	}
	metrics.IncCounter(h.metrics.HandshakesSent)

	// Read the protocol handshake message.
	buf := make([]byte, handshakeMessageLength)
	if _, err := io.ReadFull(conn, buf); err != nil {
		msg := fmt.Sprintf("failed to read the protocol handshake message; err=%s (%s)",
			err, remoteAddress)
		logger.Error("[%s] handshake: %s", h.loggingId, msg)
		h.closeConnectionDueToHandshakeError(conn, HandShakeError{message: msg})
		return
	}
	p2, err := unmarshalHandshakeMessage(buf)
	if err != nil {
		msg := fmt.Sprintf("invalid protocol handshake format; err=%s (%s)", err, remoteAddress)
		logger.Error("[%s] handshake: %s", h.loggingId, msg)
		h.closeConnectionDueToHandshakeError(conn, HandShakeError{message: msg})
		return
	}

	// The current version is only backward compatible with the last version.
	// This is enough for the real cases.
	if utils.Abs(int(p2.version)-int(p.version)) > 1 {
		msg := fmt.Sprintf("unmatched protocol version: ours is %d, but the remote's is %d;"+
			"the remote address is %s", p.version, p2.version, remoteAddress)
		logger.Info("[%s] handshake: %s", h.loggingId, msg)
		h.closeConnectionDueToHandshakeError(conn, HandShakeError{message: msg})
		metrics.IncCounter(h.metrics.ProtocolVersionMismatches)
		return
	}

	if p2.networkId != h.networkId {
		msg := fmt.Sprintf("unmatched network id: ours is %d, but the remote's is %d;"+
			"the remote address is %s", p.networkId, p2.networkId, remoteAddress)
		logger.Info("[%s] handshake: %s", h.loggingId, msg)
		h.closeConnectionDueToHandshakeError(conn, HandShakeError{message: msg})
		metrics.IncCounter(h.metrics.ProtocolNameMismatches)
		return
	}

	metrics.IncCounter(h.metrics.HandshakesGood)

	// Do the challenge-response authentication.
	//
	// Client                                   |    Server
	// -----------------------------------------+---------------------------------------
	// Send challenge-response message          |
	//                                          | Receive and verify the message
	//                                          | Send challenge-response message
	// Receive and verify the message           |
	//
	var verifiedRemoteId ConsensusId
	var remoteLoggingId string
	if connectAddress != "" { // connection created by `Connect`
		if p2.isCapable(CapabilityClientPuzzle) {
			if err := h.solveClientPuzzle(conn); err != nil {
				msg := fmt.Sprintf("failed to solve client puzzle; err=%s (%s)", err, remoteAddress)
				h.closeConnectionDueToHandshakeError(conn, ClientPuzzleError{message: msg})
				logger.Error("[%s] client-puzzle: %s", h.loggingId, msg)
				return
			}
		}
		// The client sends its signature first.
		_, signature, err := h.authenticator.Sign(tlsPublicKey)
		if err != nil {
			logger.Error("[%s] handshake: failed to create the challenge-response message; err=%s (%s)",
				h.loggingId, err, remoteAddress)
			_ = conn.Close()
			return
		}
		if err := writeChallengeResponseMessage(conn, signature); err != nil {
			logger.Error("[%s] handshake: failed to write challenge-response message; err=%s (%s)",
				h.loggingId, err, remoteAddress)
			_ = conn.Close()
			return
		}
		metrics.IncCounter(h.metrics.Voter_ChallengeResponsesSent)

		// The client waits for the server's signature.
		remoteSignature, err := readChallengeResponseMessage(conn)
		if err != nil {
			msg := fmt.Sprintf("failed to read challenge-response message; err=%s (%s)", err, remoteAddress)
			h.closeConnectionDueToHandshakeError(conn, TLSVerifyError{message: msg})
			logger.Error("[%s] handshake: %s", h.loggingId, msg)
			metrics.IncCounter(h.metrics.Voter_ChallengeResponsesBadDecode)
			return
		}
		if verifiedRemoteId, err = h.authenticator.Verify(true, connectId, remoteSignature, tlsPublicKey); err != nil {
			msg := fmt.Sprintf("failed to verify challenge-response message; err=%s (%s)", err, remoteAddress)
			h.closeConnectionDueToHandshakeError(conn, TLSVerifyError{message: msg})
			logger.Error("[%s] handshake: %s", h.loggingId, msg)
			metrics.IncCounter(h.metrics.Voter_ChallengeResponseInvalid)
			return
		}
		if p2.isCapable(CapabilityLoggingId) {
			if err := writeRemoteLoggingId(conn, h.loggingId); err != nil {
				msg := fmt.Sprintf("failed to write remote logging id; err=%s (%s)", err, remoteAddress)
				h.closeConnectionDueToHandshakeError(conn, HandShakeError{message: msg})
				logger.Warn("[%s] handshake: %s", h.loggingId, msg)
				return
			}
			if remoteLoggingId, err = readRemoteLoggingId(conn); err != nil {
				msg := fmt.Sprintf("failed to read remote logging id; err=%s (%s)", err, remoteAddress)
				h.closeConnectionDueToHandshakeError(conn, HandShakeError{message: msg})
				logger.Warn("[%s] handshake: %s", h.loggingId, msg)
				return
			}
		}

		metrics.IncCounter(h.metrics.Voter_ChallengeResponsesValid)
	} else { // connection created by `Accept`
		if p2.isCapable(CapabilityClientPuzzle) {
			if err := h.initiateClientPuzzle(conn, h.clientPuzzleMgr.GetDifficulty()); err != nil {
				msg := fmt.Sprintf("failed to process client puzzle; err=%s (%s)", err, remoteAddress)
				h.closeConnectionDueToHandshakeError(conn, ClientPuzzleError{message: msg})
				logger.Error("[%s] client-puzzle: %s", h.loggingId, msg)
				return
			}
		}

		// The server waits for the client's signature.
		//
		// We reduce the server's overheads by verifying the client's auth message
		// *before* creating the server's auth message when there are attacks.
		var remoteSignature []byte
		remoteSignature, err := readChallengeResponseMessage(conn)
		if err != nil {
			msg := fmt.Sprintf("failed to read challenge-response message; err=%s (%s)", err, remoteAddress)
			h.closeConnectionDueToHandshakeError(conn, TLSVerifyError{message: msg})
			logger.Error("[%s] handshake: %s", h.loggingId, msg)
			metrics.IncCounter(h.metrics.Proposer_ChallengeResponsesBadDecode)
			return
		}

		if verifiedRemoteId, err = h.authenticator.Verify(false, connectId, remoteSignature, tlsPublicKey); err != nil {
			msg := fmt.Sprintf("failed to verify challenge-response message; err=%s (%s)", err, remoteAddress)
			logger.Error("[%s] handshake: %s", h.loggingId, msg)
			h.closeConnectionDueToHandshakeError(conn, TLSVerifyError{message: msg})
			metrics.IncCounter(h.metrics.Proposer_ChallengeResponseInvalid)
			return
		}
		metrics.IncCounter(h.metrics.Proposer_ChallengeResponsesValid)

		// The server sends its signature.
		_, signature, err := h.authenticator.Sign(tlsPublicKey)
		if err != nil {
			logger.Error("[%s] handshake: failed to create the challenge-response message; err=%s (%s)",
				h.loggingId, err, remoteAddress)
			_ = conn.Close()
			return
		}
		metrics.IncCounter(h.metrics.Proposer_ChallengeResponsesSent)
		if err := writeChallengeResponseMessage(conn, signature); err != nil {
			logger.Error("[%s] handshake: failed to write challenge-response message; err=%s (%s)",
				h.loggingId, err, remoteAddress)
			_ = conn.Close()
			return
		}

		if p2.isCapable(CapabilityLoggingId) {
			if remoteLoggingId, err = readRemoteLoggingId(conn); err != nil {
				msg := fmt.Sprintf("failed to read remote logging id; err=%s (%s)", err, remoteAddress)
				h.closeConnectionDueToHandshakeError(conn, HandShakeError{message: msg})
				logger.Warn("[%s] handshake: %s", h.loggingId, msg)
				return
			}
			if err := writeRemoteLoggingId(conn, h.loggingId); err != nil {
				msg := fmt.Sprintf("failed to write remote logging id; err=%s (%s)", err, remoteAddress)
				h.closeConnectionDueToHandshakeError(conn, HandShakeError{message: msg})
				logger.Warn("[%s] handshake: %s", h.loggingId, msg)
				return
			}
		}
	}

	// Reset the setting to no deadline.
	logger.Note("[%s] handshake: done with %q (id=%s, loggingId=%s, addr=%s) in %s",
		h.loggingId, connectId, verifiedRemoteId, remoteLoggingId, remoteAddress, h.clk.Now().Sub(begin))
	logger.Note("[%s] handshake: protocol version (ours/peer's): %d/%d; networkId: %d",
		h.loggingId, p.version, p2.version, p.networkId)
	conn.SetReadDeadline(time.Time{})
	// Handle the connection.
	h.addConnection(ctx, newConnection(
		p2, connectId, verifiedRemoteId, connectAddress, remoteLoggingId, h.readTimeout, h.writeTimeout, conn))
}

func (h *Host) closeConnectionDueToHandshakeError(conn net.Conn, err error) {
	m := &Message{
		attribute: AttrHandshakeError,
		err:       err,
	}

	// While we're attacked, there may be a lot of handshake errors.
	// To not occupy any resource, drop the message if we cannot notify the client now.
	h.sink.Send(m, NonBlockingCall)
	metrics.IncCounter(h.metrics.TotalHandshakesBad)
	_ = conn.Close()
}

func (h *Host) initiateClientPuzzle(conn net.Conn, difficulty uint32) error {
	msg, err := readClientPuzzleExtensionMessage(conn)
	if err != nil {
		logger.Error("[%s] failed to read client-puzzle-extension; err=%s", h.loggingId, err)
		return err
	}

	clientPuzzle, err := h.clientPuzzleMgr.SelectPuzzle(msg.puzzleTypes)
	if err != nil {
		return err
	}

	challengeResponse, solution := clientPuzzle.GeneratePuzzle(difficulty)
	if err := writeClientPuzzleExtensionMessage(conn, []string{clientPuzzle.Name()}, challengeResponse); err != nil {
		logger.Error("[%s] failed to write client-puzzle-extension; err=%s", h.loggingId, err)
		return err
	}

	msg, err = readClientPuzzleExtensionMessage(conn)
	if err != nil {
		logger.Error("[%s] failed to read client-puzzle-extension; err=%s", h.loggingId, err)
		return err
	}

	return clientPuzzle.VerifyPuzzle(challengeResponse, solution, msg.challengeResponse)
}

func (h *Host) solveClientPuzzle(conn net.Conn) error {
	if err := writeClientPuzzleExtensionMessage(conn, h.clientPuzzleMgr.GetSupportedPuzzles(), nil); err != nil {
		logger.Error("[%s] failed to write client-puzzle-extension; err=%s", h.loggingId, err)
		return err
	}

	msg, err := readClientPuzzleExtensionMessage(conn)
	if err != nil {
		logger.Error("[%s] failed to read client-puzzle-extension; err=%s", h.loggingId, err)
		return err
	}

	if len(msg.puzzleTypes) != 1 {
		return xerrors.New("invalid puzzle type")
	}

	clientPuzzle, err := h.clientPuzzleMgr.GetPuzzle(msg.puzzleTypes[0])
	if err != nil {
		return err
	}

	solution, err := clientPuzzle.SolvePuzzle(msg.challengeResponse)
	if err != nil {
		return err
	}

	if err := writeClientPuzzleExtensionMessage(conn, msg.puzzleTypes, solution); err != nil {
		logger.Error("[%s] failed to write client-puzzle-extension; err=%s", h.loggingId, err)
		return err
	}

	return nil
}

// StopAccepting stops the background goroutine started by StartAccepting().
// The function returns after the background goroutine ends.
// It's okay to call this even if the goroutine is already stopped or
// StartAccepting() is never called.
func (h *Host) StopAccepting() error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.listener == nil {
		return nil
	}

	if err := h.listener.Close(); err != nil {
		logger.Error("[%s] failed to close the listener; err=%s", h.loggingId, err)
	}
	h.listener = nil
	logger.Info("[%s] stopped accepting connections", h.loggingId)
	return nil
}

func (h *Host) GetBoundIPPort() string {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	return h.getBoundIPPort()
}

func (h *Host) getBoundIPPort() string {
	h.mutex.CheckIsLocked("")

	if h.listener == nil {
		return ""
	}
	addr := h.listener.Addr().String()
	i := strings.LastIndex(addr, ":")
	if i >= 0 {
		ip, port := addr[:i], addr[i:]
		if ip == "[::]" {
			addr = "127.0.0.1" + port
		}
	}
	return addr
}

// ConnectForTest is the sync version of ConnectAsync. This is more convenient for tests.
func (h *Host) ConnectForTest(connectId ConsensusId, connectAddress string, group GroupConectedNess) error {
	utils.EnsureRunningInTestCode()

	if connectAddress == "" {
		debug.Bug("address cannot be empty")
	}

	h.mutex.Lock()
	ctx := h.connectCtx
	h.mutex.Unlock()
	return h.doConnect(ctx, connectId, connectAddress, group)
}

// ConnectForTest connects to |address|. The new connection's role is RoleHub if the other side is a hub;
// otherwise, it's RoleSpoke. |connectId| is optional and will be used during the challenge-response.
func (h *Host) ConnectAsync(connectId ConsensusId, connectAddress string, group GroupConectedNess) {
	if connectAddress == "" {
		debug.Bug("address cannot be empty")
	}

	ctx := h.getConnectCtx()
	go func() {
		err := h.doConnect(ctx, connectId, connectAddress, group)
		if err == ErrIsConnected {
			logger.Info("[%s] already connected to %s (%s)", h.loggingId, connectId, connectAddress)
			return
		}
		if err != nil {
			if cerr, ok := err.(*ConnectError); ok {
				var errs []error
				for _, err := range cerr.Errors {
					if err == ErrIsConnected {
						continue
					}
					errs = append(errs, err)
				}
				if len(errs) == 0 {
					logger.Info("[%s] already connected to %s (%s)", h.loggingId, connectId, connectAddress)
					return
				}
				err = &ConnectError{errs}
				logger.Info("[%s] failed to connect to %s (%s); err=%s", h.loggingId, connectId, connectAddress, err)
				return
			}
			logger.Info("[%s] failed to connect to %s (%s); err=%s", h.loggingId, connectId, connectAddress, err)
		}
		if h.sendUnverifiedConnectionEvents {
			h.sink.Send(&Message{attribute: AttrUnverifiedConnection, err: err}, PanicIfBlockCall)
		}
	}()
}

// Index of rightmost occurrence of b in s.
func last(s string, b byte) int {
	i := len(s)
	for i--; i >= 0; i-- {
		if s[i] == b {
			break
		}
	}
	return i
}

func (h *Host) doConnect(
	ctx context.Context, connectId ConsensusId, connectAddress string, group GroupConectedNess,
) error {
	if group == OneInGroup {
		return h.doConnectOne(ctx, connectId, connectAddress)
	}

	var err error
	var host, port string
	if last(connectAddress, ':') >= 0 {
		host, port, err = net.SplitHostPort(connectAddress)
		if err != nil {
			return xerrors.Errorf("failed to connect to %s: %w", connectAddress, err)
		}
		port = ":" + port
	} else {
		host = connectAddress
	}

	addrs, err := h.domainNameResolver.LookupHost(ctx, host)
	if err != nil {
		logger.Warn("[%s] failed to resolve %s: %s; fall back to %s",
			h.loggingId, host, err, OneInGroup)
		return h.doConnectOne(ctx, connectId, connectAddress)
	}

	var wg sync.WaitGroup
	errs := make([]error, len(addrs))
	for i, addr := range addrs {
		wg.Add(1)
		go func(index int, addr string) {
			defer wg.Done()
			errs[index] = h.doConnectOne(ctx, connectId, addr+port)
		}(i, addr)
	}
	wg.Wait()
	var retErrs []error
	for _, err := range errs {
		if err != nil {
			retErrs = append(retErrs, err)
		}
	}
	if len(retErrs) == 0 {
		return nil
	}
	return &ConnectError{retErrs}
}

// `connectAddress` could be either a host name or an IP.
func (h *Host) doConnectOne(
	ctx context.Context, connectId ConsensusId, connectAddress string,
) error {
	var tcpConn net.Conn
	var err error

	logger.Info("[%s] connect to %q with address %s", h.loggingId, connectId, connectAddress)
	h.mutex.Lock()
	if h.getConnection(connectId, "", connectAddress) != nil {
		logger.Info("[%s] Already connected to id:%q, addr:%s", h.loggingId, connectId, connectAddress)
		h.mutex.Unlock()
		return ErrIsConnected
	}
	h.mutex.Unlock()

	// If the network is fine but the destination isn't ready to accept connections,
	// DialContext() will return immediately. We need to backoff then retry in this case.
	dialer := &net.Dialer{}
	linear := backoff.NewLinear(h.config.BackOffBegin, h.config.BackOffEnd)
	begin := h.clk.Now()
	for {
		dialCtx, cancelDial := context.WithTimeout(ctx, time.Second*3)
		tcpConn, err = dialer.DialContext(dialCtx, "tcp", connectAddress)
		cancelDial()
		if err == nil {
			break
		} else if err == context.Canceled {
			return err
		} else if time.Since(begin) > h.config.WaitingTime {
			return err
		}
		// backoff and retry in next loop iteration
		if err = linear.Backoff(ctx); err != nil {
			return err
		}
	}

	h.mutex.Lock()  // Only check `ctx.Err()` after taking the `*Host` lock here.
	err = ctx.Err() // If `(*Host).resetConnectCtx` happens-before this,
	if err == nil { // it'll remove and close the connection. Otherwise, we close it here.
		h.unverifiedConns = append(h.unverifiedConns, tcpConn)
	}
	h.mutex.Unlock()
	if err != nil {
		_ = tcpConn.Close() // Concurrent calls to `(*tls.Conn).Close` and `(*tls.Conn).Handshake`
		return err          // could cause the former to block. Thus we close the raw TCP connection.
	}

	if err := tcpConn.(*net.TCPConn).SetKeepAlive(true); err != nil {
		_ = tcpConn.Close()
		return err
	}

	if err := tcpConn.(*net.TCPConn).SetKeepAlivePeriod(150 * time.Second); err != nil {
		_ = tcpConn.Close()
		return err
	}

	// `net.DialTimeout` supports specifying a timeout while `tls.Dial` doesn't
	// so we create a TLS connection from the TCP one here
	conn := tls.Client(tcpConn, &tls.Config{
		// We don't rely on trusted TLS certificates and intentionally skip their verification.
		// Our consensus layer will verify the identity of remote nodes via challenge-response.
		// See this document for details of our security design:
		// https://docs.google.com/presentation/d/1vQ1Kh5O_kNXe0y0GK9c26UTmblPIdx8DDoKmPhrrr3c/edit#slide=id.g57a867204c_0_110
		InsecureSkipVerify: true,
	})

	// Ensure `(*tls.Conn).Handshake()` happens before
	// reading peer certificates for that connection
	if err = conn.Handshake(); err != nil {
		h.mutex.Lock()
		if h.connectCtx.Err() != nil && IsClosedError(err) {
			err = nil // connect operation cancelled
		}
		h.mutex.Unlock()
		return err // report TLS handshake errors without retrying
	}

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) < 1 {
		return nil // scottt: why is this not a handshake error?
	}
	go h.handshake(ctx, connectAddress, connectId, conn, certs[0].RawSubjectPublicKeyInfo, tcpConn)
	return nil
}

func (h *Host) GetAddress(id ConsensusId) string {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if c, ok := h.verifiedIdToConnections[id]; ok {
		return c.getAddress()
	}
	return ""
}

func (h *Host) GetNumConnections() int {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	return len(h.verifiedIdToConnections)
}

func (h *Host) GetReadTimeout() time.Duration {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	return h.readTimeout
}

func (h *Host) GetWriteTimeout() time.Duration {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	return h.writeTimeout
}

func (h *Host) GetRole() Role {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	return h.role
}

func (h *Host) SetRole(role Role) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	h.role = role
}

// Broadcast sends `m` to all connections if the following conditions match:
// 1. the connection is enabled for broadcast.
// 2. `filter` is nil or `filter` returns true.
func (h *Host) Broadcast(m *Message, filter func(ConsensusId) bool) (uint, error) {
	// NOTE: m will be shared by multiple goroutines if the connections
	// are implemented by channels. However, we will not modify the content of m
	// normally, so there is no data race.
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if len(h.verifiedIdToConnections) == 0 {
		return 0, xerrors.New("no connected hosts")
	}

	b := uint(0)
	for id, c := range h.verifiedIdToConnections {
		if filter != nil && !filter(id) {
			continue
		}

		b++
		c.asyncWrite(m)
	}

	if b == 0 {
		logger.Info("[%s] broadcast when no connected hosts", h.loggingId)
	}
	return b, nil
}

func (h *Host) Send(id ConsensusId, m *Message) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	c, ok := h.verifiedIdToConnections[id]
	if !ok {
		return xerrors.Errorf("failed to send message (type=%d); id %s not exist",
			m.GetType(), id)
	}
	c.asyncWrite(m)

	return nil
}

func (h *Host) getConnection(connectId, verifiedId ConsensusId, connectAddress string) connection {
	h.mutex.CheckIsLocked("")

	if connectId != "" {
		// We've connected the same id before.
		if c, ok := h.connectIdToConnections[connectId]; ok {
			return c
		}
		// The peer has already connected to us.
		if c, ok := h.verifiedIdToConnections[connectId]; ok {
			return c
		}
	}
	if verifiedId != "" {
		// We've connected the same id before.
		if c, ok := h.connectIdToConnections[verifiedId]; ok {
			return c
		}
		// The peer has already connected to us.
		if c, ok := h.verifiedIdToConnections[verifiedId]; ok {
			return c
		}
	}
	if connectAddress != "" {
		// We've connected the same address before.
		if c, ok := h.addressToConnections[connectAddress]; ok {
			return c
		}
	}
	return nil
}

func (h *Host) addConnection(ctx context.Context, c connection) {
	h.mutex.Lock()
	connectId := c.getConnectId()
	verifiedId := c.getVerifiedId()
	address := c.getAddress()
	connectAddress := c.getConnectAddress()
	if verifiedId == "" {
		debug.Bug("verifiedId should never be empty (connectId:%q)", connectId)
	}
	if address == "" {
		debug.Bug("address should never be empty (connectId:%q, verifiedId=%q)", connectId, verifiedId)
	}

	if err := ctx.Err(); err != nil {
		logger.Error("[%s] drop new connection to %s due to %s", h.loggingId, connectId, err)
		if err := c.close(); err != nil {
			logger.Warn("[%s] failed to close: %s (%s)", h.loggingId, err, c.getDebugInfo())
		}
		h.mutex.Unlock()
		return
	}

	// Handle connecting to self.
	if verifiedId == h.authenticator.GetSigningId() {
		logger.Info("[%s] drop new connection to self", h.loggingId)
		m := &Message{
			attribute: AttrHandshakeError,
			err:       ErrConnectedToSelf,
		}

		// While we're attacked, there may be a lot of handshake errors.
		// To not occupy any resource, drop the message if we cannot notify the client now.
		h.sink.Send(m, NonBlockingCall)
		_ = c.close()
		h.mutex.Unlock()
		return
	}

	var closedMsg *Message
	if oc := h.getConnection(connectId, verifiedId, connectAddress); oc != nil {
		// Handle the case that two nodes connect to each other without knowing their connect id
		// (e.g., two bootnodes connect to each other).
		// Consider node A and B connect to each other and A connects first and the handshake is done.
		// Here is what happens when B connects to A:
		// 1. Both A and B drops their old connections.
		// 2. B remembers the connectAddress of A, so B will not reconnect.
		// 3. A gets the connectAddress from the old connection (the code below),
		//    so A will not reconnect, either.
		if oc.getConnectAddress() != "" && c.getConnectAddress() == "" {
			c.setConnectAddress(oc.getConnectAddress())
			connectAddress = c.getConnectAddress()
		}

		// Duplicated connections handling:
		// 1. private vs. public: keep the private one.
		// 2. new vs. old: keep the new one.
		ocIsPrivate := utils.IsPrivateIPByString(utils.StripPort(oc.getAddress()))
		cIsPrivate := utils.IsPrivateIPByString(utils.StripPort(c.getAddress()))
		if cIsPrivate != ocIsPrivate && ocIsPrivate {
			// Keep the old one.
			logger.Info("[%s] drop new connection (%s) because the old one uses a private IP",
				h.loggingId, c.getAddress())
			_ = c.close()
			h.mutex.Unlock()
			return
		}

		// Keep the new one.
		closedMsg = h.removeConnection(oc, "addConnection")
	}

	c = newThrottlingConnection(c, h.throttler)

	if connectId != "" {
		h.connectIdToConnections[connectId] = c
	}
	h.verifiedIdToConnections[verifiedId] = c
	h.addressToConnections[connectAddress] = c
	h.mutex.Unlock()
	logger.Info("[%s] added new connection to %s (connectId=%s, remoteLoggingId=%s, address=%s, connectAddress=%s)",
		h.loggingId, verifiedId, connectId, c.getRemoteLoggingId(), address, connectAddress)

	// Must call this before sending the message,
	// so the user of Host can do some preprocessing works.
	if h.connectionObserver != nil {
		h.connectionObserver.OnConnected(
			c.getConnectAddress(), c.getConnectId(), c.getVerifiedId())
	}

	m := &Message{
		attribute: AttrOpen,
		source:    c,
	}

	// It's possible for h.sink buffer to become full and we will block on writing to h.sink,
	// so run this in its own goroutine.
	go func() {
		// Guarantee sending the closed msg *before* the open msg.
		if closedMsg != nil {
			h.sink.Send(closedMsg, BlockingCall)
		}
		h.sink.Send(m, BlockingCall)
		// To ensure the order, start the reader goroutine after sending the opening message.
		go h.receive(c)
	}()
}

// receive runs in a new goroutine without holding the mutex.
func (h *Host) receive(c connection) {
	for {
		m, err := c.read()
		if err != nil {
			logger.Error("[%s] %s: read fails; err=%s", h.loggingId, c.getDebugInfo(), err)

			h.mutex.Lock()
			cm := h.removeConnection(c, "receive")
			h.mutex.Unlock()
			if cm != nil {
				// NOTE: There may be a race condition between receive() and addConnection()
				// when there is a duplicated connection. The peer just closed the connection
				// and it's possible receive() reads the closed connection and gets an error
				// *before* addConnection() checks the duplicated connection. In that case,
				// the user of Host may receive the open event (sent by addConnection() *before*
				// the closed event (sent by receive()). Thus, we must call Send() immediately.
				h.sink.Send(cm, BlockingCall)
			}
			return
		}

		h.sink.Send(m, BlockingCall)
	}
}

func (h *Host) removeConnection(c connection, caller string) *Message {
	h.mutex.CheckIsLocked("")

	// connections may be closed by the host owner or from the other end so it is a legitimate case to close twice
	if err := c.close(); err != nil {
		logger.Info("[%s] failed to close: %s (%s)", h.loggingId, err, c.getDebugInfo())
	}

	// When there are duplicated connections, here is what happens:
	// 1. addConnection() closes a duplicated connection and call removeConnection() with c.
	// 2. addConnection() starts a new goroutine to run receive() with c'.
	// 3. An old goroutine which runs receive() with c gets a read error
	//    and then call removeConnection() with c. This time we should skip the call;
	//    otherwise, we'll accidentally close c'.
	if cc, ok := h.verifiedIdToConnections[c.getVerifiedId()]; !ok || cc != c {
		return nil
	}

	metrics.IncCounter(h.metrics.Disconnects)
	delete(h.verifiedIdToConnections, c.getVerifiedId())
	if c.getConnectId() != "" {
		delete(h.connectIdToConnections, c.getConnectId())
	}
	if c.getConnectAddress() != "" {
		delete(h.addressToConnections, c.getConnectAddress())
	}

	// Must call this before sending the message,
	// so the user of Host can do some preprocessing works.
	if h.connectionObserver != nil {
		h.connectionObserver.OnDisconnected(
			c.getConnectAddress(), c.getConnectId(), c.getVerifiedId())
	}

	return &Message{
		attribute: AttrClosed,
		source:    c,
		blob:      []byte{},
	}
}

func (h *Host) CloseAllConnections() {
	cs := h.resetConnectCtx()
	var ms []*Message
	h.mutex.Lock()
	for _, c := range cs {
		if m := h.removeConnection(c, "CloseAllConnections"); m != nil {
			ms = append(ms, m)
		}
	}
	h.mutex.Unlock()

	// To avoid a deadlock on sink, send messages in a new goroutine.
	go func() {
		for _, m := range ms {
			h.sink.Send(m, BlockingCall)
		}
	}()
}

func (h *Host) resetConnectCtx() []connection {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	for _, c := range h.unverifiedConns {
		err := c.Close()
		if err != nil {
			logger.Warn("[%s] closing unverified connection failed: %s", h.loggingId, err)
		}
	}
	if h.listener != nil {
		err := h.listener.Close()
		if err != nil {
			logger.Warn("[%s] closing listener failed: %s", h.loggingId, err)
		}
		h.listener = nil
	}
	if h.cancelConnects != nil {
		h.cancelConnects()
	}
	h.connectCtx, h.cancelConnects = context.WithCancel(context.Background())

	var cs []connection
	for _, c := range h.verifiedIdToConnections {
		cs = append(cs, c)
	}
	return cs
}

func (h *Host) getConnectCtx() context.Context {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	return h.connectCtx
}

// CloseConnections closes connections when `filter` returns true.
func (h *Host) CloseConnections(filter func(id ConsensusId) bool) {
	h.mutex.Lock()
	var ms []*Message
	for id, c := range h.verifiedIdToConnections {
		if filter(id) {
			if m := h.removeConnection(c, "CloseConnections"); m != nil {
				ms = append(ms, m)
			}
		}
	}
	h.mutex.Unlock()

	// To avoid a deadlock on sink, send messages in a new goroutine.
	go func() {
		for _, m := range ms {
			h.sink.Send(m, BlockingCall)
		}
	}()
}

func (h *Host) IsCapable(id ConsensusId, feature int) bool {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	var c connection
	var ok bool
	c, ok = h.verifiedIdToConnections[id]
	if !ok {
		return false
	}
	return c.isCapable(feature)
}

//--------------------------------------------------------------------

// For now, one packet represents one message.
// When we want to support the session layer (resume connection silently)
// or prioritized messages, we'll need to support the one-to-many mapping
// between the message and packets.
func newMessageByPacket(p *packet, c connection) (*Message, error) {
	m := Message{
		typ:       p.typ,
		attribute: p.attribute,
		source:    c,
		blob:      p.blob,
	}
	return &m, nil
}

// For now, one packet represents one message.
// When we want to support the session layer (be able to resume connection silently)
// or prioritized messages, we'll need to support the one-to-many mapping
// between the message and packets.
func newPacket(m *Message) *packet {
	body := m.GetBlob()
	return &packet{
		size:      uint32(packetHeaderSize + len(body)),
		typ:       m.GetType(),
		attribute: m.GetAttribute(),
		blob:      body,
	}
}

//--------------------------------------------------------------------

func NewMessage(typ uint8, attribute uint16, blob []byte) *Message {
	return &Message{
		typ:       typ,
		attribute: attribute,
		source:    nil, // The receiver will set this field.
		blob:      blob,
	}
}

func NewMessageWithWriteOnlyConn(typ uint8, attribute uint16, blob []byte, replyCh chan<- *Message) *Message {
	return &Message{
		typ:       typ,
		attribute: attribute,
		source:    newWriteOnlyConn(replyCh),
		blob:      blob,
	}
}

func (m *Message) GetType() uint8 {
	return m.typ
}

func (m *Message) GetAttribute() uint16 {
	return m.attribute
}

func (m *Message) GetConnectId() ConsensusId {
	// No nil check. The caller should only call this on received messages.
	return m.source.getConnectId()
}

func (m *Message) HasId() bool {
	return m.source != nil
}

func (m *Message) GetId() ConsensusId {
	if m.source == nil {
		function, file, line, _ := runtime.Caller(1)
		caller := fmt.Sprintf("%s:%d %s:", path.Base(file), line, runtime.FuncForPC(function).Name())
		logger.Warn("Message.GetId() is called when source is nil (caller: %s)", caller)
		return ""
	}
	return m.source.getVerifiedId()
}

func (m *Message) GetConnectAddress() string {
	// No nil check. The caller should only call this on received messages.
	return m.source.getConnectAddress()
}

func (m *Message) GetBlob() []byte {
	return m.blob
}

func (m *Message) GetExtra() interface{} {
	return m.extra
}

func (m *Message) Reply(msg *Message) error {
	if msg.source != nil {
		return xerrors.New("Reply() is called with source == nil")
	}
	m.source.asyncWrite(msg)
	return nil
}

func (m *Message) Clone() *Message {
	blob := make([]byte, len(m.blob))
	copy(blob, m.blob)

	return &Message{
		typ:       m.typ,
		attribute: m.attribute,
		source:    m.source,
		blob:      blob,
		extra:     m.extra,
		err:       m.err,
	}
}

func (m *Message) CloseConnection() error {
	return m.source.close()
}

func (m *Message) IsClosed() bool {
	return m.source.isClosed()
}

func (m *Message) GetSourceAddress() string {
	if m.source == nil {
		return ""
	}
	return m.source.getAddress()
}

func (m *Message) GetSourceDebugInfo() string {
	if m.source == nil {
		return ""
	}
	return m.source.getDebugInfo()
}

func (m *Message) GetError() error {
	return m.err
}

//--------------------------------------------------------------------

func (p *handshakeMessage) setCapability(c uint, v bool) {
	bit := byte(1 << (c % 8))
	if v {
		p.reserved[c/8] |= bit
	} else {
		p.reserved[c/8] &= ^bit
	}
}

func (p *handshakeMessage) isCapable(c uint) bool {
	bit := byte(1 << (c % 8))
	return (p.reserved[c/8] & bit) == bit
}

func marshalHandshakeMessage(p *handshakeMessage) []byte {
	var out [handshakeMessageLength]byte
	copy(out[:2], utils.Uint16ToBytes(p.version))
	copy(out[2:10], utils.Uint64ToBytes(p.networkId))
	copy(out[10:], p.reserved[:])
	return out[:]
}

func unmarshalHandshakeMessage(bytes []byte) (*handshakeMessage, error) {
	if len(bytes) != handshakeMessageLength {
		return nil, xerrors.Errorf("invalid input: length is not %d", handshakeMessageLength)
	}
	var p handshakeMessage
	var err error
	p.version, bytes, err = utils.BytesToUint16(bytes)
	if err != nil {
		return nil, err
	}

	p.networkId, bytes, err = utils.BytesToUint64(bytes)
	if err != nil {
		return nil, err
	}

	copy(p.reserved[:], bytes)
	return &p, nil
}

func writeClientPuzzleExtensionMessage(conn net.Conn, puzzleTypes []string, challengeResponse []byte) error {
	msg := ClientPuzzleExtension{
		puzzleTypes:       puzzleTypes,
		challengeResponse: challengeResponse,
	}
	return writeBytes(conn, msg.ToBytes())
}

func writeChallengeResponseMessage(conn net.Conn, signature []byte) error {
	return writeBytes(conn, signature)
}

func writeRemoteLoggingId(conn net.Conn, loggingId string) error {
	if len(loggingId) > 50 {
		return writeBytes(conn, []byte(loggingId[:50]))
	}
	return writeBytes(conn, []byte(loggingId))
}

func writeBytes(conn net.Conn, data []byte) error {
	_, err := conn.Write(utils.Uint16ToBytes(uint16(len(data))))
	if err != nil {
		return err
	}

	_, err = conn.Write(data)
	return err
}

func readClientPuzzleExtensionMessage(conn net.Conn) (*ClientPuzzleExtension, error) {
	bytes, err := readBytes(conn)
	if err != nil {
		return nil, err
	}

	var ext ClientPuzzleExtension
	if err := ext.FromBytes(bytes); err != nil {
		return nil, err
	}
	return &ext, nil
}

func readChallengeResponseMessage(conn net.Conn) ([]byte, error) {
	return readBytes(conn)
}

func readRemoteLoggingId(conn net.Conn) (string, error) {
	bytes, err := readBytes(conn)
	if err != nil {
		return "", err
	}
	loggingId := string(bytes)
	if len(loggingId) > 50 {
		loggingId = loggingId[:50]
	}
	return loggingId, nil
}

func readBytes(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	size, _, err := utils.BytesToUint16(buf)
	if err != nil {
		return nil, err
	}

	buf = make([]byte, size)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	return buf, nil
}

func IsClosedError(err error) bool {
	if err == nil {
		return false
	}
	// See `parseCloseError` in `src/net/error_test.go`:
	// https://sourcegraph.com/github.com/golang/go@afd2d2b/-/blob/src/net/error_test.go#L329:6
	return strings.Contains(err.Error(), "use of closed network connection")
}

//--------------------------------------------------------------------

func NewClock() Clock {
	return &clockImpl{}
}

func (c *clockImpl) Now() time.Time {
	return time.Now()
}

func (c *clockImpl) Sleep(d time.Duration) {
	time.Sleep(d)
}
