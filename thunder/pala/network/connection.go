package network

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils/deque"

	"github.com/golang/snappy"
)

// All operations must be goroutine-safe.
type connection interface {
	read() (*Message, error)
	// we don't expect or handle error here.
	asyncWrite(msg *Message)
	close() error
	isClosed() bool
	// Assume X connects to Y via a connect id C and an address A.
	// X's getConnectId() returns C (may be empty);
	// Y's getConnectId() returns an empty id.
	getConnectId() ConsensusId
	getVerifiedId() ConsensusId
	getRole() Role
	isCapable(feature int) bool
	// Return the peer's address which should not be empty.
	getAddress() string
	// Assume X connects to Y via a connect id C and an address A.
	// X's getConnectId() returns A
	// Y's getConnectId() returns an empty string.
	// Note that X's getConnectId() may be differnt from A's getAddress().
	getConnectAddress() string
	setConnectAddress(addr string)
	getDebugInfo() string
	getRemoteLoggingId() string
}

type connectionImpl struct {
	connectId       ConsensusId
	verifiedId      ConsensusId
	connectAddress  string
	remoteLoggingId string
	role            Role
	readTimeout     time.Duration
	writeTimeout    time.Duration
	conn            net.Conn
	handshake       *handshakeMessage
	// otherwise, use `conn.(*tls.Conn).ConnectionState().PeerCertificates`

	// Member fields below are protected by mutex.
	mutex  sync.Mutex
	closed bool
	ch     chan *Message
	stopCh chan chan error
}

type throttlingConnection struct {
	connection
	throttler *throttler
}

type throttler struct {
	// Set once in the constructor.
	cfg ThrottlingConfig
	clk Clock

	// Protected by the mutex.
	mutex   sync.Mutex
	sources map[ConsensusId]*logs
	union   *logs
}

type clockImpl struct {
}

type logs struct {
	countPerSecond uint
	details        deque.Deque
	sum            int
}

type log struct {
	createdTime time.Time
	numBytes    int
}

//--------------------------------------------------------------------

func newConnection(
	handshake *handshakeMessage, connectId, verifiedId ConsensusId,
	connectAddress, remoteLoggingId string, readTimeout, writeTimeout time.Duration, conn net.Conn,
) connection {
	role := RoleSpoke
	if handshake.isCapable(CapabilityHub) {
		role = RoleHub
	}

	c := &connectionImpl{
		connectId:       connectId,
		verifiedId:      verifiedId,
		connectAddress:  connectAddress,
		remoteLoggingId: remoteLoggingId,
		role:            role,
		readTimeout:     readTimeout,
		writeTimeout:    writeTimeout,
		conn:            conn,
		handshake:       handshake,
		ch:              make(chan *Message, 1024),
		stopCh:          make(chan chan error, 1),
	}

	go c.loop()

	return c
}

func (c *connectionImpl) loop() {
	write := func(p *packet) error {
		if p.size-packetHeaderSize > MaxMessageBodySize {
			logger.Warn("write a message whose body size=%d > the max=%d",
				p.size-packetHeaderSize, MaxMessageBodySize)
			return ErrExceedMaxMessageSize
		}
		if c.isCapable(CapabilitySnappy) && len(p.blob) > 0 {
			compressed := snappy.Encode(nil, p.blob)
			diff := len(p.blob) - len(compressed)
			if diff > 0 {
				p.size -= uint32(diff)
				p.blob = compressed
				p.attribute |= AttrCompressed
			}
		}
		c.conn.SetWriteDeadline(time.Now().Add(c.writeTimeout))
		if _, err := c.conn.Write(utils.Uint32ToBytes(p.size)); err != nil {
			return err
		}
		if _, err := c.conn.Write([]byte{byte(p.typ)}); err != nil {
			return err
		}
		if _, err := c.conn.Write(utils.Uint16ToBytes(p.attribute)); err != nil {
			return err
		}
		if _, err := c.conn.Write(p.blob); err != nil {
			return err
		}
		return nil
	}

	ch := c.ch
	stopCh := c.stopCh
	for {
		select {
		case msg := <-ch:
			p := newPacket(msg)
			if err := write(p); err != nil {
				logger.Info("cannot write to %s; err=%s", c.getAddress(), err)
				// Run in a new goroutine to avoid the deadlock due to c.stopCh.
				go c.close()
				ch = nil
				continue
			}
		case errCh := <-stopCh:
			defer func() {
				errCh <- nil
			}()
			return
		}
	}
}

func (c *connectionImpl) read() (*Message, error) {
	// To ensure the connection is healthy, set a read timeout since there is always some message
	// (e.g., MessageStatus) within a period normally.
	c.conn.SetReadDeadline(time.Now().Add(c.readTimeout))
	tmp := make([]byte, 4)
	// packet.size
	if _, err := io.ReadFull(c.conn, tmp); err != nil {
		return nil, err
	}
	size, _, err := utils.BytesToUint32(tmp)
	if err != nil {
		return nil, err
	}
	p := packet{size: size}

	// The maximum size is probably <1MB in our current usage, so allocating one buffer is safe.
	if p.size-packetHeaderSize > MaxMessageBodySize {
		logger.Warn("read a message whose body size=%d > the max=%d",
			p.size-packetHeaderSize, MaxMessageBodySize)
		return nil, ErrExceedMaxMessageSize
	}
	buf := make([]byte, p.size-4)

	if _, err := io.ReadFull(c.conn, buf); err != nil {
		return nil, err
	}

	// packet.typ
	p.typ = buf[0]
	buf = buf[1:]

	// packet.attribute
	if p.attribute, buf, err = utils.BytesToUint16(buf); err != nil {
		return nil, err
	}

	// packet.blob
	p.blob = buf
	if c.isCapable(CapabilitySnappy) &&
		(p.attribute&AttrCompressed) == AttrCompressed && len(p.blob) > 0 {
		var err error
		if p.blob, err = snappy.Decode(nil, p.blob); err != nil {
			return nil, err
		}
	}

	// Note that we can use handshakeMessage.version to determine how to read data.
	// E.g., support multiplexing in a new version.
	//
	// version 1: message-to-packet is 1 : 1.
	m, err := newMessageByPacket(&p, c)
	if err != nil {
		return nil, err
	}

	return m, nil
}

func (c *connectionImpl) asyncWrite(msg *Message) {
	select {
	case c.ch <- msg:
	default:
		logger.Warn("connection buffer is full; close the connection")
		c.close()
	}
}

func (c *connectionImpl) close() error {
	c.mutex.Lock()
	if c.closed {
		c.mutex.Unlock()
		return nil
	}

	c.closed = true
	ch := make(chan error)
	c.stopCh <- ch
	err := c.conn.Close()
	c.mutex.Unlock()
	// Don't block the call.
	go func() { <-ch }()
	return err
}

func (c *connectionImpl) isClosed() bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.closed
}

func (c *connectionImpl) getConnectId() ConsensusId {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.connectId
}

func (c *connectionImpl) getVerifiedId() ConsensusId {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.verifiedId
}

func (c *connectionImpl) getRole() Role {
	return c.role
}

func (c *connectionImpl) isCapable(feature int) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.handshake.isCapable(uint(feature))
}

func (c *connectionImpl) getAddress() string {
	return c.conn.RemoteAddr().String()
}

func (c *connectionImpl) getConnectAddress() string {
	return c.connectAddress
}

func (c *connectionImpl) setConnectAddress(addr string) {
	c.connectAddress = addr
}

func (c *connectionImpl) getRemoteLoggingId() string {
	return c.remoteLoggingId
}

func (c *connectionImpl) getDebugInfo() string {
	return fmt.Sprintf("(local:%s,remote:%s)",
		c.conn.LocalAddr().String(),
		c.conn.RemoteAddr().String())
}

//--------------------------------------------------------------------

func newThrottlingConnection(c connection, t *throttler) connection {
	return &throttlingConnection{c, t}
}

func (c *throttlingConnection) read() (*Message, error) {
	m, err := c.connection.read()
	if err != nil {
		return nil, err
	}
	d := c.throttler.pauseReadIfNeeded(c.getVerifiedId(), len(m.GetBlob()))
	c.throttler.clk.Sleep(d)

	return m, err
}

func (c *throttlingConnection) close() error {
	c.throttler.remove(c.connection.getVerifiedId())
	return c.connection.close()
}

//--------------------------------------------------------------------

func newThrottler(cfg ThrottlingConfig, clk Clock) *throttler {
	if cfg.TotalReadBytesThresholdPerSecond < cfg.ReadBytesPerSecond {
		cfg.TotalReadBytesThresholdPerSecond = cfg.ReadBytesPerSecond
	}
	return &throttler{
		cfg:     cfg,
		clk:     clk,
		sources: make(map[ConsensusId]*logs),
		// As long as logs's size in sources is bounded , union's size is bounded implicitly.
		union: &logs{},
	}
}

func (th *throttler) pauseReadIfNeeded(id ConsensusId, numBytes int) time.Duration {
	th.mutex.Lock()
	defer th.mutex.Unlock()

	s, ok := th.sources[id]
	if !ok {
		s = &logs{countPerSecond: th.cfg.MessageCountPerSecond}
		th.sources[id] = s
	}

	// Check count throttling.
	l := &log{th.clk.Now(), numBytes}
	var sleepingDuration time.Duration
	if d := s.add(l); d > sleepingDuration {
		sleepingDuration = d
	}
	if d := th.union.add(l); d > sleepingDuration {
		sleepingDuration = d
	}

	// Check bytes throttling.
	if th.cfg.TotalReadBytesThresholdPerSecond > 0 &&
		th.union.readBytes() > int(th.cfg.TotalReadBytesThresholdPerSecond) {
		if th.cfg.ReadBytesPerSecond > 0 && s.readBytes() > int(th.cfg.ReadBytesPerSecond) {
			// Do throttling based on simple moving average.
			seconds := float64(s.readBytes()) / float64(th.cfg.ReadBytesPerSecond)
			d := time.Duration(seconds*float64(time.Second)) - s.interval(th.clk.Now())
			if d > sleepingDuration {
				sleepingDuration = d
			}
		}
	}

	return sleepingDuration
}

func (th *throttler) remove(id ConsensusId) {
	th.mutex.Lock()
	defer th.mutex.Unlock()

	delete(th.sources, id)
}

func (ls *logs) add(l *log) time.Duration {
	now := l.createdTime
	ls.details.PushBack(l)
	ls.sum += l.numBytes

	// Clean up out-of-date logs to maintain ls.sum as a simple moving average.
	for ls.details.Len() > 0 {
		l2 := ls.details.Front().(*log)
		if l2.createdTime.Add(time.Second).Before(now) {
			ls.sum -= l2.numBytes
			ls.details.PopFront()
		} else {
			break
		}
	}

	if ls.countPerSecond > 0 && ls.details.Len() > int(ls.countPerSecond) {
		l2 := ls.details.Front().(*log)
		ls.sum -= l2.numBytes
		ls.details.PopFront()

		return l2.createdTime.Add(time.Second).Sub(now)
	}
	return 0
}

func (ls *logs) readBytes() int {
	return ls.sum
}

func (ls *logs) interval(now time.Time) time.Duration {
	if ls.details.Len() < 1 {
		return 0
	}
	d := now.Sub(ls.details.Front().(*log).createdTime)
	if d < 0 {
		logger.Warn("logs are not in ordered")
		d = 0
	}
	return d
}

func (l *log) String() string {
	return fmt.Sprintf("%d at %s", l.numBytes, l.createdTime)
}
