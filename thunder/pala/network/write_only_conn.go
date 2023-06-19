package network

import (
	"context"
	"sync"
)

type writeOnlyConn struct {
	mu      sync.Mutex
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
	writeCh chan<- *Message
}

func newWriteOnlyConn(ch chan<- *Message) connection {
	ctx, cancel := context.WithCancel(context.Background())
	return &writeOnlyConn{
		ctx:     ctx,
		cancel:  cancel,
		writeCh: ch,
	}
}

func (c *writeOnlyConn) asyncWrite(msg *Message) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ctx.Err() != nil {
		return
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		select {
		case c.writeCh <- msg:
		case <-c.ctx.Done():
		}
	}()
}

func (c *writeOnlyConn) close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ctx.Err() != nil {
		return c.ctx.Err()
	}
	c.cancel()
	c.wg.Wait()
	return nil
}

func (c *writeOnlyConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ctx.Err() != nil
}

// dummy implementation of not used method
func (c *writeOnlyConn) read() (*Message, error) { return nil, nil }

func (c *writeOnlyConn) getConnectId() ConsensusId  { return ConsensusId("fake") }
func (c *writeOnlyConn) getVerifiedId() ConsensusId { return ConsensusId("fake") }

func (c *writeOnlyConn) setId(id ConsensusId) {}

func (c *writeOnlyConn) getRole() Role { return 0 }

func (c *writeOnlyConn) isCapable(feature int) bool { return true }

func (c *writeOnlyConn) getAddress() string { return "" }

func (c *writeOnlyConn) setConnectAddress(addr string) {}

func (c *writeOnlyConn) getConnectAddress() string { return "" }

func (c *writeOnlyConn) getDebugInfo() string       { return "" }
func (c *writeOnlyConn) getRemoteLoggingId() string { return "" }
