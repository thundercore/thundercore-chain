package network

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/testutils/detector"
	oTestutils "github.com/ethereum/go-ethereum/thunder/thunderella/testutils"

	"github.com/stretchr/testify/require"
)

type clockFake struct {
	t                time.Time
	sleepingDuration time.Duration
}

func (c *clockFake) Now() time.Time {
	return c.t
}

func (c *clockFake) Sleep(d time.Duration) {
	if d <= 0 {
		return
	}
	c.sleepingDuration += d
	c.t = c.t.Add(d)
}

func (c *clockFake) increase(d time.Duration) {
	c.t = c.t.Add(d)
}

type clockWrapper struct {
	clks    []*clockFake
	current int
}

func (c *clockWrapper) Now() time.Time {
	return c.clks[c.current].Now()
}

func (c *clockWrapper) Sleep(d time.Duration) {
	c.clks[c.current].Sleep(d)
}

func (c *clockWrapper) increase(d time.Duration) {
	c.clks[c.current].increase(d)
}

func (c *clockWrapper) set(current int) {
	c.current = current
}

//------------------------------------------------------------------------------

func TestThrottlingByBytes(t *testing.T) {
	t.Run("no throttling due to no config", func(t *testing.T) {
		req := require.New(t)

		id := ConsensusId("v1")
		cfg := ThrottlingConfig{}
		clk := &clockFake{}
		th := newThrottler(cfg, clk)
		// Test read different bytes.
		for i := 0; i < 10; i++ {
			d := th.pauseReadIfNeeded(id, 1e9)
			clk.Sleep(d)
		}
		// No sleep.
		req.Equal(time.Duration(0), clk.sleepingDuration)
	})

	t.Run("no throttling due to not reaching the upper bound", func(t *testing.T) {
		req := require.New(t)

		id := ConsensusId("v1")
		cfg := ThrottlingConfig{
			TotalReadBytesThresholdPerSecond: 1500,
			ReadBytesPerSecond:               1000,
		}
		clk := &clockFake{}
		th := newThrottler(cfg, clk)
		for i := 0; i < 10; i++ {
			// As long as we read at most TotalReadBytesThreasholdPerSecond in one second,
			// there is no throttling.
			clk.increase(time.Second + time.Nanosecond)
			d := th.pauseReadIfNeeded(id, int(cfg.TotalReadBytesThresholdPerSecond))
			clk.Sleep(d)
		}
		// No sleep.
		req.Equal(time.Duration(0), clk.sleepingDuration)
	})

	t.Run("throttling with multiple connections", func(t *testing.T) {
		req := require.New(t)

		var ids []ConsensusId
		var clks []*clockFake
		var sums []int
		for i := 0; i < 10; i++ {
			ids = append(ids, ConsensusId(fmt.Sprintf("v%d", i)))
			clks = append(clks, &clockFake{})
			sums = append(sums, 0)
		}
		clk := &clockWrapper{clks, 0}
		begin := clk.Now()
		// Use the configuration closed to the production.
		cfg := ThrottlingConfig{
			TotalReadBytesThresholdPerSecond: 5e9, //  5 GB
			ReadBytesPerSecond:               1e7, // 10 MB
		}
		th := newThrottler(cfg, clk)

		r := rand.New(rand.NewSource(0))
		for i := 0; i < 10000; i++ {
			for j := 0; j < len(ids); j++ {
				clk.set(j)
				// Simulate readers read after 1ms if possible.
				clk.increase(time.Millisecond)
				// Simulate readers read different bytes in different ranges.
				n := int(r.Int31n(1e7 / (1 << uint(j))))
				d := th.pauseReadIfNeeded(ids[j], n)
				clk.Sleep(d)
				sums[j] += n
			}
		}

		expectedBps := float64(cfg.ReadBytesPerSecond)
		epsilon := expectedBps / 10
		for i := 0; i < len(ids); i++ {
			clk.set(i)
			ms := clk.Now().Sub(begin) / time.Millisecond
			bps := float64(sums[i]) / float64(ms) * 1000
			// ReadBytesPerSecond is 1000, so bps should be closed to it.
			if i < len(ids)-1 {
				req.True(clks[i].sleepingDuration > 0)
			} else {
				// In the last case, the read bytes is so small such that it doesn't hit the bound.
				req.True(clks[i].sleepingDuration == 0)
			}
			req.GreaterOrEqual(bps, expectedBps-epsilon)
			req.LessOrEqual(bps, expectedBps+epsilon)
		}
	})
}

func TestThrottlingByMessageCount(t *testing.T) {
	t.Run("no throttling due to not reaching the upper bound", func(t *testing.T) {
		req := require.New(t)

		id := ConsensusId("v1")
		cfg := ThrottlingConfig{
			MessageCountPerSecond: 10,
		}
		clk := &clockFake{}
		th := newThrottler(cfg, clk)
		for i := 0; i < 110; i++ {
			clk.increase(100 * time.Millisecond)
			d := th.pauseReadIfNeeded(id, 1)
			clk.Sleep(d)
		}
		req.Equal(time.Duration(0), clk.sleepingDuration)
	})

	t.Run("throttling", func(t *testing.T) {
		req := require.New(t)

		id := ConsensusId("v1")
		cfg := ThrottlingConfig{
			MessageCountPerSecond: 10,
		}
		clk := &clockFake{}
		th := newThrottler(cfg, clk)
		for i := 0; i < 110; i++ {
			d := th.pauseReadIfNeeded(id, 1)
			clk.Sleep(d)
		}
		req.Equal(10*time.Second, clk.sleepingDuration)
	})
}

func TestConnectionImpl(t *testing.T) {
	newConn := func(req *require.Assertions, readTimeout, writeTimeout time.Duration,
	) (connection, net.Conn, net.Listener) {
		l, err := net.Listen("tcp", "0.0.0.0:0")
		req.NoError(err)
		addr := l.Addr().String()

		var serverConn net.Conn
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			serverConn, err = l.Accept()
			req.NoError(err)
		}()

		conn, err := net.Dial("tcp", addr)
		req.NoError(err)
		wg.Wait()
		c := newConnection(&handshakeMessage{}, "id", "id", "addr", "id", readTimeout, writeTimeout, conn)
		return c, serverConn, l
	}

	t.Run("read timeout", func(t *testing.T) {
		if oTestutils.RaceEnabled {
			// Skip because race detector reports there is a race between l.Accept() and net.Dial()
			// in newConn(). Don't know how to fix that.
			return
		}
		d := detector.NewBundleDetector()
		d.SetTrace()
		defer d.Verify(t)

		req := require.New(t)

		c, serverConn, l := newConn(req, 10*time.Millisecond, 24*time.Hour)
		req.NotNil(serverConn)
		defer func() {
		}()

		_, err := c.read()
		req.Error(err)
		nerr, ok := err.(net.Error)
		req.True(ok)
		req.True(nerr.Timeout())

		req.NoError(c.close())
		req.NoError(serverConn.Close())
		req.NoError(l.Close())
	})

	t.Run("write timeout", func(t *testing.T) {
		if oTestutils.RaceEnabled {
			// Skip because race detector reports there is a race between l.Accept() and net.Dial()
			// in newConn(). Don't know how to fix that.
			return
		}

		d := detector.NewBundleDetector()
		d.SetTrace()
		defer d.Verify(t)

		req := require.New(t)

		c, serverConn, l := newConn(req, 24*time.Hour, time.Nanosecond)
		defer func() {
			l.Close()
			serverConn.Close()
		}()

		c.asyncWrite(&Message{})

		_, err := c.read()
		req.Error(err)
		nerr, ok := err.(net.Error)
		req.True(ok)
		req.False(nerr.Timeout()) // Error due to read a closed connection.
		req.True(c.isClosed())
	})
}

func BenchmarkThrottling(b *testing.B) {
	numConnection := 1000
	numMessage := 1000
	// Use a closed-production configuration.
	cfg := ThrottlingConfig{
		TotalReadBytesThresholdPerSecond: 5e9, //  5 GB
		ReadBytesPerSecond:               1e7, // 10 MB
		MessageCountPerSecond:            200,
	}
	clk := &clockFake{}
	th := newThrottler(cfg, clk)
	req := require.New(b)
	ds := make(map[int]time.Duration)
	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		// 1000 connections read 1000 times concurrently.
		for j := 0; j < numConnection; j++ {
			ds[j] = 0
		}
		for j := 0; j < numConnection; j++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				var d time.Duration
				id := ConsensusId(fmt.Sprintf("v%d", index))
				r := rand.New(rand.NewSource(0))
				for k := 0; k < numMessage; k++ {
					d += th.pauseReadIfNeeded(id, int(r.Int31n(1e6)))
				}
				ds[index] = d
			}(j)
		}
		wg.Wait()

		for _, d := range ds {
			numSecond := int64(numMessage / int(cfg.MessageCountPerSecond))
			req.Greater(d.Nanoseconds(), numSecond*time.Second.Nanoseconds(), d)
		}
	}
}
