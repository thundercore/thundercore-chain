package limiter

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type clockFake struct {
	now time.Time
}

func (c *clockFake) Now() time.Time { return c.now }

func (c *clockFake) add(d time.Duration) { c.now = c.now.Add(d) }

func TestLimiterAllow(t *testing.T) {

	t.Run("basic", func(t *testing.T) {
		req := require.New(t)
		clock := &clockFake{now: time.Now()}
		l := newLimiter(3, time.Second, clock)

		req.True(l.Allow(1))
		req.True(l.Allow(1))
		req.True(l.Allow(1))
		req.False(l.Allow(1))
		req.False(l.Allow(1))
	})

	t.Run("different n", func(t *testing.T) {
		req := require.New(t)
		clock := &clockFake{now: time.Now()}
		l := newLimiter(5, time.Second, clock)

		req.True(l.Allow(1))
		req.True(l.Allow(2))
		req.False(l.Allow(3))
		req.True(l.Allow(1))
		req.False(l.Allow(2))
	})

	t.Run("time runs", func(t *testing.T) {
		req := require.New(t)
		clock := &clockFake{now: time.Now()}
		l := newLimiter(3, time.Second, clock)

		req.True(l.Allow(2))
		clock.add(100 * time.Millisecond)

		req.True(l.Allow(1))
		clock.add(100 * time.Millisecond)

		req.False(l.Allow(3))
		req.False(l.Allow(1))
		clock.add(801 * time.Millisecond)

		req.False(l.Allow(3))
		req.True(l.Allow(1))
		clock.add(100 * time.Millisecond)

		req.False(l.Allow(3))
		req.True(l.Allow(2))

		clock.add(1001 * time.Millisecond)

		req.False(l.Allow(4))
		req.True(l.Allow(3))
	})
}
