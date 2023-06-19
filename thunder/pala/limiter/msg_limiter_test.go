package limiter

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMsgLimiter(t *testing.T) {
	msgid1 := MsgId("msg id 1")
	msgid2 := MsgId("msg id 2")

	id1 := Id("id1")
	id2 := Id("id2")

	t.Run("new msg limiter", func(t *testing.T) {
		req := require.New(t)

		configs := []MsgLimitConfig{
			MsgLimitConfig{MsgId: msgid1, Limit: 1, Window: time.Second},
			MsgLimitConfig{MsgId: msgid2, Limit: 7, Window: 10 * time.Millisecond},
			MsgLimitConfig{MsgId: msgid1, Limit: 5, Window: time.Second},
		}

		l := NewMsgLimiter(configs)

		wantConfigs := configs[1:]
		req.Equal(len(wantConfigs), len(l.configs))
		req.Equal(len(wantConfigs), len(l.limiters))

		for _, c := range wantConfigs {
			got, ok := l.configs[c.MsgId]
			req.True(ok)
			req.Equal(c, got)
			_, ok = l.limiters[c.MsgId]
			req.True(ok)
		}
	})

	t.Run("get limiter", func(t *testing.T) {
		req := require.New(t)

		configs := []MsgLimitConfig{
			MsgLimitConfig{MsgId: msgid1, Limit: 1, Window: time.Second},
		}

		l := NewMsgLimiter(configs)

		l.mu.Lock()
		defer l.mu.Unlock()

		l1 := l.getLimiterLocked(msgid1, id1)
		req.NotNil(l1)

		l2 := l.getLimiterLocked(msgid1, id2)
		req.NotNil(l2)

		req.Equal(l1, l.getLimiterLocked(msgid1, id1))
		req.Nil(l.getLimiterLocked(msgid2, id1))
	})

	t.Run("allow", func(t *testing.T) {
		req := require.New(t)
		configs := []MsgLimitConfig{
			MsgLimitConfig{MsgId: msgid1, Limit: 3, Window: 10 * time.Millisecond},
		}

		l := NewMsgLimiter(configs)

		req.True(l.Allow(msgid1, id1, 1))
		req.True(l.Allow(msgid1, id1, 2))
		req.False(l.Allow(msgid1, id1, 1))
		req.True(l.Allow(msgid1, id2, 3))
		req.False(l.Allow(msgid1, id2, 1))

		req.True(l.Allow(msgid2, id1, 100))
		req.True(l.Allow(msgid2, id2, 100))
		req.True(l.Allow(msgid2, id1, 100))
		req.True(l.Allow(msgid2, id2, 100))

		time.Sleep(10 * time.Millisecond)

		req.True(l.Allow(msgid1, id1, 1))
		req.True(l.Allow(msgid1, id1, 2))
		req.False(l.Allow(msgid1, id1, 1))
		req.True(l.Allow(msgid1, id2, 3))
		req.False(l.Allow(msgid1, id2, 1))

		req.Len(l.limiters[msgid1], 2)
	})

	t.Run("gc", func(t *testing.T) {
		req := require.New(t)
		configs := []MsgLimitConfig{
			MsgLimitConfig{MsgId: msgid1, Limit: 3, Window: 10 * time.Millisecond},
		}

		l := newMsgLimiter(configs, 1, 10*time.Millisecond)

		req.True(l.Allow(msgid1, id1, 1))
		req.True(l.Allow(msgid1, id2, 2))

		l.mu.Lock()
		l1 := l.getLimiterLocked(msgid1, id1)
		req.NotNil(l1)
		l2 := l.getLimiterLocked(msgid1, id2)
		req.NotNil(l2)
		l.mu.Unlock()

		time.Sleep(10 * time.Millisecond)
		req.True(l.Allow(msgid1, id1, 1))

		// l2 is gced
		l.mu.Lock()
		defer l.mu.Unlock()
		req.Len(l.limiters[msgid1], 1)
		req.Equal(l1, l.getLimiterLocked(msgid1, id1))

	})
}
