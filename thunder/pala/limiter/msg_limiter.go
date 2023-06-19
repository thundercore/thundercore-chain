package limiter

import (
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"
)

type Id string
type MsgId string

var (
	// MsgLimiter will remove records of idle peers
	// Do gc every `gcFrequency` msgs
	gcFrequency = int64(10000)
	// Consider peer who has no heartbeat more than `maxIdleTime` as idle peer.
	maxIdleTime = 10 * time.Second

	// The max allowed window of the underlying limiter.
	maxAllowedWindow = time.Second

	logger = lgr.NewLgr("/limiter")
)

// TODO(thunder): limit the message size as well.
type MsgLimitConfig struct {
	MsgId  MsgId
	Limit  int64
	Window time.Duration
}

type MsgLimiter struct {
	mu          utils.CheckedLock
	configs     map[MsgId]MsgLimitConfig
	limiters    map[MsgId]map[Id]*Limiter
	heartbeats  map[Id]time.Time
	msgCounter  int64
	gcFrequency int64
	maxIdleTime time.Duration
}

// NewMsgLimiter create a MsgLimiter with default settings
// the default gcFrequency and maxIdleTime is determined by the expected msg loading.
// We can revisit the settings when we encounter performance issue.
func NewMsgLimiter(configs []MsgLimitConfig) *MsgLimiter {
	return newMsgLimiter(configs, gcFrequency, maxIdleTime)
}

func newMsgLimiter(configs []MsgLimitConfig, gcFrequency int64, maxIdleTime time.Duration) *MsgLimiter {
	l := &MsgLimiter{
		configs:     make(map[MsgId]MsgLimitConfig),
		limiters:    make(map[MsgId]map[Id]*Limiter),
		heartbeats:  make(map[Id]time.Time),
		msgCounter:  0,
		gcFrequency: gcFrequency,
		maxIdleTime: maxIdleTime,
	}

	for i, c := range configs {
		if c.Window > maxAllowedWindow {
			msg := fmt.Sprintf(
				"config #%d invalid, exceed max allowed window, config window=%s max allowed window=%s",
				i, c.Window, maxAllowedWindow)
			panic(msg)
		}
		l.configs[c.MsgId] = c
		l.limiters[c.MsgId] = make(map[Id]*Limiter)
	}
	return l
}

func (l *MsgLimiter) Allow(msgid MsgId, id Id, n int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	limiter := l.getLimiterLocked(msgid, id)
	// no Limit on this msg type, always allow
	if limiter == nil {
		return true
	}

	return limiter.Allow(n)
}

func (l *MsgLimiter) getLimiterLocked(msgid MsgId, id Id) *Limiter {
	l.mu.CheckIsLocked("")
	config, ok := l.configs[msgid]
	if !ok {
		return nil
	}

	if _, ok := l.limiters[msgid][id]; !ok {
		l.limiters[msgid][id] = NewLimiter(config.Limit, config.Window)
	}

	// GC related operations
	l.msgCounter += 1
	l.heartbeats[id] = time.Now()
	l.gcLocked()

	return l.limiters[msgid][id]
}

func (l *MsgLimiter) gcLocked() {
	l.mu.CheckIsLocked("")
	if l.msgCounter < l.gcFrequency {
		return
	}
	// Reset counter
	l.msgCounter = 0
	if len(l.heartbeats) > 10000 {
		logger.Warn("Too many records (num: %d), may have performance issue.", len(l.heartbeats))
	}
	for id, t := range l.heartbeats {
		if time.Since(t) > l.maxIdleTime {
			for _, ls := range l.limiters {
				delete(ls, id)
			}
			delete(l.heartbeats, id)
		}
	}
}
