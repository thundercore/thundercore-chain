package limiter

import (
	"sync"
	"time"
)

type Clock interface {
	Now() time.Time
}

type clock struct{}

func (c clock) Now() time.Time { return time.Now() }

type Limiter struct {
	mu     sync.Mutex
	limit  int64
	window time.Duration
	clock  Clock
	log    *Log
}

func NewLimiter(limit int64, window time.Duration) *Limiter {
	return newLimiter(limit, window, clock{})
}

func newLimiter(limit int64, window time.Duration, clock Clock) *Limiter {
	return &Limiter{
		limit:  limit,
		window: window,
		clock:  clock,
		log:    NewLog(),
	}
}

func (l *Limiter) Allow(n int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clock.Now()

	l.log.RemoveRecordBefore(now.Add(-l.window))

	if l.log.Sum()+n > l.limit {
		return false
	}

	l.log.AppendRecord(now, n)
	return true
}
