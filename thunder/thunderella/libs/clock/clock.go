package clock

import (
	// Standard imports
	"time"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
)

type Clock interface {
	Now() time.Time
	Sleep(d time.Duration)
	NewTimer(d time.Duration) *time.Timer
}

type realClock struct {
}

func (c *realClock) Now() time.Time {
	return time.Now()
}

func (c *realClock) Sleep(d time.Duration) {
	time.Sleep(d)
}

func (c *realClock) NewTimer(d time.Duration) *time.Timer {
	return time.NewTimer(d)
}

type fakeClock struct {
	rate time.Duration
	base time.Time
}

func (c *fakeClock) Now() time.Time {
	d := time.Since(c.base)
	return c.base.Add(d * c.rate)
}

func (c *fakeClock) Sleep(d time.Duration) {
	time.Sleep(d / c.rate)
}

func (c *fakeClock) NewTimer(d time.Duration) *time.Timer {
	return time.NewTimer(d / c.rate)
}

func NewRealClock() Clock {
	return &realClock{}
}

func NewFakeClock(rate int) Clock {
	if rate <= 0 {
		debug.Bug("rate is invalid: %d", rate)
	}

	return &fakeClock{time.Duration(rate), time.Now()}
}
