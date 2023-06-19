package utils

import "time"

type Clock interface {
	Now() time.Time
}

type clockImpl struct {
}

func NewClock() Clock {
	return clockImpl{}
}

func (c clockImpl) Now() time.Time {
	return time.Now()
}

type ClockFake struct {
	now time.Time
}

func NewClockFake() *ClockFake {
	return &ClockFake{}
}

func (c *ClockFake) Now() time.Time {
	return c.now
}

func (c *ClockFake) Add(d time.Duration) {
	c.now = c.now.Add(d)
}
