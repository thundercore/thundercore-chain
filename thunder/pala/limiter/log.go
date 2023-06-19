package limiter

import (
	"container/list"
	"time"
)

type record struct {
	n           int64
	createdTime time.Time
}

type Log struct {
	records *list.List
	sum     int64
}

func NewLog() *Log {
	return &Log{
		records: list.New(),
	}
}

func (m *Log) AppendRecord(t time.Time, n int64) {
	if b := m.records.Back(); b != nil {
		if t.Before(b.Value.(*record).createdTime) {
			panic("time out of order")
		}
	}
	l := &record{n: n, createdTime: t}
	m.records.PushBack(l)
	m.sum += n
}

func (m *Log) RemoveRecordBefore(t time.Time) {
	for m.records.Len() > 0 {
		e := m.records.Front()
		l := e.Value.(*record)
		if l.createdTime.After(t) {
			return
		}
		m.sum -= l.n
		m.records.Remove(e)
	}
}

func (m *Log) Sum() int64 { return m.sum }

func (m *Log) Len() int { return m.records.Len() }
