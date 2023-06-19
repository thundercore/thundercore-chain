package limiter

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLog(t *testing.T) {

	var ts []time.Time
	now := time.Now()
	for i := 0; i < 10; i++ {
		ts = append(ts, now.Add(time.Duration(i)))
	}

	t.Run("append record", func(t *testing.T) {
		req := require.New(t)
		m := NewLog()

		m.AppendRecord(ts[0], 1)
		req.Equal(int(1), m.Len())
		req.Equal(int64(1), m.Sum())

		m.AppendRecord(ts[1], 3)
		req.Equal(int(2), m.Len())
		req.Equal(int64(4), m.Sum())

		m.AppendRecord(ts[1], 2)
		req.Equal(int(3), m.Len())
		req.Equal(int64(6), m.Sum())

		m.AppendRecord(ts[2], 3)
		req.Equal(int(4), m.Len())
		req.Equal(int64(9), m.Sum())

	})

	t.Run("remove record before", func(t *testing.T) {
		req := require.New(t)
		m := NewLog()

		m.AppendRecord(ts[0], 1)
		m.AppendRecord(ts[1], 3)
		m.AppendRecord(ts[3], 5)
		m.AppendRecord(ts[3], 7)
		m.AppendRecord(ts[4], 9)
		m.AppendRecord(ts[5], 11)
		m.AppendRecord(ts[6], 13)
		m.AppendRecord(ts[8], 15)
		req.Equal(int(8), m.Len())
		req.Equal(int64(64), m.Sum())

		m.RemoveRecordBefore(ts[3])
		req.Equal(int(4), m.Len())
		req.Equal(int64(48), m.Sum())

		m.RemoveRecordBefore(ts[7])
		req.Equal(int(1), m.Len())
		req.Equal(int64(15), m.Sum())

		m.RemoveRecordBefore(ts[9])
		req.Equal(int(0), m.Len())
		req.Equal(int64(0), m.Sum())
	})

	t.Run("out of order", func(t *testing.T) {
		req := require.New(t)
		m := NewLog()

		m.AppendRecord(ts[0], 1)
		req.Equal(int(1), m.Len())
		req.Equal(int64(1), m.Sum())

		m.AppendRecord(ts[2], 2)
		req.Equal(int(2), m.Len())
		req.Equal(int64(3), m.Sum())

		req.Panics(func() {
			m.AppendRecord(ts[1], 1)
		})
	})

}
