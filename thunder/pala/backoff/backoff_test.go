package backoff

import (
	"context"
	"testing"
	"time"
)

func TestLinear(t *testing.T) {
	type args struct {
		start time.Duration
		limit time.Duration
	}
	tests := []struct {
		name string
		args args
	}{
		{"linear 25ms 1000ms cancel at 200ms", args{start: 25 * time.Millisecond, limit: 1000 * time.Millisecond}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewLinear(tt.args.start, tt.args.limit)
			ctx, cancelBackoff := context.WithCancel(context.Background())
			go func() {
				time.Sleep(200 * time.Millisecond)
				cancelBackoff()
			}()
			for {
				err := b.Backoff(ctx)
				if err != nil {
					break
				}
				t.Logf("backedoff: %s", time.Now())
			}
		})
	}
}
