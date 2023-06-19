package consensus

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/testutils/detector"

	"github.com/stretchr/testify/require"
)

func TestTimerFake(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)

	epoch := blockchain.NewEpoch(1, 1)
	timer := NewTimerFake(epoch)
	ch := timer.GetChannel()
	select {
	case <-ch:
		req.FailNow("expect blocked")
	default:
	}

	epoch = epoch.NextEpoch()
	timer.(*TimerFake).AllowAdvancingEpochTo(epoch, time.Nanosecond)
	// Expect the returned channel is unblocked.
	select {
	case <-ch:
	case <-time.NewTimer(10 * time.Millisecond).C:
		req.FailNow("expect not blocked")
	}
}
