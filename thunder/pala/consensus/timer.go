package consensus

import (
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
)

const voterWaitingTimeInMS = 6000

type Timer interface {
	GetChannel() <-chan time.Time
	// epoch is used to have a more deterministic timeout in test.
	// We don't expect it's necessary for the production code.
	Reset(duration time.Duration, epoch blockchain.Epoch)
	Stop()
}

type timerImpl struct {
	timer *time.Timer
}

func NewTimer(epoch blockchain.Epoch) Timer {
	// create a stopped timer
	t := time.NewTimer(0)
	<-t.C
	return &timerImpl{
		t,
	}
}

func (t *timerImpl) GetChannel() <-chan time.Time {
	return t.timer.C
}

func (t *timerImpl) Reset(duration time.Duration, epoch blockchain.Epoch) {
	t.Stop()
	t.timer.Reset(duration)
}

func (t *timerImpl) Stop() {
	if !t.timer.Stop() {
		select {
		case <-t.timer.C:
		default:
		}

	}
}
