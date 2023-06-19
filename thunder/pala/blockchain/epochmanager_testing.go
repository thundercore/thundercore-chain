package blockchain

import (
	"sync"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
)

type EpochManagerFake struct {
	mutex                    sync.Mutex
	epoch                    Epoch
	cNotas                   map[Session]ClockMsgNota
	updatedByReconfiguration bool
}

func NewEpochManagerFake() EpochManager {
	return &EpochManagerFake{
		epoch:  NewEpoch(1, 1),
		cNotas: make(map[Session]ClockMsgNota),
	}
}

func (e *EpochManagerFake) GetEpoch() Epoch {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	return e.epoch
}

func (e *EpochManagerFake) UpdateByClockMsgNota(cn ClockMsgNota) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	epoch := cn.GetEpoch()
	if epoch.Compare(e.epoch) > 0 {
		e.epoch = epoch
		e.cNotas[epoch.Session] = cn
		e.updatedByReconfiguration = false
	} else if epoch.Compare(e.epoch) < 0 {
		debug.Bug("EpochManagerFake does not expect the epoch decreases: %s -> %s", e.epoch, epoch)
	}
	return nil
}

func (e *EpochManagerFake) GetLatestClockMsgNota(session Session) ClockMsgNota {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if cn, ok := e.cNotas[session]; ok {
		return cn
	}
	return nil
}

func (e *EpochManagerFake) SetEpochDueToReconfiguration(epoch Epoch) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if epoch.Compare(e.epoch) < 0 {
		debug.Bug("EpochManagerFake does not expect the epoch decreases: %s -> %s", e.epoch, epoch)
	}
	e.epoch = epoch
	e.updatedByReconfiguration = true
	return nil
}

func (e *EpochManagerFake) SetEpoch(epoch Epoch) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	// Used for reset or special cases. No comparison check.
	e.epoch = epoch
	return nil
}
