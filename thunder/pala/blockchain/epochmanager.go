package blockchain

import (
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	utils "github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"

	"github.com/ethereum/go-ethereum/ethdb"
)

type epochStatus struct {
	epoch     Epoch
	clockNota ClockMsgNota
}

type EpochManagerImpl struct {
	mu         utils.CheckedLock
	db         ethdb.Database
	marshaller DataUnmarshaller
	cached     *epochStatus
}

func NewEpochManager(db ethdb.Database, marshaller DataUnmarshaller) *EpochManagerImpl {
	return &EpochManagerImpl{
		db:         db,
		marshaller: marshaller,
		cached:     updateEpochStatusIfNotExisted(db, marshaller),
	}
}

func updateEpochStatusIfNotExisted(db ethdb.Database, marshaller DataUnmarshaller) *epochStatus {
	if es := readEpochStatus(db, marshaller); es != nil {
		return es
	}
	es := &epochStatus{epoch: Epoch{1, 1}}
	if err := writeEpochStatus(db, es); err != nil {
		return nil
	}
	return es
}

func (em *EpochManagerImpl) GetEpoch() Epoch {
	em.mu.Lock()
	defer em.mu.Unlock()

	return em.cached.epoch
}

func (em *EpochManagerImpl) UpdateByReconfiguration(s Session) error {
	em.mu.Lock()
	defer em.mu.Unlock()

	if em.cached != nil && em.cached.epoch.Session > s {
		debug.Bug("Update session backward %d->%d is forbidden.", em.cached.epoch.Session, s)
	}

	es := &epochStatus{
		epoch:     NewEpoch(uint32(s), 1),
		clockNota: nil,
	}
	logger.Info("Epoch progress from %s to %s", em.cached.epoch, es.epoch)

	if err := writeEpochStatus(em.db, es); err != nil {
		return err
	}

	em.cached = es
	return nil
}

func (em *EpochManagerImpl) UpdateByClockMsgNota(cn ClockMsgNota) error {
	em.mu.Lock()
	defer em.mu.Unlock()

	if em.cached != nil && em.cached.epoch.Compare(cn.GetEpoch()) > 0 {
		debug.Bug("Update epoch backward %s->%s is forbidden.", em.cached.epoch, cn.GetEpoch())
	}
	if cnImpl, ok := cn.(*clockMsgNotaImpl); ok {
		status := cnImpl.getStatus()
		if status != valid {
			debug.Bug("clockMsgNota (%s) is not valid (%d)", cn.GetBlockSn(), status)
		}
	}

	logger.Note("Epoch progress from %s to %s", em.cached.epoch, cn.GetEpoch())

	es := &epochStatus{
		epoch:     cn.GetEpoch(),
		clockNota: cn,
	}

	batch := em.db.NewBatch()

	if err := writeEpochStatus(batch, es); err != nil {
		return err
	}

	if err := writeClockMsgNotarization(batch, cn); err != nil {
		return err
	}

	if err := batch.Write(); err != nil {
		return err
	}

	em.cached = es

	return nil
}

// TODO(frog): this may not get the last ClockMsgNota.
func (em *EpochManagerImpl) GetLatestClockMsgNota(session Session) ClockMsgNota {
	em.mu.Lock()
	defer em.mu.Unlock()

	// case 0: hit cache
	if session == em.cached.epoch.Session {
		return em.cached.clockNota
	}

	// case 1: stop block exists, linear search to get last session.
	header, sn := readSessionStopHeader(em.db, session)
	if header == nil {
		logger.Error("NoStopBlock session %d", session)
		return nil
	}

	epoch := sn.Epoch
	for num := header.Number.Uint64() + 1; ; num++ {
		h := rawdb.ReadCanonicalHash(em.db, num)
		if h == (common.Hash{}) {
			break
		}

		header := rawdb.ReadHeader(em.db, h, num)
		if header == nil {
			debug.Bug("missing header (%q %d)", h, num)
		}

		_, sn, err := decodeBlockSnFromNumber(header.Difficulty)
		if err != nil {
			debug.Bug("Cannot decode block sn from block header of (%q %d)", h, num)
		}

		if sn.Epoch.Session > session {
			break
		}

		epoch = sn.Epoch
	}

	return readClockMsgNotarization(em.db, em.marshaller, epoch)
}
