package blockchain

import (
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
)

type BlockMakerFake struct {
	k                  *config.Int64HardforkConfig
	timePerBlock       time.Duration
	isAllowBadBehavior bool
}

func NewBlockMakerFake(k *config.Int64HardforkConfig, delay time.Duration) *BlockMakerFake {
	return &BlockMakerFake{
		k:            k,
		timePerBlock: delay,
	}
}

// Simulate the real implementation which creates a new block in a worker goroutine.
func (bm *BlockMakerFake) KeepCreatingNewBlocks(
	bc *BlockChainImpl,
	parent Block,
	epoch Epoch,
	cNota ClockMsgNota,
	outputChan chan BlockMadeEvent,
	stopChan chan struct{},
	notaChan chan Notarization,
	stopEvent chan struct{}) {
	// Doubly-pipelined Pala always begin with (epoch, 1).
	s := BlockSn{epoch, 1}
	k := uint32(bm.k.GetValueAtSession(int64(s.Epoch.Session)))
	running := true
	defer close(stopEvent)
	var lastBlockCreatedTime time.Time
	for running {
		var notas []Notarization
		canCreate := false
		// If this is the first block of the epoch, wait for until parent block from previous
		// epoch is fully notarized before creating new blocks.
		if s.S == 1 && parent.GetBlockSn().IsPala() {
			notas = bc.GetNotarizations(parent, int(k))
			canCreate = notas != nil
			if !canCreate {
				logger.Error("parent block from previous epoch is not fully notarized (parent=%s)",
					parent.GetBlockSn())
			}
		} else if s.S <= k {
			// Allow up to k unnotarized blocks.
			canCreate = true
		} else {
			// Allow up to k unnotarized blocks.
			ns := BlockSn{epoch, s.S - k}
			n := bc.GetNotarization(ns)
			if n != nil {
				notas = append(notas, n)
				canCreate = true
			}
		}

		if canCreate {
			nb := NewBlockFake(s, parent.GetBlockSn(), parent.GetNumber()+1, notas, cNota, s.String())
			cNota = nil

			// Insert the new block before sending it to the channel.
			// We always adds the block before adding the block's notarization.
			if err := bc.InsertBlock(nb, false); err != nil {
				if !bm.isAllowBadBehavior {
					debug.Bug("KeepCreatingNewBlocks fails to insert the created block; err=%s", err)
				}

				// This can happen in byzantine/faulty proposer test case.
				// If an honestly proposed block is already inserted, we will hit this part of the code and the faulty
				// proposer will not propose blocks for the rest of this epoch because we do not advance s.S.
				// Note if a byzantine/faulty proposer succesfully inserts a faulty block into their own chain, then
				// the node will never receive new blocks that extend from the honest block as the current
				// blockchain implementation does not support having two blocks with the same BlockSn.
				// TODO(thunder) come up with better behavior here. Desired behavior may depend on the test case.
				logger.Warn("startWorker fails to insert the created block; err=%s", err)
				running = false
				continue
			} else {
				parent = nb
				s.S++

				if bm.timePerBlock > 0 {
					// Simulate the block time.
					diff := time.Now().Sub(lastBlockCreatedTime)
					if diff < bm.timePerBlock {
						diff = bm.timePerBlock - diff
						time.Sleep(diff)
					}
				}

				outputChan <- BlockMadeEvent{nb}
				lastBlockCreatedTime = time.Now()
				continue
			}
		}

		select {
		case <-stopChan:
			running = false
		case <-notaChan:
		}
	}
}

func (bm *BlockMakerFake) AllowBadBehavior() {
	bm.isAllowBadBehavior = true
}
