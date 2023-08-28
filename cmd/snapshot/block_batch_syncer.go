package main

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"

	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
)

type OrderedStatusMap struct {
	mapping map[string]bool
	order   []string
	mu      sync.Mutex
}

func (o *OrderedStatusMap) BlockRangeToKey(blocks []*big.Int) string {
	return fmt.Sprintf("%s-%s", blocks[0].String(), blocks[len(blocks)-1].String())
}

func (o *OrderedStatusMap) KeyToBlockRange(key string) (*big.Int, *big.Int) {
	sp := strings.Split(key, "-")
	start, _ := new(big.Int).SetString(sp[0], 10)
	end, _ := new(big.Int).SetString(sp[1], 10)
	return start, end
}

func (o *OrderedStatusMap) Put(blocks []*big.Int, v bool) {
	o.mu.Lock()
	defer o.mu.Unlock()

	key := o.BlockRangeToKey(blocks)
	o.mapping[key] = v
	o.order = append(o.order, key)
}

func (o *OrderedStatusMap) Update(blocks []*big.Int, v bool) {
	o.mu.Lock()
	defer o.mu.Unlock()

	key := o.BlockRangeToKey(blocks)
	o.mapping[key] = v
}

func (o *OrderedStatusMap) Get(k string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()

	return o.mapping[k]
}

func (o *OrderedStatusMap) Pop() {
	o.mu.Lock()
	defer o.mu.Unlock()
	key, order := o.order[0], o.order[1:]
	o.order = order
	delete(o.mapping, key)
}

func (o *OrderedStatusMap) Order() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	copied := make([]string, len(o.order))
	copy(copied, o.order)
	return copied
}

func NewOrderedStatusMap() *OrderedStatusMap {
	return &OrderedStatusMap{
		mapping: map[string]bool{},
		order:   []string{},
	}
}

type BatchSyncer struct {
	db     ethdb.Database
	pg     *PeerGroup
	taskCh chan []*big.Int
	doneCh chan []*big.Int
	taskWg sync.WaitGroup
	doneWg sync.WaitGroup
	status *OrderedStatusMap
}

func NewBatchSyncer(db ethdb.Database, pg *PeerGroup) *BatchSyncer {
	return &BatchSyncer{
		taskCh: make(chan []*big.Int, 16),
		doneCh: make(chan []*big.Int, 16),
		db:     db,
		pg:     pg,
		status: NewOrderedStatusMap(),
	}
}

func (bs *BatchSyncer) start() {
	bs.doneWg.Add(1)
	go func() {
		defer bs.doneWg.Done()

		for finishedBlocks := range bs.doneCh {
			bs.status.Update(finishedBlocks, true)

			var lastProcessedBlock *big.Int
			order := bs.status.Order()
			for _, rangeKey := range order {
				if bs.status.Get(rangeKey) {
					_, lastProcessedBlock = bs.status.KeyToBlockRange(rangeKey)
					bs.status.Pop()
					// fmt.Printf("Update last processed block: %s\n", end.String())
				} else {
					// block in this range are not synced.
					break
				}
			}

			if lastProcessedBlock != nil {
				fmt.Printf("Update last processed block: %s\n", lastProcessedBlock.String())
				bs.db.Put(LAST_PROCESSED_KEY, lastProcessedBlock.Bytes())
			}
		}
	}()

	for i := 0; i < WORKERS; i++ {
		bs.taskWg.Add(1)

		go func(i int) {
			defer bs.taskWg.Done()
			for blocks := range bs.taskCh {
				if err := bs.process(blocks); err != nil {
					panic(fmt.Sprintf("failed to process block syncing: %s", err.Error()))
				}
				// fmt.Printf("write %v into doneCh", blocks)
				bs.doneCh <- blocks
			}
			fmt.Printf("goroutine %d stopped\n", i)
		}(i)
	}
}

func (bs *BatchSyncer) run(blocks []*big.Int) {
	bs.status.Put(blocks, false)
	bs.taskCh <- blocks
}

func (bs *BatchSyncer) wait() error {
	close(bs.taskCh)
	bs.taskWg.Wait()
	close(bs.doneCh)
	bs.doneWg.Wait()
	return nil
}

func (bs *BatchSyncer) batchTooLargeError(err error) bool {
	return strings.Contains(err.Error(), "EOF")
}

func (bs *BatchSyncer) binaryProcess(blockNums []*big.Int) error {
	mid := len(blockNums) / 2
	errs := []string{}

	leftErr := bs.process(blockNums[:mid])
	if leftErr != nil {
		errs = append(errs, leftErr.Error())
	}

	rightErr := bs.process(blockNums[mid:])
	if rightErr != nil {
		errs = append(errs, rightErr.Error())
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "\n"))
	}

	return nil
}

func (bs *BatchSyncer) process(blockNums []*big.Int) error {
	if len(blockNums) == 0 {
		return nil
	}
	start := blockNums[0].String()
	end := blockNums[len(blockNums)-1].String()

	fmt.Printf("BatchSyncer process block %s -> %s\n", start, end)

	fullBlocks, err := bs.pg.BatchGetTtBlocks(blockNums)
	if err != nil {
		if bs.batchTooLargeError(err) {
			if len(blockNums) == 1 {
				return err
			}
			return bs.binaryProcess(blockNums)
		}
		return err
	}

	for _, ttBlock := range fullBlocks {
		if err := bs.write(ttBlock); err != nil {
			return err
		}
	}

	fmt.Printf("BatchSyncer process block %s -> %s done\n", start, end)
	return nil
}

func (bs *BatchSyncer) write(ttBlock *blockchain.TtBlockForSnapshot) error {
	batch := bs.db.NewBatch()
	// Block body (transactions and uncles)
	block := types.NewBlockWithHeader(ttBlock.Header).WithBody(ttBlock.BlockBody.Transactions, ttBlock.BlockBody.Uncles)
	rawdb.WriteBlock(batch, block)
	rawdb.WriteTxLookupEntriesByBlock(batch, block)

	// Receipt
	rawdb.WriteReceipts(batch, block.Hash(), block.NumberU64(), ttBlock.Receipts)
	// Difficulty
	td, success := new(big.Int).SetString(ttBlock.Td, 10)
	if !success {
		return fmt.Errorf("failed to set string")
	}
	rawdb.WriteTd(batch, block.Hash(), block.NumberU64(), td)
	// Hash
	rawdb.WriteCanonicalHash(batch, ttBlock.CanonicalHash, block.NumberU64())

	// Sync Pala block meta
	if ttBlock.IsPala {
		meta := ttBlock.PalaMeta
		if err := blockchain.WriteSnapshotBlock(batch, meta.BlockSn, meta.RawBlockMeta, meta.RawNotarization, meta.SessionStopBlock); err != nil {
			return err
		}
	}

	if err := batch.Write(); err != nil {
		return err
	}

	return nil
}
