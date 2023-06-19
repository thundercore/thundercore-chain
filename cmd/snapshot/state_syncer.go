package main

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/trie"
)

type StateSyncer struct {
	pg            *PeerGroup
	stateDB       ethdb.Database
	taskCh        chan *types.Block
	stopped       chan bool
	ctx           context.Context
	trieBatchSize int
	bloom         *trie.SyncBloom
}

func NewStateSyncer(ctx context.Context, pg *PeerGroup, db ethdb.Database, trieBatchSize int) *StateSyncer {
	return &StateSyncer{
		pg:            pg,
		stateDB:       db,
		taskCh:        make(chan *types.Block, 1),
		stopped:       make(chan bool, 1),
		ctx:           ctx,
		trieBatchSize: trieBatchSize,
		bloom:         trie.NewSyncBloom(1, db),
	}
}

func (ss *StateSyncer) start() {

	for block := range ss.taskCh {
		bss := &BlockStateSyncer{
			pg:            ss.pg,
			sched:         state.NewStateSync(block.Root(), ss.stateDB, ss.bloom, nil),
			stateDB:       ss.stateDB,
			respCh:        make(chan StateSyncResult, 64),
			missingCh:     make(chan []common.Hash, 64),
			unCommitted:   0,
			ctx:           ss.ctx,
			trieBatchSize: ss.trieBatchSize,
		}

		bss.initWorker()

		errCh := bss.start()
		select {
		case err := <-errCh:
			if err != nil {
				panic(err)
			}
		case <-ss.ctx.Done():
			break
		}

		bss.wait()
	}

	ss.stopped <- true
}

func (ss *StateSyncer) wait() error {
	close(ss.taskCh)
	<-ss.stopped
	return ss.bloom.Close()
}

type BlockStateSyncer struct {
	pg            *PeerGroup
	stateDB       ethdb.Database
	trieBatchSize int

	sched       *trie.Sync
	respCh      chan StateSyncResult
	missingCh   chan []common.Hash
	unCommitted int

	ctx context.Context
	wg  sync.WaitGroup
}

type StateSyncResult struct {
	syncResults []trie.SyncResult
	missing     []common.Hash
	err         error
}

func (result *StateSyncResult) MissingString() string {
	strs := []string{}
	for _, m := range result.missing {
		strs = append(strs, m.String())
	}

	return strings.Join(strs, ",")
}

func (bss *BlockStateSyncer) GetMissingTrie(missing []common.Hash) {
	if resp, err := bss.pg.GetTrieState(missing); err == nil {
		bss.respCh <- StateSyncResult{
			syncResults: resp,
			missing:     missing,
			err:         nil,
		}
	} else {
		bss.respCh <- StateSyncResult{
			syncResults: []trie.SyncResult{},
			missing:     missing,
			err:         err,
		}
	}
}

func (bss *BlockStateSyncer) initWorker() {
	for i := 0; i < WORKERS; i++ {
		bss.wg.Add(1)

		go func(i int) {
			defer bss.wg.Done()
			for {
				select {
				case missing, ok := <-bss.missingCh:
					if !ok {
						return
					}
					bss.GetMissingTrie(missing)
				case <-bss.ctx.Done():
					fmt.Printf("Worker %d canceled\n", i)
					return
				}
			}
		}(i)
	}
}

func (bss *BlockStateSyncer) wait() {
	bss.wg.Wait()
	close(bss.respCh)
}

func (bss *BlockStateSyncer) start() chan error {
	errCh := make(chan error)
	bss.wg.Add(1)

	go func() {
		defer func() {
			if err := bss.commit(true); err != nil {
				panic(err)
			}
			bss.wg.Done()
		}()

		for bss.sched.Pending() > 0 {
			if err := bss.commit(false); err != nil {
				fmt.Printf("StateSyncer failed to commit state: %s\n", err.Error())
				errCh <- err
				return
			}

			select {
			case resp := <-bss.respCh:
				if err := bss.process(resp); err != nil {
					errCh <- err
					return
				}
			case <-bss.ctx.Done():
				fmt.Printf("state syncer was canceled\n")
				return
			default:
				// TODO(kevinfang): Missing returns paths and codes for snapsync
				nodes, _, codes := bss.sched.Missing(bss.trieBatchSize)
				missing := append(nodes, codes...)
				if len(missing) > 0 {
					bss.missingCh <- missing
				} else {
					// Wait one response to prevent busy loop.
					select {
					case resp := <-bss.respCh:
						if err := bss.process(resp); err != nil {
							errCh <- err
							return
						}
					case <-bss.ctx.Done():
						fmt.Printf("state syncer was canceled\n")
						return
					}
				}
			}
		}

		close(bss.missingCh)
		errCh <- nil
	}()

	return errCh
}

func (bss *BlockStateSyncer) process(resp StateSyncResult) error {
	if resp.err != nil {
		fmt.Printf("StateSyncer fetch failed: %s\n", resp.err.Error())
		bss.missingCh <- resp.missing
	} else {
		for _, result := range resp.syncResults {
			err := bss.sched.Process(result)
			if err != nil {
				fmt.Printf("StateSyncer failed to process result: %s", err.Error())
				return err
			} else {
				bss.unCommitted += len(resp.missing)
			}
		}
	}
	return nil
}

func (bss *BlockStateSyncer) commit(force bool) error {
	if !force && bss.unCommitted < ethdb.IdealBatchSize {
		return nil
	}

	batch := bss.stateDB.NewBatch()
	if err := bss.sched.Commit(batch); err != nil {
		return err
	} else {
		fmt.Printf("StateSyncer commit trie length: %d\n", bss.unCommitted)
	}
	if err := batch.Write(); err != nil {
		fmt.Printf("StateSyncer failed to process result: %s", err.Error())
		return err
	}

	bss.unCommitted = 0
	return nil
}
