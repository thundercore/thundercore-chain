package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"os/signal"
	"path"
	"sync"
	"syscall"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"

	"gopkg.in/yaml.v2"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/ethereum/go-ethereum/core/rawdb"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	flag "github.com/spf13/pflag"
)

var (
	RETRY_MAX          = 5
	MAX_CONNECTION     = 256
	WORKERS            = 8
	SNAPSHOT_CONFIG    = "snapshot.yaml"
	LAST_PROCESSED_KEY = []byte("snapshot_last_processed")

	BIG_ZERO = new(big.Int).SetInt64(0)
	BIG_ONE  = new(big.Int).SetInt64(1)
)

type SyncPeer interface {
	Id() string
	Close()
	Available() bool
	Disable()
	Enable()

	GetPalaMeta() (map[string][]byte, error)
	GetBlockByNumber(*big.Int) (*types.Block, error)
	GetTtBlock(*big.Int) (*blockchain.TtBlockForSnapshot, error)
	GetTrieState(keys []common.Hash) ([]trie.SyncResult, error)
	BatchGetTtBlocks([]*big.Int) ([]*blockchain.TtBlockForSnapshot, error)
}

func NewSnapshotTaker(configPath string, sig chan os.Signal) (*SnapshotTaker, error) {
	config, err := loadConfig(configPath)
	if err != nil {
		return nil, err
	}

	// Open database for snapshot
	// TODO(kevinfang): LDBDatabase was removed in ethdb/databa
	db, err := rawdb.NewLevelDBDatabase(config.Datadir, 0, 0, "", false)
	if err != nil {
		return nil, err
	}

	// Create sync nodes
	pg, err := NewSyncGroupByConfig(config)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &SnapshotTaker{
		pg:     pg,
		db:     db,
		sig:    sig,
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}
	go s.handleSignal()

	return s, nil
}

type SnapshotTaker struct {
	pg     *PeerGroup
	db     ethdb.Database
	sig    chan os.Signal
	config *SnapshotConfig

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func (s *SnapshotTaker) handleSignal() {
	for sig := range s.sig {
		fmt.Printf("catch signal: %s, pid %d\n", sig.String(), os.Getpid())

		switch sig {
		case os.Interrupt:
			s.handleExit()
			os.Exit(1)
		case (syscall.SIGTERM | syscall.SIGINT):
			s.handleExit()
			os.Exit(1)
		case syscall.SIGHUP:
			if err := s.handleReload(); err != nil {
				fmt.Printf("failed to handle hub signal: %v\n", err.Error())
			}
		}
	}
}

func (s *SnapshotTaker) reloadConfig() error {
	config, err := loadConfig(s.config.configPath)
	if err != nil {
		return err
	}

	s.config = config
	return nil
}

func (s *SnapshotTaker) handleReload() error {
	err := s.reloadConfig()
	if err != nil {
		return err
	}

	if err := s.pg.reloadConfig(s.config); err != nil {
		return err
	}

	return nil
}

func (s *SnapshotTaker) handleExit() {
	fmt.Printf("Stopping the program...")
	s.cancel()
	s.wg.Wait()
	s.close()
}

func (s *SnapshotTaker) close() {
	s.db.Close()
	s.pg.Close()
}

func (s *SnapshotTaker) run() error {
	head, err := s.syncChainMeta()
	if err != nil {
		return err
	}

	s.wg.Add(1)
	go s.processBlock(head)
	s.wg.Add(1)
	go s.processState(head)

	s.wg.Wait()
	fmt.Println("Done.")

	return nil
}

// Synchronize chain mata from slowest peer and return its head block.
func (s *SnapshotTaker) syncChainMeta() (*types.Block, error) {
	var (
		head *types.Block
		err  error
	)

	slowestPeer, err := s.pg.GetSlowestPeer()
	if err != nil {
		return head, err
	}

	palaMeta, err := slowestPeer.GetPalaMeta()
	if err != nil {
		return head, err
	}
	height, err := blockchain.WritePalaMeta(s.db, palaMeta)
	if err != nil {
		return head, err
	}

	head, err = slowestPeer.GetBlockByNumber(new(big.Int).SetUint64(height))
	if err != nil {
		return head, err
	}

	rawdb.WriteHeadBlockHash(s.db, head.Hash())
	ttBlock, err := s.pg.GetTtBlock(head.Number())
	if err != nil {
		return head, err
	}

	rawdb.WriteHeadHeaderHash(s.db, ttBlock.Header.Hash())
	return head, err
}

func (s *SnapshotTaker) processState(head *types.Block) {
	defer s.wg.Done()

	stateSyncer := NewStateSyncer(s.ctx, s.pg, s.db, s.config.TrieBatchSize)
	go stateSyncer.start()

	fmt.Printf("Process genesis block state\n")
	genesis, err := s.pg.GetBlockByNumber(BIG_ZERO)
	if err != nil {
		panic(err)
	}
	stateSyncer.taskCh <- genesis

	offset := new(big.Int).SetUint64(s.config.Offset)
	blockNum := new(big.Int).Sub(head.Number(), offset)
	canceled := false

LOOP:
	for ; blockNum.Cmp(head.Number()) <= 0; blockNum = new(big.Int).Add(blockNum, BIG_ONE) {
		fmt.Printf("Process block %s state\n", blockNum.String())
		block, err := s.pg.GetBlockByNumber(blockNum)
		if err != nil {
			panic(err)
		}
		select {
		case stateSyncer.taskCh <- block:
		case <-s.ctx.Done():
			canceled = true
			fmt.Printf("Stopping StateSyncer...\n")
			break LOOP
		}
	}

	if err := stateSyncer.wait(); err != nil {
		panic(err)
	}
	if canceled {
		fmt.Printf("Stopping StateSyncer... done\n")
	}

	fmt.Println("Finish state syncing")
}

func (s *SnapshotTaker) processBlock(head *types.Block) {
	defer s.wg.Done()

	startBlock := s.restoreProgressOrZero()
	fmt.Printf("BatchSyncer start block: %s\n", startBlock.String())
	batchSyncer := NewBatchSyncer(s.db, s.pg)
	go batchSyncer.start()

	canceled := false
	blockNums := []*big.Int{}
LOOP:
	for blockNum := startBlock; blockNum.Cmp(head.Number()) <= 0; blockNum = new(big.Int).Add(blockNum, BIG_ONE) {
		blockNums = append(blockNums, blockNum)
		if len(blockNums) >= s.config.BlockBatchSize {
			batchSyncer.run(blockNums)
			blockNums = nil
		}

		select {
		case <-s.ctx.Done():
			fmt.Printf("Stopping BlockSyncer...\n")
			canceled = true
			break LOOP
		default:
		}
	}

	if !canceled && len(blockNums) > 0 {
		batchSyncer.run(blockNums)
	}

	if err := batchSyncer.wait(); err != nil {
		panic(err)
	}

	fmt.Println("Finish block processing")
}

func (s *SnapshotTaker) restoreProgressOrZero() *big.Int {
	value, err := s.db.Get(LAST_PROCESSED_KEY)
	if err != nil {
		return BIG_ZERO
	}
	lastProcessed := new(big.Int).SetBytes(value)
	return new(big.Int).Add(lastProcessed, BIG_ONE)
}

func Exit(err error) {
	if err != nil {
		fmt.Printf("error: %s\n", err.Error())
		os.Exit(1)
	}

	os.Exit(0)
}

type SnapshotConfig struct {
	RpcUrls        []string `yaml:"RpcUrls"`
	Datadir        string   `yaml:"Datadir"`
	Concurrency    int      `yaml:"Concurrency"`
	Offset         uint64   `yaml:"Offset"`
	BlockBatchSize int      `yaml:"BlockBatchSize"`
	TrieBatchSize  int      `yaml:"TrieBatchSize"`
	configPath     string
}

func loadConfig(configPath string) (*SnapshotConfig, error) {
	var config SnapshotConfig

	configFile := path.Join(configPath, SNAPSHOT_CONFIG)
	f, err := ioutil.ReadFile(configFile)
	if err != nil {
		return &config, err
	}

	err = yaml.Unmarshal(f, &config)
	if err != nil {
		return nil, err
	}

	config.configPath = configPath
	if config.Concurrency == 0 {
		config.Concurrency = 3
	}
	if config.BlockBatchSize == 0 {
		config.BlockBatchSize = 256
	}
	if config.TrieBatchSize == 0 {
		config.TrieBatchSize = 4096
	}
	if config.Offset == 0 {
		config.Offset = 10800
	}
	return &config, nil
}

func main() {
	configPath := flag.String("configPath", "config/pala/", "config path.")
	flag.Parse()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, os.Interrupt)

	snapshotTaker, err := NewSnapshotTaker(*configPath, sig)
	if err != nil {
		Exit(err)
	}
	defer snapshotTaker.close()

	if err := snapshotTaker.run(); err != nil {
		Exit(err)
	}
}
