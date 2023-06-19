package blockchain

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/consensus/thunder"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/stretchr/testify/require"
)

var (
	loadCrashSeed = flag.Bool("ttcrashseed", false, "Set true if you need to reproduce the latest test result")
)

type LoggingDatabase struct {
	t *testing.T
	ethdb.Database
}

func (ld *LoggingDatabase) Put(key []byte, value []byte) error {
	ld.t.Logf("Put(% x)", key)
	return ld.Database.Put(key, value)
}

func (ld *LoggingDatabase) Delete(key []byte) error {
	ld.t.Logf("Delete(% x)", string(key))
	return ld.Database.Delete(key)
}

func (ld *LoggingDatabase) NewBatch() ethdb.Batch {
	return &LoggingBatch{
		t:     ld.t,
		batch: ld.Database.NewBatch(),
	}
}

type LoggingBatch struct {
	t      *testing.T
	aggLog string
	batch  ethdb.Batch
}

func (lb *LoggingBatch) Put(key []byte, value []byte) error {
	lb.aggLog += fmt.Sprintf("Put(%s)\n", hex.EncodeToString(key))
	return lb.batch.Put(key, value)
}

func (lb *LoggingBatch) Delete(key []byte) error {
	lb.aggLog += fmt.Sprintf("Delete(%s)\n", string(key))
	return lb.batch.Delete(key)
}

func (lb *LoggingBatch) ValueSize() int { // amount of data in the batch
	return lb.batch.ValueSize()
}

func (lb *LoggingBatch) Write() error {
	lb.t.Logf("Commit{\n%s}\n", lb.aggLog)
	return lb.batch.Write()
}

func (lb *LoggingBatch) Reset() {
	lb.aggLog = ""
	lb.batch.Reset()
}

func (lb *LoggingBatch) Replay(w ethdb.KeyValueWriter) error {
	return nil
}

type CrashingDatabase struct {
	random *rand.Rand
	ethdb.Database
}

func NewCrashingDatabase(db ethdb.Database, seed int64) *CrashingDatabase {
	return &CrashingDatabase{
		random:   rand.New(rand.NewSource(seed)),
		Database: db,
	}
}

func (cd *CrashingDatabase) Put(key []byte, value []byte) error {
	if cd.random.Int31n(20) == 1 {
		debug.Bug("Crash before Write into database")
	}
	err := cd.Database.Put(key, value)
	if cd.random.Int31n(20) == 1 {
		debug.Bug("Crash before Write into database")
	}
	return err
}

func (cd *CrashingDatabase) NewBatch() ethdb.Batch {
	return &CrashingBatch{
		random: cd.random,
		batch:  cd.Database.NewBatch(),
	}
}

type CrashingBatch struct {
	random *rand.Rand
	batch  ethdb.Batch
}

func (cb *CrashingBatch) Put(key []byte, value []byte) error {
	return cb.batch.Put(key, value)
}

func (cb *CrashingBatch) Delete(key []byte) error {
	return cb.batch.Delete(key)
}

func (cb *CrashingBatch) ValueSize() int { // amount of data in the batch
	return cb.batch.ValueSize()
}

func (cb *CrashingBatch) Write() error {
	if cb.random.Int31n(100) == 1 {
		debug.Bug("Crash before Write into database")
	}
	err := cb.batch.Write()
	if cb.random.Int31n(100) == 1 {
		debug.Bug("Crash after Write into database")
	}
	return err
}

func (cb *CrashingBatch) Reset() {
	cb.batch.Reset()
}

func (cb *CrashingBatch) Replay(w ethdb.KeyValueWriter) error {
	return nil
}

func NewCrashingMemoryDb(t *testing.T, db ethdb.Database) ethdb.Database {
	req := require.New(t)
	seedpath := filepath.Join("testdata", t.Name()+".seed")
	var seed int64
	if *loadCrashSeed {
		data, err := ioutil.ReadFile(seedpath)
		req.NoError(err, "fail to read seed file")
		r, _, err := utils.BytesToUint64(data)
		req.NoError(err)
		seed = int64(r)
	} else {
		seed = time.Now().UnixNano()
	}

	err := ioutil.WriteFile(seedpath, []byte(utils.Uint64ToBytes(uint64(seed))), 0644)
	req.NoError(err, "fail to write seed file")

	crashingDb := NewCrashingDatabase(db, seed)
	return crashingDb
}

func NewThunderWithExistingDb(t *testing.T, db ethdb.Database) *core.BlockChain {
	req := require.New(t)

	config := params.ThunderChainConfig()
	config.Thunder = newThunderConfig()
	engine := thunder.New(newThunderConfig())
	cacheConfig := &core.CacheConfig{
		TrieDirtyDisabled: true,
	}
	blockchain, err := core.NewBlockChain(db, cacheConfig, config, engine, vm.Config{}, nil, nil)
	req.NoError(err)

	return blockchain
}
