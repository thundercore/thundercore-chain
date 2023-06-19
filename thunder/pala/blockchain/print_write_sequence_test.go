package blockchain

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/consensus/thunder"

	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/stretchr/testify/require"
)

func NewThunderWithLoggingDb(t *testing.T, engine consensus.Engine) (ethdb.Database, *core.BlockChain, error) {
	gspec := core.DefaultThunderGenesisBlock()
	db := rawdb.NewMemoryDatabase()
	loggingDb := &LoggingDatabase{
		t:        t,
		Database: db,
	}
	gspec.MustCommit(db)
	config := params.ThunderChainConfig()
	config.Thunder = newThunderConfig()
	blockchain, err := core.NewBlockChain(loggingDb, nil, config, engine, vm.Config{}, nil, nil)

	if err != nil {
		t.FailNow()
	}

	return loggingDb, blockchain, nil
}

func TestBlockChain_PrintDatabaseWriteMethod(t *testing.T) {
	// there's 3 main write logic blockchain.insertBlock, storage.Writeblockwithstate, blockchain.Addnotarization.
	req := require.New(t)
	k := uint32(1)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	chainDb, chain, err := NewThunderWithLoggingDb(t, thunder.New(newThunderConfig()))
	req.NoError(err)

	bc, err := NewBlockChainWithFakeNota(hardforkK, chainDb, chain, nil, nil, 100*time.Millisecond)
	req.NoError(err)

	// block
	makeBlock := func(parent, sn BlockSn) Block {
		makeSlice := func(sn BlockSn) []BlockSn {
			r := make([]BlockSn, 0)
			r = append(r, sn)
			return r
		}
		blocks := GeneratePalaChain(chain, bc.GetBlock(parent).(*blockImpl).B, chain.Engine(), chainDb, 1, BlockGenWithConsensusTransaction(chain, makeSlice(sn), hardforkK, nil, true, []ConsensusId{}))
		return blocks[0]
	}

	block := makeBlock(GetGenesisBlockSn(), NewBlockSn(1, 1, 1))

	t.Logf("InsertBlock()...")
	err = bc.InsertBlock(block, false)
	t.Logf("InsertBlock()...END")

	req.NoError(err)

	t.Logf("AddNotarization()...")
	err = bc.AddNotarization(NewNotarizationFake(NewBlockSn(1, 1, 1), []ConsensusId{}))
	t.Logf("AddNotarization()...END")
	req.NoError(err)

	// this is more tricky
	block = makeBlock(NewBlockSn(1, 1, 1), NewBlockSn(1, 1, 2))
	blocks, receipts := core.GenerateThunderChain(chain, bc.GetBlock(NewBlockSn(1, 1, 1)).(*blockImpl).B, chain.Engine(), chainDb, 1, BlockGenWithConsensusTransaction(chain, []BlockSn{NewBlockSn(1, 1, 2)}, hardforkK, nil, true, []ConsensusId{}))
	statedb, err := chain.StateAt(block.(*blockImpl).B.Root())
	req.NoError(err)
	t.Logf("writeBlockWithState()...")
	logs := []*types.Log{}
	for _, receipt := range receipts[0] {
		logs = append(logs, receipt.Logs...)
	}
	bc.(*BlockChainImpl).storage.(*StorageImpl).writeBlockWithState(newBlock(blocks[0], chain.Config().Thunder), receipts[0], logs, statedb)
	t.Logf("writeBlockWithState()...END")

	t.Logf("AddNotarization()...")
	err = bc.AddNotarization(NewNotarizationFake(NewBlockSn(1, 1, 2), []ConsensusId{}))
	t.Logf("AddNotarization()...END")
	req.NoError(err)
}
