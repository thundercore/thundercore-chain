package blockchain

import (
	"bytes"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chain"
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chainconfig"
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/consensus/thunder"
	"github.com/ethereum/go-ethereum/thunder/thunderella/testutils"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
)

func TestGetGenesisBlock(t *testing.T) {
	req := require.New(t)

	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(1, 0)

	storage := NewPalaStorageWithMemoryDB(hardforkK)

	block := storage.GetGenesisBlock()

	sn := block.GetBlockSn()

	req.True(sn.IsGenesis())
}

func TestNewStorage(t *testing.T) {
	type args struct {
		db ethdb.Database
		bc *core.BlockChain
	}

	memdb, chain, err := NewThunderSinceGenesisWithMemDb()
	if err != nil {
		t.Log("Fail to init env")
		t.FailNow()
	}

	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
		{
			name: "fake",
			args: args{
				db: memdb,
				bc: chain,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
			hardforkK.SetTestValueAtSession(int64(k), 0)

			got := NewStorage(StorageConfig{
				Db:                tt.args.db,
				Bc:                tt.args.bc,
				Marshaller:        &DataUnmarshallerFake{},
				PalaFromGenesis:   true,
				Info:              &testutils.TestingCommInfo,
				UnnotarizedWindow: hardforkK,
			})
			if got != nil {
				var s Storage = got
				b := s.GetGenesisBlock()
				t.Log(b.GetDebugString())
			} else {
				t.Errorf("NewStorage() returns nil")
				t.FailNow()
			}
		})
	}
}

func TestStorageImpl_GetBlock(t *testing.T) {
	cfg := config.HardforkMapBackuper{}
	cfg.Backup()
	defer cfg.Restore()

	req := require.New(t)

	thunderConfig := newThunderConfig()
	thunderEngine := thunder.New(thunderConfig)
	thunderEngine.SetEngineClient(&thunder.FakeEngineClient{})
	memdb, chain, err := core.NewThunderCanonical(thunderEngine, 0, true)
	req.NoError(err)

	chain.Config().Thunder = thunderConfig
	chain.Config().Thunder.VerifyBidSession = uint32(1)
	chain.Config().Thunder.IsInConsensusTx = func(evm params.Evm) bool { return true }
	chain.Config().Thunder.BidVerificationEnabled = func() bool { return true }
	chain.Config().Thunder.GetSessionFromDifficulty = func(df, bn *big.Int, cfg *params.ThunderConfig) uint32 { return uint32(1) }
	chain.Config().Thunder.PalaBlock = new(big.Int).SetInt64(5)

	blocks, _ := core.GenerateChain(chain.Config(), chain.Genesis(), chain.Engine(), memdb, 5, nil)

	req.Equal(5, len(blocks))
	l, err := chain.InsertChain(blocks)
	req.Equal(5, l)
	req.NoError(err)

	for _, block := range blocks {
		req.NoError(chain.WriteKnownBlock(block))
	}

	type fields struct {
		db         ethdb.Database
		bc         *core.BlockChain
		marshaller DataUnmarshaller
	}

	f := fields{
		db:         memdb,
		bc:         chain,
		marshaller: &DataUnmarshallerFake{},
	}

	tests := []struct {
		name   string
		fields fields
		sn     BlockSn
		want   Block
	}{
		{
			name:   "getBlock 0",
			fields: f,
			sn:     GetGenesisBlockSn(),
			want:   newBlock(chain.Genesis(), chain.Config().Thunder),
		},
		{
			name:   "getBlock 1",
			fields: f,
			sn: BlockSn{
				Epoch: Epoch{
					Session: 0,
					E:       1,
				},
				S: 1,
			},
			want: newBlock(blocks[0], chain.Config().Thunder),
		},
		{
			name:   "getBlock 2",
			fields: f,
			sn: BlockSn{
				Epoch: Epoch{
					Session: 0,
					E:       1,
				},
				S: 2,
			},
			want: newBlock(blocks[1], chain.Config().Thunder),
		},
		{
			name:   "getBlock 3",
			fields: f,
			sn: BlockSn{
				Epoch: Epoch{
					Session: 0,
					E:       1,
				},
				S: 3,
			},
			want: newBlock(blocks[2], chain.Config().Thunder),
		},
		{
			name:   "getBlock 4",
			fields: f,
			sn: BlockSn{
				Epoch: Epoch{
					Session: 0,
					E:       1,
				},
				S: 4,
			},
			want: newBlock(blocks[3], chain.Config().Thunder),
		},
		{
			name:   "getBlock 5 (should fail due to hardfork config)",
			fields: f,
			sn: BlockSn{
				Epoch: Epoch{
					Session: 0,
					E:       1,
				},
				S: 5,
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &StorageImpl{
				db:         tt.fields.db,
				bc:         tt.fields.bc,
				marshaller: tt.fields.marshaller,
			}
			req := require.New(t)
			got := s.GetBlock(tt.sn)
			if tt.want != nil {
				req.NotNil(got)
				req.True(bytes.Equal(got.GetBody(), tt.want.GetBody()))

				block := got.(*blockImpl).B

				wantHeader := newHeader(block.Header(), chain.Config().Thunder)
				gotHeader := s.GetHeaderByNumber(got.GetNumber())
				req.True(bytes.Equal(gotHeader.GetBody(), wantHeader.GetBody()))

				wantBlockBody := block.Body()
				data, err := rlp.EncodeToBytes(wantBlockBody)
				req.NoError(err)
				gotRawBlockBody := s.GetRawBlockBody(got.GetHash())
				req.True(bytes.Equal(data, gotRawBlockBody))

			} else {
				req.Nil(got)

				gotHeader := s.GetHeaderByNumber(10000000)
				gotRawBlockBody := s.GetRawBlockBody(Hash{})
				req.Nil(gotHeader)
				req.Nil(gotRawBlockBody)
			}
		})
	}

	expectedSn := BlockSn{
		Epoch: Epoch{
			Session: 0,
			E:       1,
		},
		S: 4,
	}
	Upgrade(memdb, chain)

	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(1), 0)

	s := NewStorage(StorageConfig{
		Db:                memdb,
		Bc:                chain,
		Marshaller:        &DataUnmarshallerFake{},
		PalaFromGenesis:   true,
		Info:              &testutils.TestingCommInfo,
		UnnotarizedWindow: hardforkK,
	})
	req.Equal(expectedSn, s.GetFinalizedHeadSn())
	req.Equal(expectedSn, s.GetFreshestNotarizedHeadSn())
}

func TestStorageImpl_GetBlockFromHistoryDB(t *testing.T) {
	req := require.New(t)
	chainDb, chain, err := NewThunderSinceGenesisWithMemDb()
	req.NoError(err)
	blockSns := []BlockSn{
		NewBlockSn(1, 1, 1),
		NewBlockSn(1, 1, 2),
		NewBlockSn(1, 1, 3),
		NewBlockSn(1, 1, 4),
		NewBlockSn(1, 2, 1),
		NewBlockSn(1, 2, 2),
		NewBlockSn(1, 2, 3),
		NewBlockSn(1, 3, 1),
		NewBlockSn(1, 3, 2),
		NewBlockSn(1, 3, 3),
	}

	K := uint32(1)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(K), 0)

	bc, err := NewBlockChainWithFakeNota(hardforkK, chainDb, chain, nil, nil, 100*time.Millisecond)
	req.NoError(err)

	blocks := GeneratePalaChain(chain, chain.Genesis(), chain.Engine(), chainDb, len(blockSns), BlockGenWithConsensusTransaction(chain, blockSns, hardforkK, WithSimpleTransactionAndRandomBidForTest(100, chain), false, []ConsensusId{}))
	req.Equal(len(blockSns), len(blocks))

	for i, blk := range blocks {
		err := bc.InsertBlock(blk, false)
		req.NoError(err, "failed to the %d-th block", i)
	}
	req.Equal(NewBlockSn(1, 3, 3-K), bc.GetFreshestNotarizedHead().GetBlockSn())

	memDB := chainDb.(ethdb.KeyValueStore)
	// take the memory db as history store and create empty memory db as main database
	historyDB := rawdb.NewHistoryDatabaseWithDBListInstance(memorydb.New(), []ethdb.KeyValueStore{memDB})
	bcFromHistoryDB, err := NewBlockChainWithFakeNota(hardforkK, historyDB, chain, nil, nil, 100*time.Millisecond)
	// make sure we can retrieve data from history db
	req.Equal(NewBlockSn(1, 3, 3-K), bcFromHistoryDB.GetFreshestNotarizedHead().GetBlockSn())
}

func TestStorageImpl_InsertBlock(t *testing.T) {
	t.Parallel()
	req := require.New(t)
	chainDb, chain, err := NewThunderSinceGenesisWithMemDb()
	req.NoError(err)
	blockSns := []BlockSn{
		NewBlockSn(1, 1, 1),
		NewBlockSn(1, 1, 2),
		NewBlockSn(1, 1, 3),
		NewBlockSn(1, 1, 4),
		NewBlockSn(1, 2, 1),
		NewBlockSn(1, 2, 2),
		NewBlockSn(1, 2, 3),
		NewBlockSn(1, 3, 1),
		NewBlockSn(1, 3, 2),
		NewBlockSn(1, 3, 3),
	}

	K := uint32(2)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(K), 0)

	bc, err := NewBlockChainWithFakeNota(hardforkK, chainDb, chain, nil, nil, 100*time.Millisecond)
	req.NoError(err)

	blocks := GeneratePalaChain(chain, chain.Genesis(), chain.Engine(), chainDb, len(blockSns), BlockGenWithConsensusTransaction(chain, blockSns, hardforkK, WithSimpleTransactionAndRandomBidForTest(100, chain), false, []ConsensusId{}))
	req.Equal(len(blockSns), len(blocks))

	for i, blk := range blocks {
		err := bc.InsertBlock(blk, false)
		req.NoError(err, "failed to the %d-th block", i)
	}

}

func TestStorageImpl_Canonical(t *testing.T) {
	cfg := config.HardforkMapBackuper{}
	cfg.Backup()
	defer cfg.Restore()

	req := require.New(t)
	n := uint32(15)
	k := uint32(3)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	var currentBlock Block

	chainDb, chain, err := NewThunderSinceGenesisWithMemDb()
	req.NoError(err)

	blockSns := make([]BlockSn, 0, n)

	for i := uint32(1); i <= n; i++ {
		sn := NewBlockSn(1, 1, i)
		blockSns = append(blockSns, sn)
	}

	bc, err := NewBlockChainWithFakeNota(hardforkK, chainDb, chain, nil, nil, 100*time.Millisecond)
	req.NoError(err)

	// case 1 single chain to (1, n), (1, n - k) would be the canonical head
	blocks := GeneratePalaChain(chain, chain.Genesis(), chain.Engine(), chainDb, int(n), BlockGenWithConsensusTransaction(chain, blockSns, hardforkK, nil, false, []ConsensusId{}))

	for i, blk := range blocks {
		err := bc.InsertBlock(blk, false)
		req.NoError(err, "failed to insert the %d-th block (%s)", i, blk.GetBlockSn())
	}
	req.Equal(NewBlockSn(1, 1, n-k), bc.GetFreshestNotarizedHead().GetBlockSn())

	makeSlice := func(sn BlockSn) []BlockSn {
		r := make([]BlockSn, 0)
		r = append(r, sn)
		return r
	}

	makeBlock := func(parent, sn BlockSn) Block {
		blocks := GeneratePalaChain(chain, bc.GetBlock(parent).(*blockImpl).B, chain.Engine(), chainDb, 1, BlockGenWithConsensusTransaction(chain, makeSlice(sn), hardforkK, nil, false, []ConsensusId{}))
		return blocks[0]
	}

	// case 2 branch to (2, 1) from (1, n - k), (1, n - k) would still be the canonical head
	currentBlock = makeBlock(NewBlockSn(1, 1, n-k), NewBlockSn(1, 2, 1))
	err = bc.InsertBlock(currentBlock, false)
	req.NoError(err)

	req.Equal(NewBlockSn(1, 1, n-k), bc.GetFreshestNotarizedHead().GetBlockSn())

	// case 3 add (1, n - k + 1) notarization, (1, n - k + 1) would be the new canonical head
	err = bc.AddNotarization(NewNotarizationFake(NewBlockSn(1, 1, n-k+1), []ConsensusId{}))
	req.NoError(err)

	req.Equal(NewBlockSn(1, 1, n-k+1), bc.GetFreshestNotarizedHead().GetBlockSn())

	// case 4 add (2, 1) notarization, (2, 1) would be the new canonical head
	err = bc.AddNotarization(NewNotarizationFake(NewBlockSn(1, 2, 1), []ConsensusId{}))
	req.NoError(err)

	req.Equal(NewBlockSn(1, 2, 1), bc.GetFreshestNotarizedHead().GetBlockSn())

	// case 5 add (1, n - k + 2) notarization, (2, 1) would still be the canonical head
	err = bc.AddNotarization(NewNotarizationFake(NewBlockSn(1, 1, n-k+2), []ConsensusId{}))
	req.NoError(err)

	req.Equal(NewBlockSn(1, 2, 1), bc.GetFreshestNotarizedHead().GetBlockSn())

	// case 6 add (2, 2) notarization, (2, 2) would be the new canonical head
	currentBlock = makeBlock(NewBlockSn(1, 2, 1), NewBlockSn(1, 2, 2))
	err = bc.InsertBlock(currentBlock, false)
	req.NoError(err)
	req.Equal(NewBlockSn(1, 2, 1), bc.GetFreshestNotarizedHead().GetBlockSn())

	err = bc.AddNotarization(NewNotarizationFake(NewBlockSn(1, 2, 2), []ConsensusId{}))

	req.NoError(err)
	req.Equal(NewBlockSn(1, 2, 2), bc.GetFreshestNotarizedHead().GetBlockSn())
}

func TestStorageImpl_handleStopBlock(t *testing.T) {
	req := require.New(t)
	k := uint32(3)

	chainDb, chain, err := NewThunderSinceGenesisWithMemDb()
	req.NoError(err)

	chain.Config().Thunder = newThunderConfig()
	chain.Config().Thunder.PalaBlock = new(big.Int).SetInt64(6)

	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	storage := NewStorage(StorageConfig{
		Db:                chainDb,
		Bc:                chain,
		Marshaller:        &DataUnmarshallerFake{},
		PalaFromGenesis:   true,
		Info:              &testutils.TestingCommInfo,
		UnnotarizedWindow: hardforkK,
	})

	// generated old chain
	blocks, _ := core.GenerateThunderChain(chain, chain.Genesis(), chain.Engine(), chainDb, 5, func(n int, block *core.BlockGen) {
		block.SetCoinbase(chainconfig.TestnetTxnFeeAddr)
		block.SetDifficulty(big.NewInt(1))
	})

	req.Equal(5, len(blocks))

	i, err := chain.InsertChain(blocks)
	req.Equal(5, i, "Failed to insert chain %q", err)

	blockSns := []BlockSn{
		NewBlockSn(1, 1, 1),
		NewBlockSn(1, 1, 2),
		NewBlockSn(1, 1, 3),
		NewBlockSn(1, 1, 4),
		NewBlockSn(1, 1, 5),
	}

	newBlocks := GeneratePalaChain(chain, chain.CurrentBlock(), chain.Engine(), chainDb, len(blockSns), BlockGenWithConsensusTransaction(chain, blockSns, hardforkK, nil, false, []ConsensusId{}))
	req.Equal(len(blockSns), len(newBlocks))

	for _, b := range newBlocks {
		err := storage.InsertBlock(b)
		req.NoError(err)
	}

	header, _ := readSessionStopHeader(chainDb, Session(0))
	req.Equal(blocks[len(blocks)-1].Hash(), header.Hash())
}

func TestStorageImpl_setHead(t *testing.T) {
	req := require.New(t)
	k := uint32(1)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	blockSns := []BlockSn{
		NewBlockSn(1, 1, 1),
		NewBlockSn(1, 1, 2),
		NewBlockSn(1, 1, 3),
		NewBlockSn(1, 1, 4),
		NewBlockSn(1, 1, 5),
		NewBlockSn(1, 2, 1),
		NewBlockSn(1, 2, 2),
		NewBlockSn(1, 2, 3),
		NewBlockSn(1, 2, 4),
		NewBlockSn(1, 2, 5),
	}
	s, _ := prepareChain(
		req, hardforkK, &DataUnmarshallerFake{}, []ConsensusId{"v1", "v2"}, blockSns)

	type args struct {
		number uint64
	}
	tests := []struct {
		name            string
		args            args
		expectFreshest  BlockSn
		expectFinalized BlockSn
	}{
		{
			name: "the same high",
			args: args{
				number: 10,
			},
			expectFreshest:  NewBlockSn(1, 2, 5),
			expectFinalized: NewBlockSn(1, 2, 4),
		},
		{
			name: "back to the a normal node",
			args: args{
				number: 8,
			},
			expectFreshest:  NewBlockSn(1, 2, 3),
			expectFinalized: NewBlockSn(1, 2, 2),
		},
		{
			name: "back to a timeout node",
			args: args{
				number: 6,
			},
			expectFreshest:  NewBlockSn(1, 2, 1),
			expectFinalized: NewBlockSn(1, 1, 4),
		},
		{
			name: "back to last epoch",
			args: args{
				number: 4,
			},
			expectFreshest:  NewBlockSn(1, 1, 4),
			expectFinalized: NewBlockSn(1, 1, 3),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			s.setHead(tt.args.number)
			req.Equal(tt.expectFreshest, s.GetFreshestNotarizedHeadSn())
			req.Equal(tt.expectFinalized, s.GetFinalizedHeadSn())
			s.ensureIntegrity()
			blk := newBlock(s.bc.CurrentBlock(), s.bc.Config().Thunder)
			req.Equal(tt.expectFreshest, blk.GetBlockSn())
		})
	}
}

func TestStorageImpl_ensureIntegrity(t *testing.T) {
	req := require.New(t)
	k := uint32(1)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	unmarshaller := &DataUnmarshallerFake{}
	voterIds := []ConsensusId{"v1", "v2"}

	blockSns := []BlockSn{
		NewBlockSn(1, 1, 1),
		NewBlockSn(1, 1, 2),
		NewBlockSn(1, 1, 3),
		NewBlockSn(1, 1, 4),
		NewBlockSn(1, 1, 5),
		NewBlockSn(1, 2, 1),
		NewBlockSn(1, 2, 2),
		NewBlockSn(1, 2, 3),
		NewBlockSn(1, 2, 4),
		NewBlockSn(1, 2, 5),
	}

	s, chainDb := prepareChain(req, hardforkK, unmarshaller, voterIds, blockSns)

	// Test the case that the local epoch is older.
	// Note that we haven't update the local epoch,
	// so it's the intiail value.
	ep := NewEpochManager(chainDb, unmarshaller)
	req.Equal(NewEpoch(1, 1), ep.GetEpoch())

	s.ensureIntegrity()

	ep = NewEpochManager(chainDb, unmarshaller)
	req.Equal(NewEpoch(1, 2), ep.GetEpoch())

	// Test the case that the local epoch is newer.
	cNota := NewClockMsgNotaFake(NewEpoch(1, 3), voterIds)
	err := ep.UpdateByClockMsgNota(cNota)
	req.NoError(err)
	req.Equal(NewEpoch(1, 3), ep.GetEpoch())

	s.ensureIntegrity()

	ep = NewEpochManager(chainDb, unmarshaller)
	req.Equal(NewEpoch(1, 2), ep.GetEpoch())
}

func TestStorageImpl_getCommInfo(t *testing.T) {
	req := require.New(t)
	k := uint32(1)

	chainDb, bc, err := NewThunderSinceGenesisWithMemDb()
	req.NoError(err)

	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	s := NewStorage(StorageConfig{
		Db:                chainDb,
		Bc:                bc,
		Info:              &testutils.TestingCommInfo,
		Marshaller:        &DataUnmarshallerFake{},
		PalaFromGenesis:   true,
		UnnotarizedWindow: hardforkK,
	})
	var empty []committee.AccelInfo
	st, err := bc.State()
	req.NoError(err)
	cInfo := s.getCommInfo(st, empty)
	req.NotNil(cInfo)
	req.Empty(cInfo.AccelInfo)
}

func TestStorageImpl_StopBlockTimeout(t *testing.T) {
	req := require.New(t)
	k := uint32(1)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	c, err := NewChainGeneratorWithElection(hardforkK)
	req.NoError(err)

	chainDb, bc, err := NewThunderSinceGenesisWithMemDb()
	req.NoError(err)

	sessionOffset := config.NewInt64HardforkConfig(
		"blockchain.unused.value", "")

	sessionOffset.SetTestValueAt(5, chain.Seq(0))
	sessionOffset.SetTestValueAtSession(5, 0)

	bc.Config().Thunder.ElectionStopBlockSessionOffset = sessionOffset

	s := NewStorage(StorageConfig{
		Db:                chainDb,
		Bc:                bc,
		Marshaller:        &DataUnmarshallerFake{},
		PalaFromGenesis:   true,
		Info:              &testutils.TestingCommInfo,
		UnnotarizedWindow: hardforkK,
	})
	//                                     (this height is stop block)
	// (1,1,1)->(1,1,2)->(1,1,3)->(1,1,4)->(1,1,5)
	//                                |
	//                                |---->(1,2,1)->(1,2,2)
	//                                        |
	//                                        |----->(2,1,1)->(2,1,2)
	sn := NewBlockSn(1, 1, 5)
	req.NoError(c.Init(sn))
	req.NoError(c.Branch(NewBlockSn(1, 1, 4), NewBlockSn(1, 2, 2)))
	c.Branch(NewBlockSn(1, 2, 1), NewBlockSn(2, 1, 2))
	PrettifyChainGenerator(c)

	srcChain := c.GetChain()

	shouldInsert := []BlockSn{
		NewBlockSn(1, 1, 1), NewBlockSn(1, 1, 2), NewBlockSn(1, 1, 3), NewBlockSn(1, 1, 4), NewBlockSn(1, 2, 1),
		NewBlockSn(2, 1, 1), NewBlockSn(2, 1, 2),
	}

	for _, sn := range shouldInsert {
		blk := srcChain.GetBlock(sn)
		req.NotNil(blk, "Block get %s failed", sn)
		req.NoError(s.InsertBlock(blk))
	}
}

func prepareChain(
	req *require.Assertions, k *config.Int64HardforkConfig, unmarshaller *DataUnmarshallerFake,
	voterIds []ConsensusId, blockSns []BlockSn,
) (*StorageImpl, ethdb.Database) {
	chainDb, chain, err := NewThunderSinceGenesisWithMemDb()
	req.NoError(err)

	s := NewStorage(StorageConfig{
		Db:                chainDb,
		Bc:                chain,
		Marshaller:        unmarshaller,
		PalaFromGenesis:   true,
		Info:              &testutils.TestingCommInfo,
		UnnotarizedWindow: k,
	})

	blocks := GeneratePalaChain(chain, chain.CurrentBlock(), chain.Engine(), chainDb, len(blockSns), BlockGenWithConsensusTransaction(chain, blockSns, k, nil, false, voterIds))
	req.Equal(len(blockSns), len(blocks))

	for _, b := range blocks {
		err := s.InsertBlock(b)
		req.NoError(err)
		_, _, err = s.AddNotarization(NewNotarizationFake(b.GetBlockSn(), []ConsensusId{}))
		req.NoError(err)
	}

	req.Equal(NewBlockSn(1, 2, 5), s.GetFreshestNotarizedHeadSn())

	return s, chainDb
}
