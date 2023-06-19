package blockchain

import (
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/clock"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/stretchr/testify/require"
)

var blockTime time.Duration

func TestMain(m *testing.M) {
	// Reduce the output to speed up the tests.
	lgr.SetLogLevel("/blockchain", lgr.LvlWarning)
	// TOOD: ../../../config is a dirty path
	config.InitHardforkConfig("../../../config")
	clk = clock.NewFakeClock(1000)
	blockTime = 100 * time.Millisecond

	m.Run()
}

func TestFreshestNotarizedChain(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		req := require.New(t)

		hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
		hardforkK.SetTestValueAtSession(1, 0)
		c, err := NewChainGenerator(true, hardforkK)
		req.NoError(err)
		bc := c.GetChain()

		// (1,1,1)->(1,1,2)->(1,1,3)->(1,1,4)
		//             |
		//             ----->(1,2,1)->(1,2,2)
		c.Init(NewBlockSn(1, 1, 4))
		c.Branch(NewBlockSn(1, 1, 2), NewBlockSn(1, 2, 2))

		actual := bc.GetFreshestNotarizedHead()

		req.NotNil(actual)
		req.Equal("0[]->(1,1,1)[]->(1,1,2)[(1,1,1)]->(1,2,1)[(1,1,2)]", DumpFakeChain(bc, actual, true))
		req.Equal(bc.(*BlockChainImpl).storage.(*StorageFake).ComputeFreshestNotarizedChain(), actual)
	})

	t.Run("freshest is not longest", func(t *testing.T) {
		req := require.New(t)

		hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
		hardforkK.SetTestValueAtSession(2, 0)
		c, err := NewChainGenerator(true, hardforkK)
		req.NoError(err)
		bc := c.GetChain()

		// (1,1,1)->(1,1,2)->(1,1,3)->(1,1,4)
		//    |        |
		//    |        ----->(1,3,1)->(1,3,2)->(1,3,3)
		//    |
		//    ----->(1,2,1)->(1,2,2)->(1,2,3)->(1,2,4)

		c.Init(NewBlockSn(1, 1, 4))
		c.Branch(NewBlockSn(1, 1, 1), NewBlockSn(1, 2, 4))
		c.Branch(NewBlockSn(1, 1, 2), NewBlockSn(1, 3, 3))

		actual := bc.GetFreshestNotarizedHead()

		req.NotNil(actual)
		req.Equal("0[]->(1,1,1)[]->(1,1,2)[]->(1,3,1)[(1,1,1),(1,1,2)]", DumpFakeChain(bc, actual, true))
		req.Equal(bc.(*BlockChainImpl).storage.(*StorageFake).ComputeFreshestNotarizedChain(), actual)
	})

	t.Run("newest is not notarized", func(t *testing.T) {
		req := require.New(t)

		hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
		hardforkK.SetTestValueAtSession(2, 0)

		c, err := NewChainGenerator(true, hardforkK)
		req.NoError(err)
		bc := c.GetChain()

		// (1,1,1)->(1,1,2)->(1,1,3)->(1,1,4)->(1,1,5)
		//    |        |
		//    |        ----->(1,3,1)->(1,3,2)
		//    |
		//    ----->(1,2,1)->(1,2,2)->(1,2,3)->(1,2,4)->(1,2,5)
		c.Init(NewBlockSn(1, 1, 5))
		c.Branch(NewBlockSn(1, 1, 1), NewBlockSn(1, 2, 5))
		c.Branch(NewBlockSn(1, 1, 2), NewBlockSn(1, 3, 2))

		actual := bc.GetFreshestNotarizedHead()
		req.NotNil(actual)

		req.Equal(bc.(*BlockChainImpl).storage.(*StorageFake).ComputeFreshestNotarizedChain(), actual)
		req.Equal("0[]->(1,1,1)[]->(1,2,1)[(1,1,1)]->(1,2,2)[]->(1,2,3)[(1,2,1)]", DumpFakeChain(bc, actual, true))
	})
}

func TestFinalizedChain(t *testing.T) {
	k := uint32(2)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	t.Run("no new finalized block", func(t *testing.T) {
		req := require.New(t)

		c, err := NewChainGenerator(true, hardforkK)
		req.NoError(err)
		bc := c.GetChain()

		// (1,1,1)->(1,1,2)->(1,1,3)->(1,1,4)
		c.Init(NewBlockSn(1, 1, 4))

		actual := bc.GetFinalizedHead()

		req.NotNil(actual)
		req.Equal("0", DumpFakeChain(bc, actual, false))
		req.Equal(bc.(*BlockChainImpl).storage.(*StorageFake).ComputeFinalizedChain(k), actual)
	})

	t.Run("minimal finalized requirement", func(t *testing.T) {
		req := require.New(t)

		c, err := NewChainGenerator(true, hardforkK)
		req.NoError(err)
		bc := c.GetChain()

		// (1,1,1)->(1,1,2)->(1,1,3)->(1,1,4)->(1,1,5)
		c.Init(NewBlockSn(1, 1, 5))
		actual := bc.GetFinalizedHead()

		req.NotNil(actual)
		req.Equal("0->(1,1,1)", DumpFakeChain(bc, actual, false))
		req.Equal(bc.(*BlockChainImpl).storage.(*StorageFake).ComputeFinalizedChain(k), actual)
	})

	t.Run("longer finalized chain", func(t *testing.T) {
		req := require.New(t)

		c, err := NewChainGenerator(true, hardforkK)
		req.NoError(err)
		bc := c.GetChain()

		// (1,1,1)->(1,1,2)->(1,1,3)->(1,1,4)->(1,1,5)
		//             |
		//             ----->(1,2,1)->(1,2,2)->(1,2,3)->(1,2,4)->(1,2,5)->(1,2,6)->(1,2,7)
		c.Init(NewBlockSn(1, 1, 5))
		c.Branch(NewBlockSn(1, 1, 2), NewBlockSn(1, 2, 7))

		actual := bc.GetFinalizedHead()

		req.NotNil(actual)
		req.Equal("0->(1,1,1)->(1,1,2)->(1,2,1)->(1,2,2)->(1,2,3)", DumpFakeChain(bc, actual, false))
		req.Equal(bc.(*BlockChainImpl).storage.(*StorageFake).ComputeFinalizedChain(k), actual)
	})
}

func TestStartCreatingNewBlock(t *testing.T) {
	req := require.New(t)
	unnotarizedWindow := uint32(2)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(unnotarizedWindow), 0)
	c, err := NewChainGenerator(true, hardforkK)
	req.NoError(err)
	bc := c.GetChain()
	epoch := NewEpoch(1, 1)

	// Create the blocks.
	var b Block
	ch, err := bc.StartCreatingNewBlocks(epoch, nil)
	req.NoError(err)
	for i := uint32(0); i < unnotarizedWindow; i++ {
		b = (<-ch).Block
		req.Equal(BlockSn{epoch, i + 1}, b.GetBlockSn())
	}
	// Expect the blockchain blocks because there is no notarization.
	select {
	case <-ch:
		t.FailNow()
	case <-time.After(100 * time.Millisecond):
	}

	// Add notarization, so BlockChain can create new blocks.
	voterIds := MakeConsensusIds("v1")
	err = bc.AddNotarization(&NotarizationFake{BlockSn{epoch, 1}, voterIds})
	req.NoError(err)
	b = (<-ch).Block
	req.Equal(BlockSn{epoch, 3}, b.GetBlockSn())
	decoder := &BlockFakeDecoder{}
	notas := decoder.GetNotarizations(b, nil)
	req.Equal(1, len(notas))
	// Expect storing the "parent-k"'s notarization.
	req.Equal(BlockSn{epoch, 1}, notas[0].GetBlockSn())

	err = bc.StopCreatingNewBlocks(WaitingPeriodForStopingNewBlocks)
	req.NoError(err)

	// Expect created blocks are already inserted.
	for i := uint32(1); i <= uint32(3); i++ {
		b = bc.GetBlock(BlockSn{epoch, i})
		req.NotNil(b)
		req.Equal(BlockSn{epoch, i}, b.GetBlockSn())
	}

	// Create the blocks at the next epoch.
	err = bc.AddNotarization(&NotarizationFake{BlockSn{epoch, 2}, voterIds})
	req.NoError(err)
	err = bc.AddNotarization(&NotarizationFake{BlockSn{epoch, 3}, voterIds})
	req.NoError(err)

	epoch = epoch.NextEpoch()
	fnc := bc.GetFreshestNotarizedHead()
	ch, err = bc.StartCreatingNewBlocks(epoch, NewClockMsgNotaFake(epoch, voterIds))
	req.NoError(err)
	b = (<-ch).Block
	req.NotNil(b)
	req.Equal(BlockSn{epoch, 1}, b.GetBlockSn())
	req.Equal(fnc.GetBlockSn(), b.GetParentBlockSn())

	// Expect the first block contains previous blocks' notarizations.
	notas = decoder.GetNotarizations(b, nil)
	req.Equal(2, len(notas))
	pe, _ := epoch.PreviousEpoch()
	req.Equal(BlockSn{pe, 2}, notas[0].GetBlockSn())
	req.Equal(BlockSn{pe, 3}, notas[1].GetBlockSn())
}

func TestFakeDataMarshalAndUnMarshal(t *testing.T) {
	req := require.New(t)

	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(1, 0)
	cg, err := NewChainGenerator(true, hardforkK)

	req.NoError(err)
	bc := cg.GetChain()

	sn := NewBlockSn(1, 1, 2)
	cg.Init(sn)
	cg.SetVoters(MakeConsensusIds("v1"))

	b := bc.GetBlock(sn)
	p := ProposalFake{ConsensusId("p1"), b}
	v := VoteFake{sn, "v1"}
	n := NewNotarizationFake(sn, MakeConsensusIds("v1"))
	c := ClockMsgFake{NewEpoch(1, 5), ConsensusId("v5")}
	cn := NewClockMsgNotaFake(NewEpoch(1, 5), MakeConsensusIds("v5"))

	du := &DataUnmarshallerFake{}

	asn, _, err := NewBlockSnFromBytes(sn.ToBytes())
	req.NoError(err)
	req.Equal(sn, asn)

	ab, _, err := du.UnmarshalBlock(b.GetBody())
	req.NoError(err)
	req.NotNil(ab)
	req.Equal(b, ab)

	ap, _, err := du.UnmarshalProposal(p.GetBody())
	req.NoError(err)
	req.NotNil(ap)
	var ep Proposal = &p
	req.Equal(ep, ap)

	av, _, err := du.UnmarshalVote(v.GetBody())
	req.NoError(err)
	req.NotNil(av)
	var ev Vote = &v
	req.Equal(ev, av)

	an, _, err := du.UnmarshalNotarization(n.GetBody())
	req.NoError(err)
	req.NotNil(an)
	req.Equal(n, an)

	ac, _, err := du.UnmarshalClockMsg(c.GetBody())
	req.NoError(err)
	req.NotNil(ac)
	var ec ClockMsg = &c
	req.Equal(ec, ac)

	acn, _, err := du.UnmarshalClockMsgNota(cn.GetBody())
	req.NoError(err)
	req.NotNil(acn)
	req.Equal(cn, acn)
}

func TestBlockChain_EngineWithBranch(t *testing.T) {
	req := require.New(t)
	k := uint32(3)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)
	end := 10

	chainDb, chain, err := NewThunderSinceGenesisWithMemDb()
	req.NoError(err)
	bc, err := NewBlockChainWithFakeNota(hardforkK, chainDb, chain, nil, nil, blockTime)
	req.NoError(err)

	makeSlice := func(sn BlockSn) []BlockSn {
		r := make([]BlockSn, 0)
		r = append(r, sn)
		return r
	}
	makeBlock := func(parent, sn BlockSn) Block {
		blocks := GeneratePalaChain(chain, bc.GetBlock(parent).(*blockImpl).B, chain.Engine(), chainDb, 1, BlockGenWithConsensusTransaction(chain, makeSlice(sn), hardforkK, WithSimpleTransactionAndRandomBidForTest(100, chain), true, []ConsensusId{}))
		return blocks[0]
	}

	parent := GetGenesisBlockSn()
	epoch := Epoch{
		Session: 1,
		E:       1,
	}
	blocks := make([]Block, 0)
	// NOTE: because the BlockGenWithConsensusTransaction() would include the n-k notarization,
	// so currentHeader() would be n-k
	for s := uint32(1); s <= uint32(end); s++ {
		cur := BlockSn{epoch, s}
		blk := makeBlock(parent, cur)
		err = bc.InsertBlock(blk, false)
		req.NoError(err)
		parent = cur
		blocks = append(blocks, blk)
	}

	t.Run("Test insert into another chain.", func(t *testing.T) {
		req := require.New(t)
		chainDb, chain, err := NewThunderSinceGenesisWithMemDb()
		req.NoError(err)

		bc, err := NewBlockChainWithFakeNota(hardforkK, chainDb, chain, nil, nil, blockTime)
		req.NoError(err)

		for _, blk := range blocks {
			err = bc.InsertBlock(blk, false)
			req.NoError(err)
			err = bc.AddNotarization(NewNotarizationFake(blk.GetBlockSn(), []ConsensusId{}))
			req.NoError(err)
		}

	})

	t.Run("Test chain events.", func(t *testing.T) {
		req := require.New(t)
		chainDb, chain, err := NewThunderSinceGenesisWithMemDb()
		req.NoError(err)
		chainEvent := make(chan core.ChainEvent, 64)
		sub := chain.SubscribeChainEvent(chainEvent)
		defer sub.Unsubscribe()
		chainHeadEvent := make(chan core.ChainHeadEvent, 64)
		chainHeadSub := chain.SubscribeChainHeadEvent(chainHeadEvent)
		defer chainHeadSub.Unsubscribe()
		chainSideEvent := make(chan core.ChainSideEvent, 64)
		chainSideSub := chain.SubscribeChainSideEvent(chainSideEvent)
		defer chainSideSub.Unsubscribe()

		bc, err := NewBlockChainWithFakeNota(hardforkK, chainDb, chain, nil, nil, blockTime)
		req.NoError(err)

		for i, blk := range blocks {
			err = bc.InsertBlock(blk, false)
			req.NoError(err)
			select {
			case e := <-chainSideEvent:
				req.Equal(blk.GetHash().Bytes(), e.Block.Hash().Bytes())
			default:
				req.FailNow("Expecting ChainSideEvent")
			}
			if uint32(blk.GetNumber()) > k {
				notarizedBlk := blocks[i-int(k)]
				select {
				case ce := <-chainEvent:
					req.Equal(notarizedBlk.GetHash().Bytes(), ce.Block.Hash().Bytes())
				default:
					req.FailNow("Expecting ChainEvent")
				}
				select {
				case e := <-chainHeadEvent:
					req.Equal(notarizedBlk.GetHash().Bytes(), e.Block.Hash().Bytes())
				default:
					req.FailNow("Expecting ChainHeadEvent")
				}
			} else {
				select {
				case ce := <-chainEvent:
					req.FailNow("Unexpected ChainEvent", ce)
				case che := <-chainHeadEvent:
					req.FailNow("Unexpected ChainHeadEvent", che)
				default:
				}
			}
		}
	})
}

func TestBlockChain_InsertWithRandomCrash(t *testing.T) {
	req := require.New(t)

	db, chain, err := NewThunderSinceGenesisWithMemDb()
	req.NoError(err)

	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(1, 0)

	bc, err := NewBlockChainWithFakeNota(hardforkK, db, chain, BuildTxPool(chain), nil, blockTime)
	req.NoError(err)
	crashingDb := NewCrashingMemoryDb(t, db)
	blockSns := make([]BlockSn, 0, 100)
	for i := 1; i < 100; i++ {
		blockSns = append(blockSns, NewBlockSn(1, 1, uint32(i)))
	}
	blocks := GeneratePalaChain(chain, chain.CurrentBlock(), chain.Engine(), db, len(blockSns),
		BlockGenWithConsensusTransaction(chain, blockSns, hardforkK, nil, false, []ConsensusId{}))

	for i := 0; i < 1000; i++ {
		// should finally up to date
		tryCrashAndRecoveryInsert(t, crashingDb, blocks)

		chain := NewThunderWithExistingDb(t, db)
		bc, err := NewBlockChainWithFakeNota(hardforkK, db, chain, BuildTxPool(chain), nil, blockTime)
		req.NoError(err)
		sn := bc.GetFreshestNotarizedHeadSn()
		if sn.Compare(blockSns[len(blockSns)-1]) == 0 {
			return
		}
	}

	req.FailNow("Cannot finish insert with random crashes", "Current progress is %s", bc.GetFreshestNotarizedHeadSn())
}

func TestFinalityCheck(t *testing.T) {
	k := uint32(2)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	req := require.New(t)
	errMsg := func(sn BlockSn) string {
		return fmt.Sprintf("block %s neither extends from finalized chain nor from previous stop block", sn.GetBlockSn())
	}

	bc, err := NewBlockChainFakeWithDelay(hardforkK, 0, 4)
	req.NoError(err)
	c := NewChainGeneratorWithExistedFakeChain(bc, hardforkK)

	endS := uint32(7)
	c.Init(NewBlockSn(1, 1, endS))
	c.NotarizeTail(c.GetTails()[0])
	req.Equal(NewBlockSn(1, 1, endS-k), bc.GetFinalizedHeadSn())
	req.Equal(NewBlockSn(1, 1, endS), bc.GetFreshestNotarizedHeadSn())

	endS = uint32(4)
	c.Branch(NewBlockSn(1, 1, 5), NewBlockSn(1, 2, endS))
	c.NotarizeTail(c.GetTails()[1])
	req.Equal(NewBlockSn(1, 2, endS-k), bc.GetFinalizedHeadSn())
	req.Equal(NewBlockSn(1, 2, endS), bc.GetFreshestNotarizedHeadSn())

	// Notarized chain:
	//                                     stop-blk
	// (1,1,1)<-(1,1,2)<-(1,1,3)<-(1,1,4)<-(1,1,5)<-(1,1,6)<-(1,1,7)
	//                                        ^
	//                                        |
	//                                        +-(1,2,1)<-(1,2,2)<-(1,2,3)<-(1,2,4)
	tests := []struct {
		name     string
		parentSn BlockSn
		sn       []BlockSn
		fail     bool
	}{
		{
			name:     "not extending from finalized head",
			parentSn: NewBlockSn(1, 1, 2),
			sn:       []BlockSn{NewBlockSn(1, 3, 1)},
			fail:     true,
		}, {
			name:     "not extending from finalized head - 2",
			parentSn: NewBlockSn(1, 1, 4),
			sn:       []BlockSn{NewBlockSn(1, 3, 1)},
			fail:     true,
		}, {
			name:     "directly extend from finalized head",
			parentSn: NewBlockSn(1, 2, 2),
			sn:       []BlockSn{NewBlockSn(1, 3, 1)},
			fail:     false,
		}, {
			name:     "extend from notarized head",
			parentSn: NewBlockSn(1, 2, 4),
			sn:       []BlockSn{NewBlockSn(1, 2, 5)},
			fail:     false,
		}, {
			name:     "extend from unnotarized head",
			parentSn: NewBlockSn(1, 2, 5),
			sn:       []BlockSn{NewBlockSn(1, 2, 6)},
			fail:     false,
		}, {
			name:     "extend from block after stop block",
			parentSn: NewBlockSn(1, 1, 5),
			sn: func() []BlockSn {
				var sn []BlockSn
				for i := uint32(0); i < 1+2*k; i++ {
					sn = append(sn, NewBlockSn(2, 1, i+1))
				}
				return sn
			}(),
			fail: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			blks, err := c.MakeBlocks(bc.GetBlock(tt.parentSn), tt.sn)
			req.NoError(err)
			for _, b := range blks {
				err = bc.InsertBlock(b, false)
				if tt.fail {
					req.EqualError(err, errMsg(b.GetBlockSn()))
				} else {
					req.NoError(err)
				}
			}
		})
	}

	req.Equal(NewBlockSn(2, 1, 1), bc.GetFinalizedHeadSn())
	req.Equal(NewBlockSn(2, 1, 1+k), bc.GetFreshestNotarizedHeadSn())
}

func TestInsertBlockAfterStopBlock(t *testing.T) {
	k := uint32(2)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	req := require.New(t)
	errMsg := func(sn BlockSn) string {
		return fmt.Sprintf("block %s neither extends from finalized chain nor from previous stop block", sn.GetBlockSn())
	}

	bc, err := NewBlockChainFakeWithDelay(hardforkK, 0, 4)
	req.NoError(err)
	c := NewChainGeneratorWithExistedFakeChain(bc, hardforkK)

	endS := uint32(5)
	c.Init(NewBlockSn(1, 1, endS))
	c.NotarizeTail(c.GetTails()[0])
	req.Equal(NewBlockSn(1, 1, endS-k), bc.GetFinalizedHeadSn())
	req.Equal(NewBlockSn(1, 1, endS), bc.GetFreshestNotarizedHeadSn())

	endS = uint32(4)
	c.Branch(NewBlockSn(1, 1, 5), NewBlockSn(1, 2, endS))
	c.NotarizeTail(c.GetTails()[1])
	req.Equal(NewBlockSn(1, 2, endS-k), bc.GetFinalizedHeadSn())
	req.Equal(NewBlockSn(1, 2, endS), bc.GetFreshestNotarizedHeadSn())

	oldFH := bc.GetFinalizedHead()

	// Notarized chain:
	//                                     stop-blk
	// (1,1,1)<-(1,1,2)<-(1,1,3)<-(1,1,4)<-(1,1,5)
	//                                        ^
	//                                        |
	//                                        +-(1,2,1)<-(1,2,2)<-(1,2,3)<-(1,2,4)
	tests := []struct {
		name     string
		parentSn BlockSn
		sn       []BlockSn
		fail     bool
	}{
		{
			name:     "extend directly from stop block - 1",
			parentSn: NewBlockSn(1, 1, 5),
			sn:       []BlockSn{NewBlockSn(1, 3, 1)},
			fail:     false,
		},
		{
			name:     "extend directly from stop block - 2",
			parentSn: NewBlockSn(1, 1, 5),
			sn:       []BlockSn{NewBlockSn(1, 1, 6), NewBlockSn(1, 1, 7)},
			fail:     false,
		},
		{
			name:     "extend from non finalized chain 1",
			parentSn: NewBlockSn(1, 3, 1),
			sn:       []BlockSn{NewBlockSn(1, 3, 2)},
			fail:     false,
		},
		{
			name:     "extend from non finalized chain 2 and finalized a new session's first block",
			parentSn: NewBlockSn(1, 1, 7),
			sn: func() []BlockSn {
				var sn []BlockSn
				for i := uint32(0); i < 1+2*k; i++ {
					sn = append(sn, NewBlockSn(2, 1, i+1))
				}
				return sn
			}(),
			fail: false,
		},
		{
			name:     "extend from non finalized chain after new session's first block is finalized",
			parentSn: NewBlockSn(1, 3, 2),
			sn:       []BlockSn{NewBlockSn(1, 3, 3)},
			fail:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			blks, err := c.MakeBlocks(bc.GetBlock(tt.parentSn), tt.sn)
			req.NoError(err)
			for _, b := range blks {
				err = bc.InsertBlock(b, false)
				if tt.fail {
					req.EqualError(err, errMsg(b.GetBlockSn()))
				} else {
					req.NoError(err)
				}
			}
		})
	}

	req.Equal(NewBlockSn(2, 1, 1), bc.GetFinalizedHeadSn())
	req.Equal(NewBlockSn(2, 1, 1+k), bc.GetFreshestNotarizedHeadSn())
	// finalized chain changed
	req.Equal(NewBlockSn(1, 1, 7), bc.GetBlockByNumber(oldFH.GetNumber()).GetBlockSn())
}

func TestStopCreatingNewBlocks(t *testing.T) {
	req := require.New(t)

	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(1, 0)

	c, err := NewChainGenerator(true, hardforkK)
	req.NoError(err)

	bc := c.GetChain()

	waitingPeriod := 100 * time.Millisecond
	err = bc.StopCreatingNewBlocks(waitingPeriod)
	req.Error(err) // Not running.

	// Update the internal data to make BlockChainImpl think BlockMaker
	// is running. This approach simplifies the test setup a lot.
	stoppedEvent := make(chan struct{})
	bc.(*BlockChainImpl).isCreatingBlockCh = stoppedEvent

	// Simulate the BlockMaker reading the stop event once, so the second call of
	// StopCreatingNewBlocks() will be blocked before stoppedEvent is closed.
	go func() {
		<-bc.(*BlockChainImpl).stopChan
		time.Sleep(waitingPeriod * 2)
		close(stoppedEvent)
	}()

	// Call StopCreatingNewBlocks twice.
	// Note:
	// * Expect the first call ends immediately (stopChan is read immediately).
	// * Expect the second call ends after stoppedEvent is closed.
	for i := 0; i < 2; i++ {
		ch := make(chan struct{})
		go func() {
			err = bc.StopCreatingNewBlocks(waitingPeriod)
			req.NoError(err)
			ch <- struct{}{}
		}()

		select {
		case <-ch:
		case <-time.After(waitingPeriod * 3):
			req.FailNow(fmt.Sprintf("StopCreatingNewBlocks() is blocked; i=%d", i))
		}
	}
}

func tryCrashAndRecoveryInsert(t *testing.T, db ethdb.Database, blocks []Block) {
	// simulate insert chain by chainsyncing or voter mode.
	req := require.New(t)
	k := uint32(1)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	var sn BlockSn
	defer func() {
		if caught := recover(); caught != nil {
			// If you have to check the stack trace, follow this code.
			//	buf := make([]byte, 1024*1024)
			//	buf = buf[:runtime.Stack(buf, false)]
			// t.Logf("Panic Recover (%s)!! %q stack := \n%s", sn, caught, string(buf))
		}
	}()

	chain := NewThunderWithExistingDb(t, db)
	bc, err := NewBlockChainWithFakeNota(hardforkK, db, chain, nil, nil, blockTime)
	req.NoError(err)

	b := newBlock(chain.CurrentBlock(), chain.Config().Thunder)
	req.Zero(bc.GetFreshestNotarizedHeadSn().Compare(b.GetBlockSn()), "Notarization doesn't match")
	lastSn := blocks[len(blocks)-1].GetBlockSn()
	for lastSn.Compare(bc.GetFreshestNotarizedHeadSn()) > 0 {
		sn = bc.GetFreshestNotarizedHeadSn()
		next := sort.Search(len(blocks), func(i int) bool {
			return blocks[i].GetBlockSn().Compare(sn) > 0
		})

		req.Greater(len(blocks), next)

		b := blocks[next]
		err := bc.InsertBlock(b, false)
		req.NoError(err)

		err = bc.AddNotarization(NewNotarizationFake(b.GetBlockSn(), []ConsensusId{}))
		req.NoError(err)
	}
}
