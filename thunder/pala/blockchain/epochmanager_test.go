package blockchain

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/consensus/thunder"

	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/stretchr/testify/require"
)

func TestEpochManagerImpl(t *testing.T) {
	memdb := rawdb.NewMemoryDatabase()
	req := require.New(t)

	em := NewEpochManager(memdb, &DataUnmarshallerFake{})

	e := em.GetEpoch()
	req.Equal(e, Epoch{1, 1})
	cn := em.GetLatestClockMsgNota(1)
	req.Nil(cn)

	cn = &ClockMsgNotaFake{Epoch{8, 7}, []ConsensusId{"thunder", "pala"}}

	err := em.UpdateByClockMsgNota(cn)
	req.NoError(err)

	newCn := em.GetLatestClockMsgNota(8)
	req.NotNil(newCn)
	req.Equal(cn, newCn)

	newE := em.GetEpoch()
	req.Equal(Epoch{8, 7}, newE)

	oldCn := em.GetLatestClockMsgNota(1)
	req.Nil(oldCn)

	req.Panics(func() { em.UpdateByReconfiguration(newE.Session - 1) })

	s := newE.Session + 1
	err = em.UpdateByReconfiguration(s)
	req.NoError(err)

	newE = em.GetEpoch()
	req.Equal(NewEpoch(uint32(s), 1), newE)
}

var (
	electionStopBlockSessionOffest = config.NewInt64HardforkConfig(
		"election.stopBlockSessionOffset",
		"The number of block that includes transactions in one session.",
	)
)

func TestEpochManagerImpl_GetLatestClockMsgNota(t *testing.T) {
	req := require.New(t)
	insertFirst := []BlockSn{
		NewBlockSn(1, 1, 1),
		NewBlockSn(1, 1, 2),
		NewBlockSn(1, 1, 3),
	}
	blockSns := []BlockSn{
		NewBlockSn(1, 1, 4),
		NewBlockSn(1, 1, 5),
		NewBlockSn(1, 1, 6),
		NewBlockSn(1, 1, 7),
		NewBlockSn(1, 1, 8),
		NewBlockSn(1, 1, 9),
		NewBlockSn(1, 1, 10),
		NewBlockSn(1, 1, 11),
		NewBlockSn(1, 1, 12),
		NewBlockSn(1, 1, 13),
		NewBlockSn(1, 1, 14),
		NewBlockSn(1, 1, 15),
		NewBlockSn(1, 1, 16),
		NewBlockSn(1, 1, 17),
		NewBlockSn(1, 1, 18),
		NewBlockSn(1, 1, 19),
		NewBlockSn(1, 1, 20),
		NewBlockSn(1, 1, 21),
		NewBlockSn(1, 1, 22),
		NewBlockSn(1, 1, 23),
		NewBlockSn(1, 1, 24),
		NewBlockSn(1, 1, 25),
		NewBlockSn(1, 1, 26),
		NewBlockSn(1, 1, 27),
		NewBlockSn(1, 2, 1),
		NewBlockSn(1, 2, 2),
		NewBlockSn(1, 2, 3),
		NewBlockSn(1, 2, 4),
		NewBlockSn(1, 2, 5),
		NewBlockSn(1, 2, 6),
	}
	k := uint32(1)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	db, chain, err := NewThunderSinceGenesisWithMemDb()
	req.NoError(err)

	bc, err := NewBlockChainWithFakeNota(hardforkK, db, chain, nil, electionStopBlockSessionOffest, 100*time.Millisecond)
	req.NoError(err)
	ep := NewEpochManager(db, &DataUnmarshallerFake{})

	req.NotNil(chain.Engine().(*thunder.Thunder))

	genBlocks := func(sns []BlockSn) []Block {
		return GeneratePalaChain(chain, chain.CurrentBlock(), chain.Engine(), db, len(sns), BlockGenWithConsensusTransaction(chain, sns, hardforkK, nil, true, []ConsensusId{}))
	}

	blocks := genBlocks(insertFirst)

	for _, blk := range blocks {
		if blk.GetBlockSn().S == 1 {
			if _, clockNota := bc.DecodeBlock(blk); clockNota != nil {
				ep.UpdateByClockMsgNota(clockNota)
			}
		}
		err = bc.InsertBlock(blk, false)
		req.NoError(err)
		err = bc.AddNotarization(NewNotarizationFake(blk.GetBlockSn(), []ConsensusId{}))
		req.NoError(err)
	}

	blocks = genBlocks(blockSns)

	for _, blk := range blocks {
		if blk.GetBlockSn().S == 1 {
			if _, clockNota := bc.DecodeBlock(blk); clockNota != nil {
				ep.UpdateByClockMsgNota(clockNota)
			}
		}
		err = bc.InsertBlock(blk, false)
		req.NoError(err)
	}

	err = ep.UpdateByReconfiguration(2)
	req.NoError(err)

	e := ep.GetLatestClockMsgNota(2)
	req.Nil(e)

	e = ep.GetLatestClockMsgNota(1)
	req.NotNil(e)
	req.Equal(Epoch{1, 2}, e.GetEpoch())
}
