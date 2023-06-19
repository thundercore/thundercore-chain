package blockchain

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"
)

var (
	_ = DataUnmarshaller(&DataUnmarshallerImpl{})
)

func indices(l uint16) []uint16 {
	idcs := make([]uint16, 0, l)
	for i := uint16(0); i < l; i++ {
		idcs = append(idcs, i)
	}
	return idcs
}

func TestDataUnmarshaller(t *testing.T) {
	req := require.New(t)
	testKeys, err := SetupKeys(numOfVoters, numOfProposers)
	req.NoError(err)
	du := DataUnmarshallerImpl{Config: newThunderConfig()}
	tx := types.NewTransaction(10, common.Address{}, big.NewInt(123), 321, big.NewInt(456), []byte{3})
	ethBody := &types.Body{Transactions: []*types.Transaction{tx}}
	ethHeader := &types.Header{Number: big.NewInt(0)}
	ethBlock := types.NewBlockWithHeader(ethHeader).WithBody(ethBody.Transactions, ethBody.Uncles)

	b := newBlock(ethBlock, newThunderConfig())
	p := NewProposalImpl(b, testKeys.ProposerPrivPropKeys[0])

	t.Run("Proposal", func(t *testing.T) {
		req := require.New(t)
		ump, _, err := du.UnmarshalProposal(p.GetBody())
		req.NoError(err)
		req.True(p.(*proposalImpl).equals(ump.(*proposalImpl)))
	})

	v := NewVoteImpl(p, testKeys.VoterPrivVoteKeys[0])
	t.Run("Vote", func(t *testing.T) {
		req := require.New(t)
		umv, _, err := du.UnmarshalVote(v.GetBody())
		req.NoError(err)
		req.True(v.(*voteImpl).equals(umv.(*voteImpl)))
	})

	t.Run("Notarization", func(t *testing.T) {
		req := require.New(t)
		n := NewNotarizationImpl(b, testKeys.ProposerPrivPropKeys[0], 0, testKeys.VoterPrivVoteKeys, []uint16{})
		umn, _, err := du.UnmarshalNotarization(n.GetBody())
		req.NoError(err)
		req.True(n.(*notarizationImpl).equals(umn.(*notarizationImpl)))
	})

	e := NewEpoch(1, 1)
	t.Run("ClockMsg", func(t *testing.T) {
		req := require.New(t)
		c := NewClockMsgImpl(e, testKeys.VoterPrivVoteKeys[0])
		umc, _, err := du.UnmarshalClockMsg(c.GetBody())
		req.NoError(err)
		req.True(c.(*clockMsgImpl).equals(umc.(*clockMsgImpl)))
	})

	t.Run("ClockMsgNota", func(t *testing.T) {
		req := require.New(t)
		cn := NewClockMsgNotaImpl(e, testKeys.ProposerPrivPropKeys[0], 0, testKeys.VoterPrivVoteKeys, []uint16{})
		umcn, _, err := du.UnmarshalClockMsgNota(cn.GetBody())
		req.NoError(err)
		req.True(cn.(*clockMsgNotaImpl).equals(umcn.(*clockMsgNotaImpl)))
	})
}
