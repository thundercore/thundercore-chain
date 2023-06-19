package blockchain

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

const (
	numOfVoters    = 5
	numOfProposers = 3
	k              = 1
)

// Verify that VerifierImpl and consensus data types implements its interface
var (
	_ = Verifier(&VerifierImpl{})
	_ = Proposal(&proposalImpl{})
	_ = Vote(&voteImpl{})
	_ = Notarization(&notarizationImpl{})
	_ = ClockMsg(&clockMsgImpl{})
	_ = ClockMsgNota(&clockMsgNotaImpl{})
)

func copyVotes(votes []Vote) []Vote {
	return append(votes[:0:0], votes...)
}

func copyClks(clocks []ClockMsg) []ClockMsg {
	return append(clocks[:0:0], clocks...)
}

func newOneBlockFake() Block {
	sn := GetGenesisBlockSn()
	return NewBlockFake(BlockSn{sn.Epoch.NextSession(), 1}, sn, 0, nil, nil, "0")
}

func newBlockChain(k *config.Int64HardforkConfig) (BlockChain, error) {
	return NewBlockChainFake(k)
}

func newInvalidClockMsg(e Epoch, id ConsensusId, signer bls.BlsSigner) ClockMsg {
	return &clockMsgImpl{
		epoch:     e,
		signature: signer.Sign(e.ToBytes()),
		voterId:   id,
	}
}

func TestProposal(t *testing.T) {
	req := require.New(t)
	testKeys, err := SetupKeys(numOfVoters, numOfProposers)
	req.NoError(err)
	p0 := CreateVerifierForTest("p0", testKeys.ElectionResult, testKeys.ProposerPrivPropKeys[0])
	v0 := CreateVerifierForTest("v0", testKeys.ElectionResult, testKeys.VoterPrivVoteKeys[0])
	b := newOneBlockFake()

	t.Run("NewProposal", func(t *testing.T) {
		req := require.New(t)
		p, err := p0.Propose(b)
		req.NoError(err)
		pb := p.GetBlock()
		req.True(bytes.Equal(pb.GetBody(), b.GetBody()))

		err = v0.VerifyProposal(p)
		req.NoError(err)
	})

	t.Run("InvalidProposal", func(t *testing.T) {
		req := require.New(t)
		sig := testKeys.VoterPrivVoteKeys[0].Sign(b.GetBody())
		p := &proposalImpl{
			block:      b,
			signature:  sig,
			proposerId: ConsensusIdFromPubKey(testKeys.ProposerPubPropKeys[0]),
		}

		err = v0.VerifyProposal(p)
		req.EqualError(err, fmt.Sprint(ErrBadSig))
	})

	t.Run("Not primary proposer", func(t *testing.T) {
		req := require.New(t)
		sig := testKeys.VoterPrivVoteKeys[0].Sign(b.GetBody())
		sn := GetGenesisBlockSn()
		nb := NewBlockFake(BlockSn{sn.Epoch.NextSession().NextEpoch(), 1}, sn, 0, nil, nil, "0")
		p := &proposalImpl{
			block:      nb,
			signature:  sig,
			proposerId: ConsensusIdFromPubKey(testKeys.ProposerPubPropKeys[0]),
		}

		err = v0.VerifyProposal(p)
		req.True(strings.Contains(err.Error(), "not the right primary proposer"))
	})
}

func TestNewVote(t *testing.T) {
	req := require.New(t)
	testKeys, err := SetupKeys(numOfVoters, numOfProposers)
	req.NoError(err)
	v := CreateVerifierForTest("v0", testKeys.ElectionResult, testKeys.VoterPrivVoteKeys[0])

	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	c, err := newBlockChain(hardforkK)
	req.NoError(err)
	b := newOneBlockFake()
	err = c.InsertBlock(b, false)
	req.NoError(err)

	t.Run("NewVote", func(t *testing.T) {
		req := require.New(t)
		p := NewProposalImpl(b, testKeys.ProposerPrivPropKeys[0])
		vote, err := v.Vote(p)
		req.NoError(err)

		err = v.VerifyVote(vote, c)
		req.NoError(err)
	})

	t.Run("InvalidVote", func(t *testing.T) {
		req := require.New(t)
		id := ConsensusIdFromPubKey(testKeys.VoterPrivVoteKeys[1].GetPublicKey())
		vote := NewInvalidVote(b.GetBlockSn(), b.GetHash(), id, testKeys.VoterPrivVoteKeys[0])
		err = v.VerifyVote(vote, c)
		req.EqualError(err, fmt.Sprint(ErrBadSig))

		vote = NewInvalidVote(b.GetBlockSn(), Hash{}, id, testKeys.VoterPrivVoteKeys[0])
		err = v.VerifyVote(vote, c)
		req.True(strings.HasPrefix(err.Error(), "Blockhash mismatch"))
	})
}

func TestNotarization(t *testing.T) {
	t.Parallel()
	req := require.New(t)
	testKeys, err := SetupKeys(numOfVoters, numOfProposers)
	req.NoError(err)
	proposer := CreateVerifierForTest("p0", testKeys.ElectionResult, testKeys.ProposerPrivPropKeys[0])
	verifiers := make([]Verifier, numOfVoters)

	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	c, err := newBlockChain(hardforkK)
	req.NoError(err)
	for i := 0; i < numOfVoters; i++ {
		verifiers[i] = CreateVerifierForTest(fmt.Sprintf("v%d", i), testKeys.ElectionResult, testKeys.VoterPrivVoteKeys[i])
	}

	b := newOneBlockFake()
	err = c.InsertBlock(b, false)
	req.NoError(err)

	votes := make([]Vote, numOfVoters)
	p := NewProposalImpl(b, testKeys.ProposerPrivPropKeys[0])
	for i := 0; i < testKeys.ElectionResult.NumCommittee(); i++ {
		votes[i] = NewVoteImpl(p, testKeys.VoterPrivVoteKeys[i])
	}
	threshold := seatBasedVotingThreshold(numOfVoters)

	type expected struct {
		notarizeError    error
		nVotes           int
		missingVoterIdxs []uint16
	}
	tests := []struct {
		name     string
		votes    []Vote
		expected expected
	}{
		{
			name:  "not enough votes",
			votes: votes[:threshold-1],
			expected: expected{
				notarizeError: ErrNotEnoughVotes,
			},
		},
		{
			name:  "just enough votes",
			votes: votes[:threshold],
			expected: expected{
				notarizeError: nil,
				nVotes:        threshold,
				missingVoterIdxs: func(begin, end uint16) []uint16 {
					var idxs []uint16
					for i := begin; i < end; i++ {
						idxs = append(idxs, i)
					}
					return idxs
				}(uint16(threshold), numOfVoters),
			},
		},
		{
			name:  "all votes",
			votes: votes,
			expected: expected{
				notarizeError: nil,
				nVotes:        numOfVoters,
			},
		},
		{
			name:  "duplicate votes",
			votes: append(copyVotes(votes), votes...),
			expected: expected{
				notarizeError: nil,
				nVotes:        numOfVoters,
			},
		},
		{
			name: "just enough votes including invalid vote",
			votes: append(copyVotes(votes)[:threshold-1],
				NewInvalidVote(b.GetBlockSn(), b.GetHash(), "invalidId", testKeys.VoterPrivVoteKeys[0]),
			),
			expected: expected{
				notarizeError: ErrNotEnoughVotes,
			},
		},
		{
			name: "just enough votes including invalid sn vote",
			votes: append(copyVotes(votes)[:threshold-1],
				NewInvalidVote(b.GetBlockSn().NextS(), b.GetHash(),
					ConsensusIdFromPubKey(&testKeys.VoterPrivVoteKeys[threshold].PublicKey), testKeys.VoterPrivVoteKeys[threshold]),
			),
			expected: expected{
				notarizeError: ErrNotEnoughVotesAfterVerification,
			},
		},
		{
			name: "invalid votes",
			votes: append(copyVotes(votes)[1:],
				NewInvalidVote(b.GetBlockSn(), b.GetHash(), "invalidId", testKeys.VoterPrivVoteKeys[0]),
				NewInvalidVote(b.GetBlockSn(), b.GetHash(), ConsensusIdFromPubKey(testKeys.VoterPrivVoteKeys[0].GetPublicKey()), testKeys.VoterPrivVoteKeys[1]),
			),
			expected: expected{
				notarizeError:    nil,
				nVotes:           numOfVoters - 1,
				missingVoterIdxs: []uint16{0},
			},
		},
		{
			name: "invalid and duplicate votes",
			votes: append(append(
				copyVotes(votes)[1:],
				NewInvalidVote(b.GetBlockSn(), b.GetHash(), "invalidId", testKeys.VoterPrivVoteKeys[0]),
				NewInvalidVote(b.GetBlockSn(), b.GetHash(), ConsensusIdFromPubKey(testKeys.VoterPrivVoteKeys[0].GetPublicKey()), testKeys.VoterPrivVoteKeys[1])),
				votes[0:numOfVoters-1]...,
			),
			expected: expected{
				notarizeError: nil,
				nVotes:        numOfVoters,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			n, err := proposer.Notarize(tt.votes, c)
			if tt.expected.notarizeError != nil {
				req.EqualError(err, fmt.Sprint(tt.expected.notarizeError))
				return
			}
			req.EqualValues(tt.expected.nVotes, n.GetNVote())
			req.Equal(tt.expected.missingVoterIdxs, n.(*notarizationImpl).missingVoterIdxs)
			req.NoError(verifiers[0].VerifyNotarizationWithBlock(n, b))
			req.NoError(verifiers[0].VerifyNotarization(n, c))
		})
	}

	t.Run("BlockHashMismatch", func(t *testing.T) {
		req := require.New(t)
		n := &notarizationImpl{
			blockHash: Hash{},
			sn:        b.GetBlockSn(),
		}
		err = verifiers[0].VerifyNotarizationWithBlock(n, b)
		req.True(strings.HasPrefix(err.Error(), "Blockhash mismatch"))
		err := verifiers[0].VerifyNotarization(n, c)
		req.True(strings.HasPrefix(err.Error(), "Blockhash mismatch"))
	})

	t.Run("AggSig is Fake, and Cache", func(t *testing.T) {
		req := require.New(t)
		n := &notarizationImpl{
			blockHash: b.GetHash(),
			sn:        b.GetBlockSn(),
			aggSig:    testKeys.VoterPrivVoteKeys[0].Sign([]byte{}),
		}
		err = verifiers[0].VerifyNotarizationWithBlock(n, b)
		req.Error(err)
		req.Equal(err, ErrBadSig)

		err := verifiers[0].VerifyNotarization(n, c)
		req.Error(err)
		req.Equal(err, ErrBadSig)
	})
}

func TestNewClockMsg(t *testing.T) {
	req := require.New(t)
	testKeys, err := SetupKeys(numOfVoters, numOfProposers)
	req.NoError(err)
	p0 := CreateVerifierForTest("p0", testKeys.ElectionResult, testKeys.ProposerPrivPropKeys[0])
	v0 := CreateVerifierForTest("v0", testKeys.ElectionResult, testKeys.VoterPrivVoteKeys[0])
	e := NewEpoch(1, 2)

	t.Run("NewClockMsg", func(t *testing.T) {
		req := require.New(t)
		c, err := v0.NewClockMsg(e)
		req.NoError(err)
		req.Equal(e, c.GetEpoch())

		err = p0.VerifyClockMsg(c)
		req.NoError(err)
	})

	t.Run("InvalidClockMsg", func(t *testing.T) {
		req := require.New(t)
		sig := testKeys.VoterPrivVoteKeys[0].Sign(e.ToBytes())
		c := &clockMsgImpl{
			epoch:     e,
			signature: sig,
			voterId:   ConsensusIdFromPubKey(testKeys.VoterPrivVoteKeys[1].GetPublicKey()),
		}

		err = p0.VerifyClockMsg(c)
		req.EqualError(err, fmt.Sprint(ErrBadSig))
	})
}

func TestNewClockMsgNota(t *testing.T) {
	req := require.New(t)
	testKeys, err := SetupKeys(numOfVoters, numOfProposers)
	req.NoError(err)
	proposer := CreateVerifierForTest("p0", testKeys.ElectionResult, testKeys.ProposerPrivPropKeys[0])
	verifiers := make([]Verifier, numOfVoters)
	for i := 0; i < numOfVoters; i++ {
		verifiers[i] = CreateVerifierForTest(fmt.Sprintf("v%d", i), testKeys.ElectionResult, testKeys.VoterPrivVoteKeys[i])
	}

	e := NewEpoch(1, 2)
	clocks := make([]ClockMsg, numOfVoters)
	for i := 0; i < numOfVoters; i++ {
		clocks[i] = NewClockMsgImpl(e, testKeys.VoterPrivVoteKeys[i])
	}

	threshold := seatBasedVotingThreshold(numOfVoters)
	type expected struct {
		notarizeError    error
		nVotes           int
		missingVoterIdxs []uint16
	}
	tests := []struct {
		name     string
		clocks   []ClockMsg
		expected expected
	}{
		{
			name:   "not enough clocks",
			clocks: clocks[:threshold-1],
			expected: expected{
				notarizeError: ErrNotEnoughVotes,
			},
		},
		{
			name:   "just enough clocks",
			clocks: clocks[:threshold],
			expected: expected{
				notarizeError: nil,
				nVotes:        threshold,
				missingVoterIdxs: func(begin, end uint16) []uint16 {
					var idxs []uint16
					for i := begin; i < end; i++ {
						idxs = append(idxs, i)
					}
					return idxs
				}(uint16(threshold), numOfVoters),
			},
		},
		{
			name:   "all clocks",
			clocks: clocks,
			expected: expected{
				notarizeError: nil,
				nVotes:        numOfVoters,
			},
		},
		{
			name:   "duplicate clocks",
			clocks: append(copyClks(clocks), clocks...),
			expected: expected{
				notarizeError: nil,
				nVotes:        numOfVoters,
			},
		},
		{
			name: "just enough clocks including invalid id",
			clocks: append(copyClks(clocks)[:threshold-1],
				newInvalidClockMsg(e, "invalidId", testKeys.VoterPrivVoteKeys[0]),
			),
			expected: expected{
				notarizeError: ErrNotEnoughVotes,
			},
		},
		{
			name: "just enough clocks including invalid epoch clock",
			clocks: append(copyClks(clocks)[:threshold-1],
				NewClockMsgImpl(NewEpoch(1, 3), testKeys.VoterPrivVoteKeys[threshold]),
			),
			expected: expected{
				notarizeError: ErrNotEnoughVotesAfterVerification,
			},
		},
		{
			name: "invalid clocks",
			clocks: append(copyClks(clocks)[1:],
				newInvalidClockMsg(e, "invalidId", testKeys.VoterPrivVoteKeys[0]),
				newInvalidClockMsg(e, ConsensusIdFromPubKey(testKeys.VoterPrivVoteKeys[0].GetPublicKey()), testKeys.VoterPrivVoteKeys[1]),
			),
			expected: expected{
				notarizeError:    nil,
				nVotes:           numOfVoters - 1,
				missingVoterIdxs: []uint16{0},
			},
		},
		{
			name: "invalid and duplicate clocks",
			clocks: append(append(
				copyClks(clocks)[1:],
				newInvalidClockMsg(e, "invalidId", testKeys.VoterPrivVoteKeys[0]),
				newInvalidClockMsg(e, ConsensusIdFromPubKey(testKeys.VoterPrivVoteKeys[0].GetPublicKey()), testKeys.VoterPrivVoteKeys[1])),
				clocks[0:numOfVoters]...,
			),
			expected: expected{
				notarizeError: nil,
				nVotes:        numOfVoters,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			n, err := proposer.NewClockMsgNota(tt.clocks)
			if tt.expected.notarizeError != nil {
				req.EqualError(err, fmt.Sprint(tt.expected.notarizeError))
				return
			}
			req.EqualValues(tt.expected.nVotes, n.GetNVote())
			req.Equal(tt.expected.missingVoterIdxs, n.(*clockMsgNotaImpl).missingVoterIdxs)
			req.NoError(verifiers[0].VerifyClockMsgNota(n))
		})
	}
}

func TestSigning(t *testing.T) {
	req := require.New(t)
	testKeys, err := SetupKeys(numOfVoters, numOfProposers)
	req.NoError(err)
	proposer := CreateVerifierForTest("p0", testKeys.ElectionResult, testKeys.ProposerPrivPropKeys[0])
	voter := CreateVerifierForTest("v0", testKeys.ElectionResult, testKeys.VoterPrivVoteKeys[0])
	signer, err := bls.NewSigningKey()
	req.NoError(err)
	bootnode := CreateVerifierForTest("b0", testKeys.ElectionResult, signer)

	testdata := []byte("sign me")

	// Proposer
	aid, signature, err := proposer.Sign(testdata)
	req.NoError(err)
	req.Equal(proposer.(*VerifierImpl).id, aid)

	aid, isConsensusNode, err := voter.VerifySignature(signature, testdata)
	req.NoError(err)
	req.True(isConsensusNode)
	req.Equal(proposer.(*VerifierImpl).id, aid)

	// Voter
	aid, signature, err = voter.Sign(testdata)
	req.NoError(err)
	req.Equal(voter.(*VerifierImpl).id, aid)

	aid, isConsensusNode, err = proposer.VerifySignature(signature, testdata)
	req.NoError(err)
	req.True(isConsensusNode)
	req.Equal(voter.(*VerifierImpl).id, aid)

	// Bootnode / Fullnode
	aid, signature, err = bootnode.Sign(testdata)
	req.NoError(err)
	req.Equal(bootnode.(*VerifierImpl).id, aid)

	aid, isConsensusNode, err = proposer.VerifySignature(signature, testdata)
	req.NoError(err)
	req.False(isConsensusNode)
	req.Equal(bootnode.(*VerifierImpl).id, aid)

	// Invalid case.
	_, _, err = proposer.VerifySignature([]byte("invalid sig"), testdata)
	req.Error(err)

	// Test unexpected scheme.
	sig := testKeys.ProposerPrivPropKeys[0].Sign(testdata)
	sigWithFakeScheme := append([]byte{fakeSignature}, sig.ToBytes()...)
	_, _, err = voter.VerifySignature(sigWithFakeScheme, testdata)
	req.True(strings.HasPrefix(err.Error(), "unexpected signature scheme"), err.Error())
}

func TestVoteCountingScheme(t *testing.T) {
	req := require.New(t)
	testKeys, err := SetupKeys(5, 1)
	req.NoError(err)

	testKeys.ElectionResult.CommInfo.MemberInfo[0].Stake = big.NewInt(300)
	testKeys.ElectionResult.CommInfo.MemberInfo[1].Stake = big.NewInt(300)
	testKeys.ElectionResult.CommInfo.MemberInfo[2].Stake = big.NewInt(100)
	testKeys.ElectionResult.CommInfo.MemberInfo[3].Stake = big.NewInt(100)
	testKeys.ElectionResult.CommInfo.MemberInfo[4].Stake = big.NewInt(100)

	var ids []ConsensusId
	for _, info := range testKeys.ElectionResult.CommInfo.MemberInfo {
		ids = append(ids, ConsensusIdFromPubKey(info.PubVoteKey))
	}

	er1 := NewElectionResultImpl(&testKeys.ElectionResult.CommInfo, Session(1))
	er2 := NewElectionResultImpl(&testKeys.ElectionResult.CommInfo, Session(2))
	er3 := NewElectionResultImpl(&testKeys.ElectionResult.CommInfo, Session(3))
	er4 := NewElectionResultImpl(&testKeys.ElectionResult.CommInfo, Session(4))
	er5 := NewElectionResultImpl(&testKeys.ElectionResult.CommInfo, Session(5))

	// er1 no config, so the vote counting scheme should be by seat
	p := CreateVerifierForTest("p0", er1, testKeys.ProposerPrivPropKeys[0])
	v := p.(*VerifierImpl)
	v.voteCountingSchemeConfig = config.NewStringHardforkConfig("test.voting.scheme", "")
	v.voteCountingSchemeConfig.SetTestValueAtSession("Seat", 2)
	v.voteCountingSchemeConfig.SetTestValueAtSession("Stake", 4)
	v.AddElectionResult(er2) // by seat
	v.AddElectionResult(er3) // by seat
	v.AddElectionResult(er4) // by stake
	v.AddElectionResult(er5) // by stake

	testcases := []struct {
		session Session
		ids     []ConsensusId
		ready   bool
	}{
		{Session(1), []ConsensusId{ids[0], ids[1], ids[2]}, false},
		{Session(1), []ConsensusId{ids[0], ids[1], ids[2], ids[3]}, true},
		{Session(2), []ConsensusId{ids[0], ids[1], ids[2]}, false},
		{Session(2), []ConsensusId{ids[0], ids[1], ids[2], ids[3]}, true},
		{Session(3), []ConsensusId{ids[0], ids[1], ids[2]}, false},
		{Session(3), []ConsensusId{ids[0], ids[1], ids[2], ids[3]}, true},
		{Session(4), []ConsensusId{ids[0]}, false},
		{Session(4), []ConsensusId{ids[0], ids[1]}, true},
		{Session(5), []ConsensusId{ids[0]}, false},
		{Session(5), []ConsensusId{ids[0], ids[1]}, true},
	}

	for i, tc := range testcases {
		t.Run(fmt.Sprintln(i), func(t *testing.T) {
			req := require.New(t)
			got := v.IsReadyToPropose(tc.ids, tc.session)
			req.Equal(tc.ready, got)
		})
	}
}

func BenchmarkProposal(b *testing.B) {
	req := require.New(b)
	testKeys, err := SetupKeys(numOfVoters, numOfProposers)
	req.NoError(err)
	p0 := CreateVerifierForTest("p0", testKeys.ElectionResult, testKeys.ProposerPrivPropKeys[0])
	v0 := CreateVerifierForTest("v0", testKeys.ElectionResult, testKeys.VoterPrivVoteKeys[0])
	blk := newOneBlockFake()

	b.Run("NewProposal", func(b *testing.B) {
		req := require.New(b)
		for i := 0; i < b.N; i++ {
			_, err := p0.(*VerifierImpl).Propose(blk)
			req.NoError(err)
		}
	})

	b.Run("NewProposalP", func(b *testing.B) {
		req := require.New(b)
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := p0.(*VerifierImpl).Propose(blk)
				req.NoError(err)
			}
		})
	})

	p := NewProposalImpl(blk, testKeys.ProposerPrivPropKeys[0])
	b.Run("VerifyProposal", func(b *testing.B) {
		req := require.New(b)
		for i := 0; i < b.N; i++ {
			err := v0.VerifyProposal(p)
			req.NoError(err)
		}
	})

	b.Run("VerifyProposalP", func(b *testing.B) {
		req := require.New(b)
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				err := v0.VerifyProposal(p)
				req.NoError(err)
			}
		})
	})
}

func BenchmarkVote(b *testing.B) {
	req := require.New(b)
	testKeys, err := SetupKeys(numOfVoters, numOfProposers)
	req.NoError(err)
	p0 := CreateVerifierForTest("p0", testKeys.ElectionResult, testKeys.ProposerPrivPropKeys[0])
	v0 := CreateVerifierForTest("v0", testKeys.ElectionResult, testKeys.VoterPrivVoteKeys[0])

	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), k)

	c, err := newBlockChain(hardforkK)
	req.NoError(err)
	blk := newOneBlockFake()
	err = c.InsertBlock(blk, false)
	req.NoError(err)
	p := NewProposalImpl(blk, testKeys.ProposerPrivPropKeys[0])

	b.Run("NewVote", func(b *testing.B) {
		req := require.New(b)
		for i := 0; i < b.N; i++ {
			_, err := v0.Vote(p)
			req.NoError(err)
		}
	})

	b.Run("NewVoteP", func(b *testing.B) {
		req := require.New(b)
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := v0.Vote(p)
				req.NoError(err)
			}
		})
	})

	vote := NewVoteImpl(p, testKeys.VoterPrivVoteKeys[0])
	b.Run("VerifyVote", func(b *testing.B) {
		req := require.New(b)
		for i := 0; i < b.N; i++ {
			err := p0.VerifyVote(vote, c)
			req.NoError(err)
		}
	})

	b.Run("VerifyVoteP", func(b *testing.B) {
		req := require.New(b)
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				err := p0.VerifyVote(vote, c)
				req.NoError(err)
			}
		})
	})
}

func BenchmarkNotarization(b *testing.B) {
	req := require.New(b)
	testKeys, err := SetupKeys(numOfVoters, numOfProposers)
	req.NoError(err)
	p0 := CreateVerifierForTest("p0", testKeys.ElectionResult, testKeys.ProposerPrivPropKeys[0])
	v0 := CreateVerifierForTest("v0", testKeys.ElectionResult, testKeys.VoterPrivVoteKeys[0])

	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), k)

	c, err := newBlockChain(hardforkK)
	req.NoError(err)
	blk := newOneBlockFake()
	err = c.InsertBlock(blk, false)
	req.NoError(err)
	p := NewProposalImpl(blk, testKeys.ProposerPrivPropKeys[0])
	votes := make([]Vote, testKeys.ElectionResult.NumCommittee())
	for i := 0; i < testKeys.ElectionResult.NumCommittee(); i++ {
		votes[i] = NewVoteImpl(p, testKeys.VoterPrivVoteKeys[i])
	}

	b.Run("Notarize", func(b *testing.B) {
		req := require.New(b)
		for i := 0; i < b.N; i++ {
			_, err := p0.Notarize(votes, c)
			req.NoError(err)
		}
	})

	b.Run("NotarizeP", func(b *testing.B) {
		req := require.New(b)
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := p0.Notarize(votes, c)
				req.NoError(err)
			}
		})
	})

	n := NewNotarizationImpl(blk, testKeys.ProposerPrivPropKeys[0], 0, testKeys.VoterPrivVoteKeys, []uint16{})
	b.Run("VerifyNotarization", func(b *testing.B) {
		req := require.New(b)
		for i := 0; i < b.N; i++ {
			err := v0.VerifyNotarization(n, c)
			req.NoError(err)
		}
	})

	b.Run("VerifyNotarizationP", func(b *testing.B) {
		req := require.New(b)
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				err := v0.VerifyNotarization(n, c)
				req.NoError(err)
			}
		})
	})
}

func BenchmarkNewClockMsg(b *testing.B) {
	req := require.New(b)
	testKeys, err := SetupKeys(numOfVoters, numOfProposers)
	req.NoError(err)
	p0 := CreateVerifierForTest("p0", testKeys.ElectionResult, testKeys.ProposerPrivPropKeys[0])
	v0 := CreateVerifierForTest("v0", testKeys.ElectionResult, testKeys.VoterPrivVoteKeys[0])
	e := NewEpoch(1, 2)

	b.Run("NewClockMsg", func(b *testing.B) {
		req := require.New(b)
		for i := 0; i < b.N; i++ {
			_, err := v0.NewClockMsg(e)
			req.NoError(err)
		}
	})

	b.Run("NewClockMsgP", func(b *testing.B) {
		req := require.New(b)
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := v0.NewClockMsg(e)
				req.NoError(err)
			}
		})
	})

	c := NewClockMsgImpl(e, testKeys.VoterPrivVoteKeys[0])
	b.Run("VerifyClockMsg", func(b *testing.B) {
		req := require.New(b)
		for i := 0; i < b.N; i++ {
			err := p0.VerifyClockMsg(c)
			req.NoError(err)
		}
	})

	b.Run("VerifyClockMsgP", func(b *testing.B) {
		req := require.New(b)
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				err := p0.VerifyClockMsg(c)
				req.NoError(err)
			}
		})
	})
}

func BenchmarkNewClockMsgNota(b *testing.B) {
	req := require.New(b)
	testKeys, err := SetupKeys(numOfVoters, numOfProposers)
	req.NoError(err)
	p0 := CreateVerifierForTest("p0", testKeys.ElectionResult, testKeys.ProposerPrivPropKeys[0])
	v0 := CreateVerifierForTest("v0", testKeys.ElectionResult, testKeys.VoterPrivVoteKeys[0])
	e := NewEpoch(1, 2)
	clocks := make([]ClockMsg, testKeys.ElectionResult.NumCommittee())
	for i := 0; i < testKeys.ElectionResult.NumCommittee(); i++ {
		clocks[i] = NewClockMsgImpl(e, testKeys.VoterPrivVoteKeys[i])
	}

	b.Run("NewClockMsgNota", func(b *testing.B) {
		req := require.New(b)
		for i := 0; i < b.N; i++ {
			_, err := p0.NewClockMsgNota(clocks)
			req.NoError(err)
		}
	})

	b.Run("NewClockMsgNotaP", func(b *testing.B) {
		req := require.New(b)
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := p0.NewClockMsgNota(clocks)
				req.NoError(err)
			}
		})
	})

	n := NewClockMsgNotaImpl(e, testKeys.ProposerPrivPropKeys[0], 0, testKeys.VoterPrivVoteKeys, []uint16{})
	b.Run("VerifyClockMsgNota", func(b *testing.B) {
		req := require.New(b)
		for i := 0; i < b.N; i++ {
			err := v0.VerifyClockMsgNota(n)
			req.NoError(err)
		}
	})

	b.Run("VerifyClockMsgNotaP", func(b *testing.B) {
		req := require.New(b)
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				err := v0.VerifyClockMsgNota(n)
				req.NoError(err)
			}
		})
	})
}

func BenchmarkVerifyAndSignUsingBLS(b *testing.B) {
	req := require.New(b)
	testKeys, err := SetupKeys(1, 1)
	req.NoError(err)
	v := CreateVerifierForTest("v0", testKeys.ElectionResult, testKeys.VoterPrivVoteKeys[0])
	pubkey := testKeys.VoterPrivVoteKeys[0].GetPublicKey()
	input := []byte("abc")

	b.Run("Sign", func(b *testing.B) {
		req := require.New(b)
		for i := 0; i < b.N; i++ {
			_, _, err := v.Sign(input)
			req.NoError(err)
		}
	})

	b.Run("Marshal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = pubkey.ToBytes()
		}
	})

	bytes := pubkey.ToBytes()
	b.Run("Unmarshal", func(b *testing.B) {
		req := require.New(b)
		for i := 0; i < b.N; i++ {
			_, err := bls.PublicKeyFromBytes(bytes)
			req.NoError(err)
		}
	})

	_, sig, err := v.Sign(input)
	req.NoError(err)
	b.Run("Verify", func(b *testing.B) {
		req := require.New(b)
		for i := 0; i < b.N; i++ {
			_, isConsensusNode, err := v.VerifySignature(sig, input)
			req.NoError(err)
			req.True(isConsensusNode)
		}
	})
}

func BenchmarkVerifyAndSignUsingECDSA(b *testing.B) {
	req := require.New(b)

	key, err := crypto.GenerateKey()
	req.NoError(err)
	input := []byte("01234567890123456789012345678901")

	b.Run("Sign", func(b *testing.B) {
		req := require.New(b)
		for i := 0; i < b.N; i++ {
			_, err := crypto.Sign(input, key)
			req.NoError(err)
		}
	})

	pubkey := key.PublicKey
	b.Run("Marshal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = crypto.CompressPubkey(&pubkey)
		}
	})

	bytes := crypto.CompressPubkey(&pubkey)
	b.Run("Unmarshal", func(b *testing.B) {
		req := require.New(b)
		for i := 0; i < b.N; i++ {
			_, err := crypto.DecompressPubkey(bytes)
			req.NoError(err)
		}
	})

	sig, err := crypto.Sign(input, key)
	req.NoError(err)
	fmt.Println("sig", len(sig), sig)
	fmt.Println("pubkey", len(bytes), bytes)
	b.Run("Verify", func(b *testing.B) {
		req := require.New(b)
		for i := 0; i < b.N; i++ {
			r := crypto.VerifySignature(bytes, input, sig[:64])
			req.True(r)
		}
	})

	b.Run("VerifyWithSigOnly", func(b *testing.B) {
		req := require.New(b)
		for i := 0; i < b.N; i++ {
			bs, err := crypto.Ecrecover(input, sig)
			req.NoError(err)
			r := crypto.VerifySignature(bs, input, sig[:64])
			req.True(r)
		}
	})
}
