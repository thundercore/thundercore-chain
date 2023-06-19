package consensus

import (
	"math/big"
	"strconv"
	"testing"

	"github.com/ethereum/go-ethereum/thunder/thunderella/config"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/testutils/detector"

	"github.com/stretchr/testify/require"
)

const (
	numOfVoters    = 5
	numOfProposers = 3
	k              = int64(2)
)

// Verify that RoleAssignerImpl implements RoleAssigner interface
var (
	_ = RoleAssigner(&RoleAssignerImpl{})
)

func makeConsensusIdsWithPrefix(num int, prefix string) []ConsensusId {
	strings := []string{}
	for i := 0; i < num; i++ {
		strings = append(strings, prefix+strconv.Itoa(i))
	}

	return MakeConsensusIds(strings...)
}

func TestRoleAssigner(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	e := blockchain.NewEpoch(1, 1)

	proposerIds := makeConsensusIdsWithPrefix(numOfProposers, "p")
	voterIds := makeConsensusIdsWithPrefix(numOfVoters, "v")
	bootnodeIds := makeConsensusIdsWithPrefix(1, "b")
	stakes := MakeStakes(numOfProposers, big.NewInt(int64(100)))

	proposerId := proposerIds[0]
	voterId := voterIds[0]
	bootnodeId := bootnodeIds[0]

	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	p := CreateRoleAssignerForTestWithCommittee("p0", proposerId, false, e.Session, proposerIds, voterIds, stakes, hardforkK, 5)
	v := CreateRoleAssignerForTestWithCommittee("v0", voterId, false, e.Session, proposerIds, voterIds, stakes, hardforkK, 5)
	b := CreateRoleAssignerForTestWithCommittee("b0", bootnodeId, true, e.Session, proposerIds, voterIds, stakes, hardforkK, 5)

	t.Run("IsProposer", func(t *testing.T) {
		detector.SetTrace()
		defer detector.Verify(t)

		req := require.New(t)

		req.True(p.IsProposer(proposerId, e.Session))
		req.False(p.IsProposer(voterId, e.Session))
		req.False(p.IsProposer(bootnodeId, e.Session))
		req.True(p.IsProposer(UseMyId, e.Session))
		req.False(p.IsProposer(UseMyId, e.NextSession().Session))

		req.True(v.IsProposer(proposerId, e.Session))
		req.False(v.IsProposer(voterId, e.Session))
		req.False(v.IsProposer(bootnodeId, e.Session))
		req.False(v.IsProposer(UseMyId, e.Session))
		req.False(v.IsProposer(UseMyId, e.NextSession().Session))

		req.True(b.IsProposer(proposerId, e.Session))
		req.False(b.IsProposer(voterId, e.Session))
		req.False(b.IsProposer(bootnodeId, e.Session))
		req.False(b.IsProposer(UseMyId, e.Session))
		req.False(b.IsProposer(UseMyId, e.NextSession().Session))

	})

	t.Run("IsPrimaryProposer", func(t *testing.T) {
		detector.SetTrace()
		defer detector.Verify(t)

		req := require.New(t)
		for i, id := range proposerIds {
			// Proposers[0] is primary proposer at epoch 1
			req.True(p.IsPrimaryProposer(id, blockchain.NewEpoch(1, uint32(i+1))))
			req.True(v.IsPrimaryProposer(id, blockchain.NewEpoch(1, uint32(i+1))))
			req.True(b.IsPrimaryProposer(id, blockchain.NewEpoch(1, uint32(i+1))))
			// Proposers[0] is not primary proposer at epoch 2
			req.False(p.IsPrimaryProposer(id, blockchain.NewEpoch(1, uint32(i+2))))
			req.False(v.IsPrimaryProposer(id, blockchain.NewEpoch(1, uint32(i+2))))
			req.False(b.IsPrimaryProposer(id, blockchain.NewEpoch(1, uint32(i+2))))
		}

		// Proposers[0] is primary proposer at epoch 4
		req.True(p.IsPrimaryProposer(proposerId, blockchain.NewEpoch(1, 4)))

		req.False(p.IsPrimaryProposer(voterId, e))
		req.False(p.IsPrimaryProposer(bootnodeId, e))
		req.True(p.IsPrimaryProposer(UseMyId, e))
		req.False(p.IsPrimaryProposer(UseMyId, e.NextEpoch()))
		req.False(p.IsPrimaryProposer(UseMyId, e.NextSession()))

		req.False(v.IsPrimaryProposer(voterId, e))
		req.False(v.IsPrimaryProposer(bootnodeId, e))
		req.False(v.IsPrimaryProposer(UseMyId, e))
		req.False(v.IsPrimaryProposer(UseMyId, e.NextEpoch()))
		req.False(v.IsPrimaryProposer(UseMyId, e.NextSession()))

		req.False(b.IsPrimaryProposer(voterId, e))
		req.False(b.IsPrimaryProposer(bootnodeId, e))
		req.False(b.IsPrimaryProposer(UseMyId, e))
		req.False(b.IsPrimaryProposer(UseMyId, e.NextEpoch()))
		req.False(b.IsPrimaryProposer(UseMyId, e.NextSession()))
	})

	t.Run("IsVoter", func(t *testing.T) {
		detector.SetTrace()
		defer detector.Verify(t)

		req := require.New(t)
		req.False(p.IsVoter(proposerId, e.Session))
		req.True(p.IsVoter(voterId, e.Session))
		req.False(p.IsVoter(bootnodeId, e.Session))
		req.False(p.IsVoter(UseMyId, e.Session))
		req.False(p.IsVoter(UseMyId, e.NextSession().Session))

		req.False(v.IsVoter(proposerId, e.Session))
		req.True(v.IsVoter(voterId, e.Session))
		req.False(v.IsVoter(bootnodeId, e.Session))
		req.True(v.IsVoter(UseMyId, e.Session))
		req.False(v.IsVoter(UseMyId, e.NextSession().Session))

		req.False(b.IsVoter(proposerId, e.Session))
		req.True(b.IsVoter(voterId, e.Session))
		req.False(b.IsVoter(bootnodeId, e.Session))
		req.False(b.IsVoter(UseMyId, e.Session))
		req.False(b.IsVoter(UseMyId, e.NextSession().Session))
	})

	t.Run("IsBootnode", func(t *testing.T) {
		detector.SetTrace()
		defer detector.Verify(t)

		req := require.New(t)
		req.False(p.IsBootnode(proposerId))
		req.False(p.IsBootnode(voterId))
		req.False(p.IsBootnode(bootnodeId))
		p.AddBootnode(bootnodeId, bootnodeId)
		req.True(p.IsBootnode(bootnodeId))
		req.False(p.IsBootnode(UseMyId))

		req.False(v.IsBootnode(proposerId))
		req.False(v.IsBootnode(voterId))
		req.False(v.IsBootnode(bootnodeId))
		v.AddBootnode(bootnodeId, bootnodeId)
		req.True(v.IsBootnode(bootnodeId))
		req.False(v.IsBootnode(UseMyId))

		req.False(b.IsBootnode(proposerId))
		req.False(b.IsBootnode(voterId))
		req.True(b.IsBootnode(bootnodeId))
		req.True(b.IsBootnode(UseMyId))
	})

	t.Run("GetNumVoters", func(t *testing.T) {
		detector.SetTrace()
		defer detector.Verify(t)

		req := require.New(t)
		req.Equal(numOfVoters, p.GetNumVoters(e.Session))
		req.Equal(-1, p.GetNumVoters(e.NextSession().Session))

		req.Equal(numOfVoters, v.GetNumVoters(e.Session))
		req.Equal(-1, v.GetNumVoters(e.NextSession().Session))

		req.Equal(numOfVoters, b.GetNumVoters(e.Session))
		req.Equal(-1, b.GetNumVoters(e.NextSession().Session))
	})
}

func TestMultipleRole(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	e := blockchain.NewEpoch(1, 1)

	pb := makeConsensusIdsWithPrefix(3, "pb")
	vb := makeConsensusIdsWithPrefix(3, "vb")
	pv := makeConsensusIdsWithPrefix(3, "pv")
	proposerIds := append(pb, pv...)
	voterIds := append(pv, vb...)
	stakes := MakeStakes(len(proposerIds), big.NewInt(int64(100)))

	pb0 := pb[0]
	vb0 := vb[0]
	pv0 := pv[0]

	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	pbRole := CreateRoleAssignerForTestWithCommittee("pb0", pb0, true, e.Session, proposerIds, voterIds, stakes, hardforkK, 5)
	vbRole := CreateRoleAssignerForTestWithCommittee("vb0", vb0, true, e.Session, proposerIds, voterIds, stakes, hardforkK, 5)
	pvRole := CreateRoleAssignerForTestWithCommittee("pv0", pv0, false, e.Session, proposerIds, voterIds, stakes, hardforkK, 5)

	t.Run("IsProposer", func(t *testing.T) {
		req := require.New(t)

		req.True(pbRole.IsProposer(pb0, e.Session))
		req.False(pbRole.IsProposer(vb0, e.Session))
		req.True(pbRole.IsProposer(pv0, e.Session))
		req.True(pbRole.IsProposer(UseMyId, e.Session))
		req.False(pbRole.IsProposer(UseMyId, e.NextSession().Session))

		req.True(vbRole.IsProposer(pb0, e.Session))
		req.False(vbRole.IsProposer(vb0, e.Session))
		req.True(vbRole.IsProposer(pv0, e.Session))
		req.False(vbRole.IsProposer(UseMyId, e.Session))
		req.False(vbRole.IsProposer(UseMyId, e.NextSession().Session))

		req.True(pvRole.IsProposer(pb0, e.Session))
		req.False(pvRole.IsProposer(vb0, e.Session))
		req.True(pvRole.IsProposer(pv0, e.Session))
		req.True(pvRole.IsProposer(UseMyId, e.Session))
		req.False(pvRole.IsProposer(UseMyId, e.NextSession().Session))
	})

	t.Run("IsPrimaryProposer", func(t *testing.T) {
		req := require.New(t)
		for i, id := range proposerIds {
			// Proposers[0] is primary proposer at epoch 1
			req.True(pbRole.IsPrimaryProposer(id, blockchain.NewEpoch(1, uint32(i+1))))
			req.True(vbRole.IsPrimaryProposer(id, blockchain.NewEpoch(1, uint32(i+1))))
			req.True(pvRole.IsPrimaryProposer(id, blockchain.NewEpoch(1, uint32(i+1))))
			// Proposers[0] is not primary proposer at epoch 2
			req.False(pbRole.IsPrimaryProposer(id, blockchain.NewEpoch(1, uint32(i+2))))
			req.False(vbRole.IsPrimaryProposer(id, blockchain.NewEpoch(1, uint32(i+2))))
			req.False(pvRole.IsPrimaryProposer(id, blockchain.NewEpoch(1, uint32(i+2))))
		}

		// Proposers[0] is primary proposer at epoch 4
		req.True(pbRole.IsPrimaryProposer(proposerIds[0], blockchain.NewEpoch(1, uint32(len(proposerIds)+1))))

		// Proposers[0] is pb0
		req.True(pbRole.IsPrimaryProposer(pb0, e))
		req.False(pbRole.IsPrimaryProposer(vb0, e))
		req.False(pbRole.IsPrimaryProposer(pv0, e))
		req.True(pbRole.IsPrimaryProposer(UseMyId, e))
		req.False(pbRole.IsPrimaryProposer(UseMyId, e.NextEpoch()))
		req.False(pbRole.IsPrimaryProposer(UseMyId, e.NextSession()))

		req.True(vbRole.IsPrimaryProposer(pb0, e))
		req.False(vbRole.IsPrimaryProposer(vb0, e))
		req.False(vbRole.IsPrimaryProposer(UseMyId, e))
		req.False(vbRole.IsPrimaryProposer(UseMyId, e.NextEpoch()))
		req.False(vbRole.IsPrimaryProposer(UseMyId, e.NextSession()))

		req.True(pvRole.IsPrimaryProposer(pb0, e))
		req.False(pvRole.IsPrimaryProposer(vb0, e))
		req.False(pvRole.IsPrimaryProposer(pv0, e))
		req.False(pvRole.IsPrimaryProposer(UseMyId, e))
		req.False(pvRole.IsPrimaryProposer(UseMyId, e.NextEpoch()))
		req.False(pvRole.IsPrimaryProposer(UseMyId, e.NextSession()))
	})

	t.Run("IsVoter", func(t *testing.T) {
		req := require.New(t)
		req.False(pbRole.IsVoter(pb0, e.Session))
		req.True(pbRole.IsVoter(vb0, e.Session))
		req.True(pbRole.IsVoter(pv0, e.Session))
		req.False(pbRole.IsVoter(UseMyId, e.Session))
		req.False(pbRole.IsVoter(UseMyId, e.NextSession().Session))

		req.False(vbRole.IsVoter(pb0, e.Session))
		req.True(vbRole.IsVoter(vb0, e.Session))
		req.True(vbRole.IsVoter(pv0, e.Session))
		req.True(vbRole.IsVoter(UseMyId, e.Session))
		req.False(vbRole.IsVoter(UseMyId, e.NextSession().Session))

		req.False(pvRole.IsVoter(pb0, e.Session))
		req.True(pvRole.IsVoter(vb0, e.Session))
		req.True(pvRole.IsVoter(pv0, e.Session))
		req.True(pvRole.IsVoter(UseMyId, e.Session))
		req.False(pvRole.IsVoter(UseMyId, e.NextSession().Session))
	})

	t.Run("IsBootnode", func(t *testing.T) {
		req := require.New(t)
		req.False(pbRole.IsBootnode(pv0))
		req.False(pbRole.IsBootnode(vb0))
		req.True(pbRole.IsBootnode(pb0))
		pbRole.AddBootnode(vb0, vb0)
		req.True(pbRole.IsBootnode(vb0))
		req.True(pbRole.IsBootnode(UseMyId))

		req.False(vbRole.IsBootnode(pv0))
		req.True(vbRole.IsBootnode(vb0))
		req.False(vbRole.IsBootnode(pb0))
		vbRole.AddBootnode(pb0, pb0)
		req.True(vbRole.IsBootnode(pb0))
		req.True(vbRole.IsBootnode(UseMyId))

		req.False(pvRole.IsBootnode(pv0))
		req.False(pvRole.IsBootnode(vb0))
		req.False(pvRole.IsBootnode(pb0))
		pvRole.AddBootnode(pb0, pb0)
		req.True(pvRole.IsBootnode(pb0))
		pvRole.AddBootnode(vb0, vb0)
		req.True(pvRole.IsBootnode(vb0))
		req.False(pvRole.IsBootnode(UseMyId))
	})

}

func TestShouldRotateProposer(t *testing.T) {
	elecOffsetVal := int64(10)
	e := blockchain.NewEpoch(1, 1)

	proposerIds := makeConsensusIdsWithPrefix(numOfProposers, "p")
	voterIds := makeConsensusIdsWithPrefix(numOfVoters, "v")
	stakes := MakeStakes(numOfProposers, big.NewInt(int64(100)))

	proposerId := proposerIds[0]

	t.Run("Test one proposer", func(t *testing.T) {
		req := require.New(t)
		oneProposer := proposerIds[:1]
		oneStake := stakes[:1]

		hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
		hardforkK.SetTestValueAtSession(int64(k), 0)

		r := CreateRoleAssignerForTestWithCommittee("p0", oneProposer[0], false, e.Session, oneProposer, voterIds, oneStake, hardforkK, elecOffsetVal)

		for e := 1; e < 10; e++ {
			for s := 1; s < 20; s++ {
				sn := blockchain.NewBlockSn(1, uint32(e), uint32(s))
				req.False(r.ExceedEpochMaxAllowedSeq(sn, uint64(1)))
			}
		}
	})

	t.Run("Test balanced stake", func(t *testing.T) {
		req := require.New(t)

		hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
		hardforkK.SetTestValueAtSession(int64(k), 0)

		r := CreateRoleAssignerForTestWithCommittee("p0", proposerId, false, e.Session, proposerIds, voterIds, stakes, hardforkK, elecOffsetVal)

		for e := 1; e < 10; e++ {
			for s := 1; s < 20; s++ {
				sn := blockchain.NewBlockSn(1, uint32(e), uint32(s))
				if s > 4 {
					req.True(r.ExceedEpochMaxAllowedSeq(sn, uint64(1)))
				} else {
					req.False(r.ExceedEpochMaxAllowedSeq(sn, uint64(1)))
				}
			}
		}
	})

	t.Run("Test different stake", func(t *testing.T) {
		req := require.New(t)
		diffStakes := []*big.Int{big.NewInt(20), big.NewInt(30), big.NewInt(50)}

		hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
		hardforkK.SetTestValueAtSession(int64(k), 0)

		r := CreateRoleAssignerForTestWithCommittee("p0", proposerId, false, e.Session, proposerIds, voterIds, diffStakes, hardforkK, elecOffsetVal)

		req.True(r.ExceedEpochMaxAllowedSeq(blockchain.NewBlockSn(1, 1, 3), uint64(1)))
		req.True(r.ExceedEpochMaxAllowedSeq(blockchain.NewBlockSn(1, 1, 5), uint64(1)))
		req.False(r.ExceedEpochMaxAllowedSeq(blockchain.NewBlockSn(1, 1, 1), uint64(1)))
		req.True(r.ExceedEpochMaxAllowedSeq(blockchain.NewBlockSn(1, 2, 4), uint64(1)))
		req.True(r.ExceedEpochMaxAllowedSeq(blockchain.NewBlockSn(1, 2, 5), uint64(1)))
		req.False(r.ExceedEpochMaxAllowedSeq(blockchain.NewBlockSn(1, 2, 2), uint64(1)))
		req.True(r.ExceedEpochMaxAllowedSeq(blockchain.NewBlockSn(1, 3, 8), uint64(1)))
		req.True(r.ExceedEpochMaxAllowedSeq(blockchain.NewBlockSn(1, 3, 10), uint64(1)))
		req.False(r.ExceedEpochMaxAllowedSeq(blockchain.NewBlockSn(1, 3, 3), uint64(1)))
	})
}
