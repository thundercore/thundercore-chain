package consensus

import (
	"testing"

	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/metrics"
	"github.com/ethereum/go-ethereum/thunder/pala/testutils/detector"

	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/stretchr/testify/require"
)

// Verify that ReconfigurerImpl implements Reconfigurer interface
var (
	_ = Reconfigurer(&ReconfigurerImpl{})
)

func newBlockChain(k *config.Int64HardforkConfig) (blockchain.BlockChain, blockchain.Storage, error) {
	s := blockchain.NewStorageFake(k, 10000, nil)
	bc, err := blockchain.NewBlockChainImpl(k, s, blockchain.NewBlockMakerFake(k, 0), &blockchain.BlockFakeDecoder{}, nil, metrics.PalaMetrics{})
	return bc, s, err
}

// prepare n chains, where bcs[i] has finalized chain with session s=i+1 and has existing election result for session s=i+2
func prepareBCs(req *require.Assertions, k *config.Int64HardforkConfig, n uint32) []blockchain.BlockChain {
	bcs := make([]blockchain.BlockChain, n)
	genesis := blockchain.GetGenesisBlockSn()
	for i := uint32(0); i < n; i++ {
		session := i + 1
		nextSession := session + 1
		bc, s, err := newBlockChain(k)
		req.NoError(err)
		testKeys, err := blockchain.SetupKeys(int(numOfVoters+i), int(numOfProposers+i))
		req.NoError(err)
		blockchain.PrepareFakeChain(req, bc, genesis, blockchain.NewEpoch(session, 1), k,
			MakeConsensusIds("v1"),
			[]string{"1", "2", "3", "4"})
		s.(*blockchain.StorageFake).AddCommInfo(blockchain.Session(nextSession), &testKeys.ElectionResult.CommInfo)
		bcs[i] = bc
	}
	return bcs
}

func TestReconfigurer(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)
	testKeys, err := blockchain.SetupKeys(numOfVoters, numOfProposers)
	req.NoError(err)
	r := NewReconfigurerImpl(&ReconfigurerImplCfg{LoggingId: "r"})

	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(1, 0)

	bcs := prepareBCs(req, hardforkK, numOfPreservedERs+1)

	t.Run("UpdateEpochManager", func(t *testing.T) {
		detector.SetTrace()
		defer detector.Verify(t)

		req := require.New(t)
		session := blockchain.Session(1)
		nextSession := session + 1
		memDb := rawdb.NewMemoryDatabase()
		e := blockchain.NewEpochManager(memDb, &blockchain.DataUnmarshallerFake{})
		err := r.UpdateEpochManager(bcs[0], e)
		req.NoError(err)
		req.Equal(blockchain.NewEpoch(uint32(nextSession), 1), e.GetEpoch())
	})

	t.Run("UpdateVerifier", func(t *testing.T) {
		detector.SetTrace()
		defer detector.Verify(t)

		req := require.New(t)
		signer, err := bls.NewSigningKey()
		req.NoError(err)
		v := blockchain.CreateVerifierForTest("v", testKeys.ElectionResult, signer)
		for i := 0; i < numOfPreservedERs+1; i++ {
			session := blockchain.Session(i + 1)
			nextSession := session + 1
			err := r.UpdateVerifier(bcs[i], v)
			req.NoError(err)
			electionResults := v.(*blockchain.VerifierImpl).GetElectionResultsForTest()
			req.True(len(electionResults) <= numOfPreservedERs)
			cachedKey := blockchain.GetCachedkey(numOfVoters+i, numOfProposers+i)
			req.NotNil(cachedKey)
			er, ok := electionResults[nextSession]
			req.True(ok)
			req.True(er.CommInfo.Equals(cachedKey.ElectionResult.CommInfo))
		}
	})

	t.Run("UpdateRoleAssigner", func(t *testing.T) {
		detector.SetTrace()
		defer detector.Verify(t)

		req := require.New(t)
		signer, err := bls.NewSigningKey()
		req.NoError(err)
		id := Id(signer.GetPublicKey())

		hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
		hardforkK.SetTestValueAtSession(2, 0)

		ra := CreateRoleAssignerForTestFromElectionResult("r", testKeys.ElectionResult, id, false, hardforkK, 5)

		for i := 0; i < numOfPreservedERs+1; i++ {
			session := blockchain.Session(i + 1)
			nextSession := session + 1
			req.NoError(err)

			err = r.UpdateRoleAssigner(bcs[i], ra)
			req.NoError(err)
			cachedKey := blockchain.GetCachedkey(numOfVoters+i, numOfProposers+i)
			req.NotNil(cachedKey)

			proposers := ra.(*RoleAssignerImpl).GetCommitteeProposers(nextSession)
			expectedProps := []ConsensusId{}
			for _, p := range cachedKey.ElectionResult.AccelInfo {
				expectedProps = append(expectedProps, blockchain.ConsensusIdFromPubKey(p.PubVoteKey))
			}
			req.Equal(expectedProps, proposers)

			voters := ra.(*RoleAssignerImpl).GetCommitteeVoters(nextSession)
			expectedVoters := []ConsensusId{}
			for _, p := range cachedKey.ElectionResult.MemberInfo {
				expectedVoters = append(expectedVoters, blockchain.ConsensusIdFromPubKey(p.PubVoteKey))
			}
			req.Equal(expectedVoters, voters)
		}
	})
}
