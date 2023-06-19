package consensus

import (
	"flag"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/network"
	"github.com/ethereum/go-ethereum/thunder/pala/testutils/detector"

	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"
)

type nodeConfigForTest struct {
	t          *testing.T
	id         ConsensusId
	k          *config.Int64HardforkConfig
	v          blockchain.Verifier
	r          RoleAssigner
	blockDelay time.Duration
}

type byzantineClientForTest struct {
	// Embed the interface to not implement uninteresting methods.
	byzantineClient
}

var (
	hasRunTestCollectingLateVotes = false
	// run with `go test thunder2/consensus -fake` if desired
	useFake = flag.Bool("fake", false, "use fake components")
)

func createNodeForTest(cfg nodeConfigForTest) (*Actor, ActorConfig) {
	nc := NewActorClientFake(cfg.id)
	chain, err := blockchain.NewBlockChainFakeWithDelay(cfg.k, cfg.blockDelay, 10000)
	require.NoError(cfg.t, err)

	epoch := blockchain.NewEpoch(1, 1)

	nodeCfg := ActorConfig{
		K:           cfg.k,
		LoggingId:   string(cfg.id),
		Chain:       chain,
		ActorClient: nc,
		Role:        cfg.r,
		Verifier:    cfg.v,
		Epoch:       epoch,
	}
	n := NewActor(nodeCfg)
	return &n, nodeCfg
}

type ElectionCfg struct {
	proposerList blockchain.ElectionResultFake
	voterList    blockchain.ElectionResultFake
	bootnodeId   ConsensusId
	testKeys     *blockchain.TestingKeys
	signer       bls.BlsSigner
}

func loggingId(proposerIdx, voterIdx int) string {
	if proposerIdx >= 0 {
		return fmt.Sprintf("p%d", proposerIdx)
	}
	if voterIdx >= 0 {
		return fmt.Sprintf("v%d", voterIdx)
	}
	return ""
}

func newVerifierAndRoleAssigner(
	cfg ElectionCfg, proposerIdx, voterIdx int, fake bool, k *config.Int64HardforkConfig,
) (blockchain.Verifier, RoleAssigner) {
	if !fake && proposerIdx >= 0 && voterIdx >= 0 {
		debug.Bug("unexpected call: proposerIdx and voterIdx cannot be set at the same time")
	}
	lid := loggingId(proposerIdx, voterIdx)
	stopBlockSessionOffset := int64(5)
	isBootnode := false

	if fake {
		var id ConsensusId
		if proposerIdx >= 0 {
			id = cfg.proposerList.GetConsensusIds()[proposerIdx]
		} else if voterIdx >= 0 {
			id = cfg.voterList.GetConsensusIds()[voterIdx]
		}
		verifier := blockchain.NewVerifierFake(id, cfg.proposerList, cfg.voterList)
		role := CreateRoleAssignerForTest(lid, id, isBootnode, k, stopBlockSessionOffset)
		stakes := MakeStakes(len(cfg.proposerList.GetConsensusIds()), big.NewInt(int64(100)))
		for s, end := cfg.proposerList.GetRange(); s <= end; s++ {
			role.(*RoleAssignerImpl).AddSessionCommittee(
				blockchain.Session(s),
				cfg.proposerList.GetConsensusIds(),
				cfg.voterList.GetConsensusIds(),
				stakes,
			)
		}
		return verifier, role
	}

	var signer bls.BlsSigner
	if proposerIdx >= 0 {
		signer = cfg.testKeys.ProposerPrivPropKeys[proposerIdx]
	} else if voterIdx >= 0 {
		signer = cfg.testKeys.VoterPrivVoteKeys[voterIdx]
	} else {
		var err error
		signer, err = bls.NewSigningKey()
		if err == nil {
			debug.Bug("failed to generate bls key: %s", err)
		}
	}
	id := Id(signer.GetPublicKey())
	verifier := blockchain.CreateVerifierForTest(lid, cfg.testKeys.ElectionResult, signer)
	role := CreateRoleAssignerForTest(lid, id, isBootnode, k, stopBlockSessionOffset)
	role.(*RoleAssignerImpl).AddElectionResult(cfg.testKeys.ElectionResult)
	return verifier, role
}

func checkProposerCreateProposal(
	req *require.Assertions, proposer *Actor, client *ActorClientFake,
	b blockchain.Block, fake bool,
) blockchain.Proposal {
	err := proposer.AddBlock(b, BlockCreatedBySelf)
	req.NoError(err)
	m := <-client.MessageChan
	req.Implements((*blockchain.Proposal)(nil), m)
	p := blockchain.MsgToProposal(m, fake)
	req.NotNil(p)

	return p
}

func checkVoterCreateVote(
	req *require.Assertions, voter *Actor, client *ActorClientFake,
	p blockchain.Proposal, fake bool,
) blockchain.Vote {
	dummyMsg := network.Message{}
	err := voter.AddProposal(p, &dummyMsg, BlockCreatedByOther)
	req.NoError(err)
	m := <-client.MessageChan
	req.Implements((*blockchain.Vote)(nil), m)
	v := blockchain.MsgToVote(m, fake)
	req.NotNil(v)

	return v
}

func checkNoMessage(req *require.Assertions, client *ActorClientFake) {
	select {
	case m := <-client.MessageChan:
		req.FailNow("expect no message", m)
	default:
	}
}

func newBlockSn(session, epoch, s uint32) blockchain.BlockSn {
	return blockchain.NewBlockSn(session, epoch, s)
}

func newEpoch(session, e uint32) blockchain.Epoch {
	return blockchain.NewEpoch(session, e)
}

func newBlockFake(
	sn blockchain.BlockSn, parentSn blockchain.BlockSn, nBlock uint64,
	notaSns []blockchain.BlockSn, voterIds []ConsensusId,
) blockchain.Block {
	var notas []blockchain.Notarization
	for _, sn := range notaSns {
		notas = append(notas, blockchain.NewNotarizationFake(sn, voterIds))
	}
	return blockchain.NewBlockFake(sn, parentSn, nBlock, notas, nil, sn.String())
}

//--------------------------------------------------------------------

func (b *byzantineClientForTest) onReceivedProposal(
	n *Actor, p blockchain.Proposal, ctx proposalContext) error {
	return xerrors.New("on purpose")
}

//--------------------------------------------------------------------

// Demonstrate the concept of how to test the protocol step by step.
//
// You can think the testing code simulates one of the possible operation sequences
// of the Mediator.
func TestOneProposerAndOneVoter(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)

	// Prepare
	epoch := blockchain.NewEpoch(1, 1)
	k := uint32(1)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	beginEpoch := blockchain.Epoch{}
	testKeys, err := blockchain.SetupKeys(2, 1)
	req.NoError(err)
	electionCfg := ElectionCfg{
		proposerList: blockchain.NewElectionResultFake(MakeConsensusIds("p1"), beginEpoch.Session, epoch.Session),
		voterList:    blockchain.NewElectionResultFake(MakeConsensusIds("v1"), beginEpoch.Session, epoch.Session),
		testKeys:     testKeys,
	}

	verifier, role := newVerifierAndRoleAssigner(electionCfg, 0, -1, *useFake, hardforkK)
	req.True(role.IsProposer(UseMyId, epoch.Session))
	req.True(role.IsVoter(UseMyId, epoch.Session))
	proposer, cfg := createNodeForTest(nodeConfigForTest{
		t:  t,
		id: "proposer 1",
		k:  hardforkK,
		v:  verifier,
		r:  role,
	})
	proposerMediator := cfg.ActorClient.(*ActorClientFake)
	proposerChain := cfg.Chain

	verifier, role = newVerifierAndRoleAssigner(electionCfg, -1, 1, *useFake, hardforkK)
	req.False(role.IsProposer(UseMyId, epoch.Session))
	req.True(role.IsVoter(UseMyId, epoch.Session))
	voter, cfg := createNodeForTest(nodeConfigForTest{
		t:  t,
		id: "voter 1",
		k:  hardforkK,
		v:  verifier,
		r:  role,
	})
	voterMediator := cfg.ActorClient.(*ActorClientFake)
	voterChain := cfg.Chain

	//
	// Test
	//
	// Simulate how the proposer receives a block from the blockchain
	// and make a new proposal.
	ch, err := proposerChain.StartCreatingNewBlocks(epoch, nil)
	req.NoError(err)
	b := (<-ch).Block

	// Add a block to the proposing node. Expect to see the node broadcasts a proposal.
	p := checkProposerCreateProposal(req, proposer, proposerMediator, b, *useFake)

	// Simulate how the proposer sends the proposal to the voter
	// and receives the vote from the voter.
	v := checkVoterCreateVote(req, voter, voterMediator, p, *useFake)

	err = proposer.AddVote(v)
	req.NoError(err)

	// Expect the proposer creates and broadcasts the notarization.
	m := <-proposerMediator.MessageChan
	req.Implements((*blockchain.Notarization)(nil), m)
	nota := blockchain.MsgToNotarization(m, *useFake)
	req.NotNil(nota)

	err = voter.AddNotarization(nota)
	req.NoError(err)

	// Expect the freshest notarized chain is extended.
	bc := proposerChain
	actual := bc.GetFreshestNotarizedHead()
	req.Equal("0[]->(1,1,1)[]", blockchain.DumpFakeChain(bc, actual, true))

	bc = voterChain
	actual = bc.GetFreshestNotarizedHead()
	req.Equal("0[]->(1,1,1)[]", blockchain.DumpFakeChain(bc, actual, true))

	// Create another new proposal based on a new block.
	b = (<-ch).Block
	p = checkProposerCreateProposal(req, proposer, proposerMediator, b, *useFake)

	v = checkVoterCreateVote(req, voter, voterMediator, p, *useFake)

	err = proposer.AddVote(v)
	req.NoError(err)

	err = proposerChain.StopCreatingNewBlocks(blockchain.WaitingPeriodForStopingNewBlocks)
	req.NoError(err)

	m = <-proposerMediator.MessageChan
	req.Implements((*blockchain.Notarization)(nil), m)
	nota = blockchain.MsgToNotarization(m, *useFake)
	req.NotNil(nota)

	err = voter.AddNotarization(nota)
	req.NoError(err)

	// Expect the freshest notarized chain is extended again.
	bc = proposerChain
	actual = bc.GetFreshestNotarizedHead()
	req.Equal("0[]->(1,1,1)[]->(1,1,2)[(1,1,1)]", blockchain.DumpFakeChain(bc, actual, true))

	bc = voterChain
	actual = bc.GetFreshestNotarizedHead()
	req.Equal("0[]->(1,1,1)[]->(1,1,2)[(1,1,1)]", blockchain.DumpFakeChain(bc, actual, true))
}

func TestSignedBySelf(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)

	// Prepare
	k := uint32(1)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	epoch := blockchain.NewEpoch(1, 1)
	electionCfg := ElectionCfg{
		proposerList: blockchain.NewElectionResultFake(MakeConsensusIds("p1"), 0, 1),
		voterList:    blockchain.NewElectionResultFake(MakeConsensusIds("p1"), 0, 1),
	}
	verifier, role := newVerifierAndRoleAssigner(electionCfg, 0, 0, true, hardforkK)
	proposer, cfg := createNodeForTest(nodeConfigForTest{
		t:  t,
		id: "proposer 1",
		k:  hardforkK,
		v:  verifier,
		r:  role,
	})
	proposerMediator := cfg.ActorClient.(*ActorClientFake)
	proposerChain := cfg.Chain

	//
	// Test
	//
	t.Run("propose, vote and notarize", func(t *testing.T) {
		ch, err := proposerChain.StartCreatingNewBlocks(epoch, nil)
		req.NoError(err)
		b := (<-ch).Block

		err = proposerChain.StopCreatingNewBlocks(blockchain.WaitingPeriodForStopingNewBlocks)
		req.NoError(err)

		err = proposer.AddBlock(b, BlockCreatedBySelf)
		req.NoError(err)
		m := <-proposerMediator.MessageChan
		req.Implements((*blockchain.Proposal)(nil), m)

		m = <-proposerMediator.MessageChan
		req.Implements((*blockchain.Notarization)(nil), m)

		actual := proposerChain.GetFreshestNotarizedHead()
		req.Equal("0[]->(1,1,1)[]", blockchain.DumpFakeChain(proposerChain, actual, true))
	})

	t.Run("timeout", func(t *testing.T) {
		err := proposer.Timeout()
		req.NoError(err)

		// Expect the voter sends a ClockMsg.
		m := <-proposerMediator.MessageChan
		c, ok := m.(*blockchain.ClockMsgFake)
		req.True(ok, m)
		epoch = epoch.NextEpoch()
		req.Equal(epoch, c.GetEpoch())

		// Expect the proposer creates and broadcasts the clock message notarization.
		m = <-proposerMediator.MessageChan
		cNota, ok := m.(*blockchain.ClockMsgNotaFake)
		req.True(ok, m)
		req.Equal(epoch, cNota.GetEpoch())

		// Expect the proposer updates clock message notarization.
		m = <-proposerMediator.MessageChan
		cNota, ok = m.(*blockchain.ClockMsgNotaFake)
		req.True(ok, m)
		req.Equal(epoch, cNota.GetEpoch())
	})
}

func TestVotingRules(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	// Prepare
	const k = uint32(2)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	voterIds := MakeConsensusIds("v1", "v2", "v3")
	setup := func(t *testing.T) (*Actor, blockchain.BlockChain) {
		electionCfg := ElectionCfg{
			proposerList: blockchain.NewElectionResultFake(MakeConsensusIds("p1"), 1, 1),
			voterList:    blockchain.NewElectionResultFake(voterIds, 1, 1),
		}

		verifier, role := newVerifierAndRoleAssigner(electionCfg, -1, 0, true, hardforkK)
		voter, voterCfg := createNodeForTest(nodeConfigForTest{
			t:  t,
			id: "voter 1",
			k:  hardforkK,
			v:  verifier,
			r:  role,
		})
		// blocks: (1,1,1) <- (1,1,2) <- (1,1,3) <- (1,1,4)
		// notas : (1,1,1),   (1,1,2)
		req := require.New(t)
		blockchain.PrepareFakeChain(
			req, voterCfg.Chain, blockchain.GetGenesisBlockSn(), blockchain.NewEpoch(1, 1), hardforkK,
			voterIds, []string{"b1", "b2", "b3", "b4"})
		return voter, voterCfg.Chain
	}

	dummyMsg := network.Message{}
	epoch := blockchain.NewEpoch(1, 1)
	var notaSns []blockchain.BlockSn
	for i := 0; i <= 6; i++ {
		notaSns = append(notaSns, newBlockSn(1, 1, uint32(i)))
	}

	t.Run("different epoch", func(t *testing.T) {
		req := require.New(t)

		voter, chain := setup(t)
		b := newBlockFake(newBlockSn(1, 2, 1), newBlockSn(1, 1, 4), 5, notaSns[3:5], voterIds)
		p := blockchain.NewProposalFake("p1", b)
		err := voter.AddProposal(p, &dummyMsg, BlockCreatedByOther)
		req.Error(err, blockchain.DumpFakeChain(chain, chain.GetFreshestNotarizedHead(), true))
	})

	epoch = epoch.NextEpoch()

	t.Run("proposer's head is fresher", func(t *testing.T) {
		req := require.New(t)

		voter, chain := setup(t)
		voter.SetEpoch(epoch)
		b := newBlockFake(newBlockSn(1, 2, 1), newBlockSn(1, 1, 5), 6, notaSns[4:6], voterIds)
		p := blockchain.NewProposalFake("p1", b)
		err := voter.AddProposal(p, &dummyMsg, BlockCreatedByOther)
		req.Error(err, blockchain.DumpFakeChain(chain, chain.GetFreshestNotarizedHead(), true))
	})

	t.Run("voters' head is fresher", func(t *testing.T) {
		req := require.New(t)

		voter, chain := setup(t)
		voter.SetEpoch(epoch)
		b := newBlockFake(newBlockSn(1, 2, 1), newBlockSn(1, 1, 1), 3, notaSns[1:2], voterIds)
		p := blockchain.NewProposalFake("p1", b)
		err := voter.AddProposal(p, &dummyMsg, BlockCreatedByOther)
		req.Error(err, blockchain.DumpFakeChain(chain, chain.GetFreshestNotarizedHead(), true))
	})

	t.Run("proposer's BlockSn is out of order", func(t *testing.T) {
		req := require.New(t)

		voter, chain := setup(t)

		b := newBlockFake(newBlockSn(1, 1, 6), newBlockSn(1, 1, 2), 6, nil, voterIds)
		p := blockchain.NewProposalFake("p1", b)
		err := voter.AddProposal(p, &dummyMsg, BlockCreatedByOther)
		req.Error(err, blockchain.DumpFakeChain(chain, chain.GetFreshestNotarizedHead(), true))

		b = newBlockFake(newBlockSn(1, 1, 5), newBlockSn(1, 1, 6), 6, notaSns[3:5], voterIds)
		p = blockchain.NewProposalFake("p1", b)
		err = voter.AddProposal(p, &dummyMsg, BlockCreatedByOther)
		req.Error(err, blockchain.DumpFakeChain(chain, chain.GetFreshestNotarizedHead(), true))

		voter.SetEpoch(epoch)
		b = newBlockFake(newBlockSn(1, 2, 2), newBlockSn(1, 1, 2), 6, nil, voterIds)
		p = blockchain.NewProposalFake("p1", b)
		err = voter.AddProposal(p, &dummyMsg, BlockCreatedByOther)
		req.Error(err, blockchain.DumpFakeChain(chain, chain.GetFreshestNotarizedHead(), true))
	})

	t.Run("proposer's BlockSn exceeds the unnotarized window", func(t *testing.T) {
		req := require.New(t)

		voter, chain := setup(t)

		// Fail because it doesn't follow the rule to include notarization (1,1,3).
		b := newBlockFake(newBlockSn(1, 1, 5), newBlockSn(1, 1, 4), 6, nil, voterIds)
		p := blockchain.NewProposalFake("p1", b)
		err := voter.AddProposal(p, &dummyMsg, BlockCreatedByOther)
		req.Error(err, blockchain.DumpFakeChain(chain, chain.GetFreshestNotarizedHead(), true))

		// Okay because the notarization (1,1,3) is included.
		b = newBlockFake(newBlockSn(1, 1, 5), newBlockSn(1, 1, 4), 6, notaSns[3:4], voterIds)
		p = blockchain.NewProposalFake("p1", b)
		err = voter.AddProposal(p, &dummyMsg, BlockCreatedByOther)
		req.NoError(err, blockchain.DumpFakeChain(chain, chain.GetFreshestNotarizedHead(), true))
	})

	t.Run("valid proposal includes the missing notarizations", func(t *testing.T) {
		req := require.New(t)

		voter, chain := setup(t)
		voter.SetEpoch(epoch)
		b := newBlockFake(newBlockSn(1, 2, 1), newBlockSn(1, 1, 4), 5, notaSns[3:5], voterIds)
		p := blockchain.NewProposalFake("p1", b)
		err := voter.AddProposal(p, &dummyMsg, BlockCreatedByOther)
		req.NoError(err, blockchain.DumpFakeChain(chain, chain.GetFreshestNotarizedHead(), true))
	})

	t.Run("same head but different hash", func(t *testing.T) {
		req := require.New(t)

		voter, chain := setup(t)
		b := newBlockFake(newBlockSn(1, 1, 5), newBlockSn(1, 1, 4), 5, notaSns[3:4], voterIds)
		p := blockchain.NewProposalFake("p1", b)
		bf := p.GetBlock().(*blockchain.BlockFake)
		var h blockchain.Hash
		copy(h[:], newBlockSn(1, 1, 3).ToBytes())
		bf.SetParentHash(h)
		err := voter.AddProposal(p, &dummyMsg, BlockCreatedByOther)
		req.Error(err, blockchain.DumpFakeChain(chain, chain.GetFreshestNotarizedHead(), true))
	})

}

func TestInconsistentBlock(t *testing.T) {
	// Scenario: The node N (a bootnode or voter) receives a proposal P1 with sn = (1,1,1).
	// The proposer crashes and immediately restarts. Then it proposes the same proposal P1' with
	// the same sn (1,1,1) but different content. The node N will reject the proposal because
	// the block hash is different. There are two possible cases afterward:
	// 1. P1' is not notarized. N will receive a new proposal (1,2,1) after a timeout and
	//    everything is fine since (1,1,1) is skipped.
	// 2. P1' is notarized. Since the notarization reflects the majority's view, N should replace
	//    the block of P1 by the block of P1'; otherwise, it cannot move forward.
	//
	// This test represents the case 2.
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)

	// Prepare
	const k = uint32(2)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	voterIds := MakeConsensusIds("v1", "v2", "v3")
	electionCfg := ElectionCfg{
		proposerList: blockchain.NewElectionResultFake(MakeConsensusIds("p1"), 1, 1),
		voterList:    blockchain.NewElectionResultFake(voterIds, 1, 1),
	}

	verifier, role := newVerifierAndRoleAssigner(electionCfg, -1, -1, true, hardforkK)
	voter, voterCfg := createNodeForTest(nodeConfigForTest{
		t:  t,
		id: "bootnode 1",
		k:  hardforkK,
		v:  verifier,
		r:  role,
	})

	dummyMsg := network.Message{}

	// Initial state.
	b := voterCfg.Chain.GetBlockByNumber(1)
	req.Nil(b)

	// Add the proposal P1 (1,1,1)
	sn := newBlockSn(1, 1, 1)
	b = newBlockFake(sn, blockchain.GetGenesisBlockSn(), 1, nil, nil)
	var h blockchain.Hash
	copy(h[:], []byte("012345"))
	b.(*blockchain.BlockFake).SetHash(h)
	p := blockchain.NewProposalFake("p1", b)
	err := voter.AddProposal(p, &dummyMsg, BlockCreatedByOther)
	req.NoError(err)

	// Add the proposal P1' (1,1,1) with different content.
	b2 := newBlockFake(sn, blockchain.GetGenesisBlockSn(), 1, nil, nil)
	p = blockchain.NewProposalFake("p1", b2)
	err = voter.AddProposal(p, &dummyMsg, BlockCreatedByOther)
	req.Error(err)

	// Add n1 and the notarization of n1.
	nota := blockchain.NewNotarizationFake(sn, voterIds)
	_, _, err = voter.AddNotarizedBlocks(
		[]blockchain.Notarization{nota}, []blockchain.Block{b2})
	req.NoError(err)

	b = voterCfg.Chain.GetBlockByNumber(1)
	req.NotNil(b)
	req.Equal(sn, b.GetBlockSn())
	req.Equal(b2, b)
}

func TestCollectingLateVotes(t *testing.T) {
	// not using real implementation for this since there would be timing issues and
	// CollectingLateVotes' logic is not related to verifier and role assigner
	if hasRunTestCollectingLateVotes {
		return
	}
	hasRunTestCollectingLateVotes = true

	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)

	// Prepare
	epoch := blockchain.NewEpoch(1, 1)
	k := uint32(2)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	voterIds := MakeConsensusIds("v1", "v2", "v3")
	beginEpoch := blockchain.Epoch{}

	electionCfg := ElectionCfg{
		proposerList: blockchain.NewElectionResultFake(MakeConsensusIds("p1"), beginEpoch.Session, epoch.Session),
		voterList:    blockchain.NewElectionResultFake(voterIds, beginEpoch.Session, epoch.Session),
	}

	verifier, role := newVerifierAndRoleAssigner(electionCfg, 0, -1, true, hardforkK)
	proposer, cfg := createNodeForTest(nodeConfigForTest{
		t:  t,
		id: "p1",
		k:  hardforkK,
		v:  verifier,
		r:  role,
		// Need a delay to collect late votes.
		blockDelay: time.Duration(100) * time.Millisecond,
	})
	proposerMediator := cfg.ActorClient.(*ActorClientFake)
	proposerChain := cfg.Chain

	//
	// Test
	//
	// Simulate how the proposer receives a block from the blockchain
	// and make a new proposal.
	ch, err := proposerChain.StartCreatingNewBlocks(epoch, nil)
	defer proposerChain.StopCreatingNewBlocks(blockchain.WaitingPeriodForStopingNewBlocks)
	req.NoError(err)
	b := (<-ch).Block

	// Add a block to the proposing node. Expect to see the node broadcasts a proposal.
	p := checkProposerCreateProposal(req, proposer, proposerMediator, b, true)

	// Simulate how the proposer receives votes from the voters.
	firstBlockSn := p.GetBlockSn()
	for _, id := range voterIds {
		v := blockchain.NewVoteFake(firstBlockSn, id)
		err = proposer.AddVote(v)
		req.NoError(err)
	}

	// Expect the proposer creates and broadcasts the notarization.
	m := <-proposerMediator.MessageChan
	nota, ok := m.(*blockchain.NotarizationFake)
	req.True(ok)
	// Once the proposer receives enough votes, it broadcasts the notarization immediately.
	req.Equal(uint16(2), nota.GetNVote())

	// Create the second proposal based on a new block.
	b = (<-ch).Block
	p = checkProposerCreateProposal(req, proposer, proposerMediator, b, true)

	// Expect there is no notarization.
	b = p.GetBlock()
	req.NotNil(b)
	decoder := blockchain.NewBlockFakeDecoder()
	notas := decoder.GetNotarizations(b, nil)
	req.Equal(0, len(notas))

	// Create the third proposal based on a new block.
	b = (<-ch).Block
	p = checkProposerCreateProposal(req, proposer, proposerMediator, b, true)

	// Expect the notarization in the proposal has full votes.
	b = p.GetBlock()
	req.NotNil(b)
	notas = decoder.GetNotarizations(b, nil)
	req.Equal(1, len(notas))
	req.Equal(firstBlockSn, notas[0].GetBlockSn())
	req.Equal(voterIds, notas[0].(*blockchain.NotarizationFake).GetVoterIds())
}
func TestInvalidVote(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)

	// Prepare
	epoch := blockchain.NewEpoch(1, 1)
	k := uint32(1)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	voterIds := MakeConsensusIds("v1", "v2", "v3")
	beginEpoch := blockchain.Epoch{}
	testKeys, err := blockchain.SetupKeys(len(voterIds), 1)
	req.NoError(err)
	electionCfg := ElectionCfg{
		proposerList: blockchain.NewElectionResultFake(MakeConsensusIds("p1"), beginEpoch.Session, epoch.Session),
		voterList:    blockchain.NewElectionResultFake(voterIds, beginEpoch.Session, epoch.Session),
		testKeys:     testKeys,
	}

	verifier, role := newVerifierAndRoleAssigner(electionCfg, 0, -1, *useFake, hardforkK)
	proposer, cfg := createNodeForTest(nodeConfigForTest{
		t:  t,
		id: "p1",
		k:  hardforkK,
		v:  verifier,
		r:  role,
		// Need a delay to collect late votes.
		blockDelay: time.Duration(100) * time.Millisecond,
	})
	proposerMediator := cfg.ActorClient.(*ActorClientFake)
	proposerChain := cfg.Chain

	//
	// Test
	//
	// Simulate how the proposer receives a block from the blockchain
	// and make a new proposal.
	ch, err := proposerChain.StartCreatingNewBlocks(epoch, nil)
	defer proposerChain.StopCreatingNewBlocks(blockchain.WaitingPeriodForStopingNewBlocks)
	req.NoError(err)
	b := (<-ch).Block

	// Add a block to the proposing node. Expect to see the node broadcasts a proposal.
	p := checkProposerCreateProposal(req, proposer, proposerMediator, b, *useFake)

	// Simulate how the proposer receives votes from the voters.
	// valid vote
	firstBlockSn := p.GetBlockSn()
	var v blockchain.Vote
	if *useFake {
		v = blockchain.NewVoteFake(firstBlockSn, voterIds[0])
	} else {
		v = blockchain.NewVoteImpl(p, testKeys.VoterPrivVoteKeys[0])
	}
	err = proposer.AddVote(v)
	req.NoError(err)

	// invalid vote
	invalidId := ConsensusId("invalidId")
	if *useFake {
		v = blockchain.NewVoteFake(firstBlockSn, invalidId)
	} else {
		v = blockchain.NewInvalidVote(p.GetBlockSn(), p.GetBlock().GetHash(), invalidId, testKeys.VoterPrivVoteKeys[1])
	}
	err = proposer.AddVote(v)
	// No error since vote is not verified, but neither a notarization is created
	req.NoError(err)
	checkNoMessage(req, proposerMediator)

	// valid vote
	if *useFake {
		v = blockchain.NewVoteFake(firstBlockSn, voterIds[2])
	} else {
		v = blockchain.NewVoteImpl(p, testKeys.VoterPrivVoteKeys[2])
	}
	err = proposer.AddVote(v)
	req.NoError(err)

	// Expect the proposer creates and broadcasts the notarization.
	m := <-proposerMediator.MessageChan
	req.Implements((*blockchain.Notarization)(nil), m)
	nota := blockchain.MsgToNotarization(m, *useFake)
	req.NotNil(nota)
	req.Equal(uint16(2), nota.GetNVote())
}

func TestInsertBlockWithoutParent(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)

	// Prepare
	k := uint32(1)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	beginEpoch := blockchain.Epoch{}
	epoch := blockchain.NewEpoch(1, 1)
	testKeys, err := blockchain.SetupKeys(1, 1)
	req.NoError(err)
	electionCfg := ElectionCfg{
		proposerList: blockchain.NewElectionResultFake(MakeConsensusIds("p1"), beginEpoch.Session, epoch.Session),
		voterList:    blockchain.NewElectionResultFake(MakeConsensusIds("v1"), beginEpoch.Session, epoch.Session),
		testKeys:     testKeys,
	}
	proposerSigner := testKeys.ProposerPrivPropKeys[0]

	verifier, role := newVerifierAndRoleAssigner(electionCfg, -1, 0, *useFake, hardforkK)
	voter, cfg := createNodeForTest(nodeConfigForTest{
		t:  t,
		id: "voter 1",
		k:  hardforkK,
		v:  verifier,
		r:  role,
	})
	voterMediator := cfg.ActorClient.(*ActorClientFake)

	// Simulate how the proposer sends the proposal to the voter
	dummyMsg := network.Message{}
	sn := blockchain.NewBlockSn(1, 1, 10)
	parentSn := blockchain.NewBlockSn(1, 1, 9)
	b := blockchain.NewBlockFake(sn, parentSn, 11, nil, nil, "data")
	var p blockchain.Proposal
	if *useFake {
		p = blockchain.NewProposalFake("p1", b)
	} else {
		p = blockchain.NewProposalImpl(b, proposerSigner)
	}
	err = voter.AddProposal(p, &dummyMsg, BlockCreatedByOther)

	// Expect the voter fails to vote the proposal and requests catching up.
	req.Error(err)
	select {
	case catchUpSn := <-voterMediator.CatchUpChan:
		req.Equal(parentSn, catchUpSn)
	case <-time.After(100 * time.Millisecond):
		req.Fail("no catch up event")
	}
}

func TestAdvancingLocalEpoch(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)

	// Prepare
	epoch := blockchain.NewEpoch(1, 1)
	k := uint32(1)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	beginEpoch := blockchain.Epoch{}
	endEpoch := blockchain.NewEpoch(1, 10)
	electionCfg := ElectionCfg{
		proposerList: blockchain.NewElectionResultFake(MakeConsensusIds("p1", "p2"), beginEpoch.Session, endEpoch.Session),
		voterList:    blockchain.NewElectionResultFake(MakeConsensusIds("v1"), beginEpoch.Session, endEpoch.Session),
	}

	verifier, role := newVerifierAndRoleAssigner(electionCfg, 1, -1, true, hardforkK)
	proposer2, cfg := createNodeForTest(nodeConfigForTest{
		t:  t,
		id: "proposer 1",
		k:  hardforkK,
		v:  verifier,
		r:  role,
	})
	proposerMediator2 := cfg.ActorClient.(*ActorClientFake)
	proposer2Chain := cfg.Chain

	verifier, role = newVerifierAndRoleAssigner(electionCfg, -1, 0, true, hardforkK)
	voter, cfg := createNodeForTest(nodeConfigForTest{
		t:  t,
		id: "voter 1",
		k:  hardforkK,
		v:  verifier,
		r:  role,
	})
	voterMediator := cfg.ActorClient.(*ActorClientFake)
	voterChain := cfg.Chain

	//
	// Test
	//
	epoch = epoch.NextEpoch()
	err := voter.Timeout()
	req.NoError(err)
	// Expect the voter sends a ClockMsg.
	m := <-voterMediator.MessageChan
	c, ok := m.(*blockchain.ClockMsgFake)
	req.True(ok, m)
	req.Equal(epoch, c.GetEpoch())

	err = proposer2.AddClockMsg(c)
	req.NoError(err)

	// Expect the proposer creates and broadcasts the clock message notarization.
	m = <-proposerMediator2.MessageChan
	cNota, ok := m.(*blockchain.ClockMsgNotaFake)
	req.True(ok, m)
	req.Equal(epoch, cNota.GetEpoch())

	// Expect the proposer updates clock message notarization.
	m = <-proposerMediator2.MessageChan
	cNota, ok = m.(*blockchain.ClockMsgNotaFake)
	req.True(ok, m)
	req.Equal(epoch, cNota.GetEpoch())
	proposer2.SetEpoch(epoch)

	// Pass the clock message notarization to the voter.
	err = voter.AddClockMsgNota(cNota)
	req.NoError(err)
	m = <-voterMediator.MessageChan
	cNota, ok = m.(*blockchain.ClockMsgNotaFake)
	req.True(ok, m)
	voter.SetEpoch(cNota.GetEpoch())

	// Simulate how the proposer receives a block from the blockchain
	// and make a new proposal.
	ch, err := proposer2Chain.StartCreatingNewBlocks(epoch, cNota)
	defer proposer2Chain.StopCreatingNewBlocks(blockchain.WaitingPeriodForStopingNewBlocks)
	req.NoError(err)
	b := (<-ch).Block

	// Add a block to the proposing node. Expect to see the node broadcasts a proposal.
	p := checkProposerCreateProposal(req, proposer2, proposerMediator2, b, true)

	// Simulate how the proposer sends the proposal to the voter
	// and receives the vote from the voter.
	v := checkVoterCreateVote(req, voter, voterMediator, p, true)

	err = proposer2.AddVote(v)
	req.NoError(err)

	// Expect the proposer creates and broadcasts the notarization.
	m = <-proposerMediator2.MessageChan
	nota, ok := m.(*blockchain.NotarizationFake)
	req.True(ok, m)

	err = voter.AddNotarization(nota)
	req.NoError(err)

	// Expect the freshest notarized chain is extended.
	bc := proposer2Chain
	actual := bc.GetFreshestNotarizedHead()
	req.Equal("0[]->(1,2,1)[]", blockchain.DumpFakeChain(bc, actual, true))

	bc = voterChain
	actual = bc.GetFreshestNotarizedHead()
	req.Equal("0[]->(1,2,1)[]", blockchain.DumpFakeChain(bc, actual, true))
}

func TestAdvancingLocalEpochByNotarizedBlocks(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)

	// Prepare
	k := uint32(1)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	electionCfg := ElectionCfg{
		proposerList: blockchain.NewElectionResultFake(MakeConsensusIds("p1"), 1, 1),
		voterList:    blockchain.NewElectionResultFake(MakeConsensusIds("v1"), 1, 1),
	}

	verifier, role := newVerifierAndRoleAssigner(electionCfg, -1, 0, true, hardforkK)
	voter, cfg := createNodeForTest(nodeConfigForTest{
		t:  t,
		id: "voter 1",
		k:  hardforkK,
		v:  verifier,
		r:  role,
	})
	voterMediator := cfg.ActorClient.(*ActorClientFake)

	sn := blockchain.NewBlockSn(1, 2, 1)
	parentSn := blockchain.GetGenesisBlockSn()
	voterIds := []ConsensusId{"v1"}
	notas := []blockchain.Notarization{
		blockchain.NewNotarizationFake(sn, voterIds),
	}
	bs := []blockchain.Block{
		blockchain.NewBlockFake(
			sn, parentSn, 1, nil,
			blockchain.NewClockMsgNotaFake(sn.Epoch, voterIds),
			"some-value"),
	}

	// Pass the notarized block to the voter.
	_, _, err := voter.AddNotarizedBlocks(notas, bs)
	req.NoError(err)
	select {
	case m := <-voterMediator.MessageChan:
		cNota, ok := m.(*blockchain.ClockMsgNotaFake)
		req.True(ok, m)
		req.Equal(sn.Epoch, cNota.GetBlockSn().Epoch)
	case <-time.After(100 * time.Millisecond):
		req.FailNow("UpdateEpoch is not called")
	}
}

func TestActorCatchUpAndVote(t *testing.T) {
	// Scenario: the voter receives proposals but it's behind.
	// Verify the voter will vote previous unnotarized proposals after it catches up.
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	setup := func(k uint32, req *require.Assertions) (
		*Actor, *ActorClientFake, []blockchain.Proposal, []blockchain.Notarization,
	) {
		// Prepare proposer/voter.
		epoch := blockchain.NewEpoch(1, 1)
		voterIds := MakeConsensusIds("v1", "v2", "v3")
		electionCfg := ElectionCfg{
			proposerList: blockchain.NewElectionResultFake(MakeConsensusIds("p1"), 1, 1),
			voterList:    blockchain.NewElectionResultFake(voterIds, 1, 1),
		}

		hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
		hardforkK.SetTestValueAtSession(int64(k), 0)

		verifier, role := newVerifierAndRoleAssigner(electionCfg, 0, -1, true, hardforkK)
		proposer, cfg := createNodeForTest(nodeConfigForTest{
			t:  t,
			id: "proposer 1",
			k:  hardforkK,
			v:  verifier,
			r:  role,
		})
		proposerMediator := cfg.ActorClient.(*ActorClientFake)
		proposerChain := cfg.Chain

		verifier, role = newVerifierAndRoleAssigner(electionCfg, -1, 0, true, hardforkK)
		voter, cfg := createNodeForTest(nodeConfigForTest{
			t:  t,
			id: "voter 1",
			k:  hardforkK,
			v:  verifier,
			r:  role,
		})
		voterMediator := cfg.ActorClient.(*ActorClientFake)

		// Prepare k proposals.
		var proposals []blockchain.Proposal
		var notarizations []blockchain.Notarization
		ch, err := proposerChain.StartCreatingNewBlocks(epoch, nil)
		req.NoError(err)
		defer proposerChain.StopCreatingNewBlocks(blockchain.WaitingPeriodForStopingNewBlocks)
		for i := 0; i < int(k); i++ {
			b := (<-ch).Block
			p := checkProposerCreateProposal(req, proposer, proposerMediator, b, true)
			proposals = append(proposals, p)

			// Add votes from voters except v1.
			for _, id := range voterIds[1:] {
				v := blockchain.NewVoteFake(p.GetBlockSn(), id)
				err = proposer.AddVote(v)
				req.NoError(err)
			}
			// Expect the proposer creates and broadcasts the notarization.
			m := <-proposerMediator.MessageChan
			nota, ok := m.(*blockchain.NotarizationFake)
			req.True(ok)
			// Once the proposer receives enough votes, it broadcasts the notarization immediately.
			req.Equal(uint16(2), nota.GetNVote())
			notarizations = append(notarizations, nota)
		}

		// Prepare another k proposals.
		for i := 0; i < int(k); i++ {
			b := (<-ch).Block
			p := checkProposerCreateProposal(req, proposer, proposerMediator, b, true)
			proposals = append(proposals, p)
		}

		// Send proposals to the voter when its status is behind.
		// Expect the voter responds a temporary error.
		for _, p := range proposals[1:] {
			dummyMsg := network.Message{}
			err := voter.AddProposal(p, &dummyMsg, BlockCreatedByOther)
			req.Error(err)
			te, ok := err.(utils.TemporaryError)
			req.True(ok)
			req.True(te.IsTemporary())
		}

		return voter, voterMediator, proposals, notarizations
	}

	t.Run("k=1", func(t *testing.T) {
		req := require.New(t)
		k := uint32(1)
		voter, voterMediator, proposals, notarizations := setup(k, req)
		// Add notarized block (1,1,1) and expect the voter votes.
		voter.AddNotarizedBlocks(
			[]blockchain.Notarization{notarizations[0]},
			[]blockchain.Block{proposals[0].GetBlock()},
		)
		voter.AddFreshestNotarizedChainExtendedEvent(
			blockchain.FreshestNotarizedChainExtendedEvent{proposals[0].GetBlockSn()})
		sn := proposals[1].GetBlockSn()
		select {
		case m := <-voterMediator.MessageChan:
			v, ok := m.(blockchain.Vote)
			req.True(ok)
			req.Equal(sn, v.GetBlockSn())
		default:
			req.FailNow(fmt.Sprintf("no vote for %s", sn))
		}

		checkNoMessage(req, voterMediator)
	})
	t.Run("k=2", func(t *testing.T) {
		req := require.New(t)
		k := uint32(2)
		voter, voterMediator, proposals, notarizations := setup(k, req)
		// Add notarized block (1,1,1) and expect the voter has no action
		// because the voter only keeps the last k proposals.
		voter.AddNotarizedBlocks(
			[]blockchain.Notarization{notarizations[0]},
			[]blockchain.Block{proposals[0].GetBlock()},
		)
		voter.AddFreshestNotarizedChainExtendedEvent(
			blockchain.FreshestNotarizedChainExtendedEvent{proposals[0].GetBlockSn()})
		checkNoMessage(req, voterMediator)

		// Add notarized block (1,1,2) and expect the voter votes.
		voter.AddNotarizedBlocks(
			[]blockchain.Notarization{notarizations[1]},
			[]blockchain.Block{proposals[1].GetBlock()},
		)
		voter.AddFreshestNotarizedChainExtendedEvent(
			blockchain.FreshestNotarizedChainExtendedEvent{proposals[1].GetBlockSn()})
		for i := 0; i < int(k); i++ {
			sn := proposals[2+i].GetBlockSn()
			select {
			case m := <-voterMediator.MessageChan:
				v, ok := m.(blockchain.Vote)
				req.True(ok)
				req.Equal(sn, v.GetBlockSn())
			default:
				req.FailNow(fmt.Sprintf("no vote for %s", sn))
			}
		}

		checkNoMessage(req, voterMediator)
	})
}

func TestByzantineClient(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)

	// Prepare a voter.
	epoch := blockchain.NewEpoch(1, 1)
	k := uint32(1)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	beginEpoch := blockchain.Epoch{}
	testKeys, err := blockchain.SetupKeys(1, 1)
	req.NoError(err)
	electionCfg := ElectionCfg{
		proposerList: blockchain.NewElectionResultFake(MakeConsensusIds("p1"), beginEpoch.Session, epoch.Session),
		voterList:    blockchain.NewElectionResultFake(MakeConsensusIds("v1"), beginEpoch.Session, epoch.Session),
		testKeys:     testKeys,
	}
	proposerSigner := testKeys.ProposerPrivPropKeys[0]

	verifier, role := newVerifierAndRoleAssigner(electionCfg, -1, 0, *useFake, hardforkK)
	voter, cfg := createNodeForTest(nodeConfigForTest{
		t:  t,
		id: "voter 1",
		k:  hardforkK,
		v:  verifier,
		r:  role,
	})
	voterChain := cfg.Chain
	voter.setByzantineClient(&byzantineClientForTest{})

	// Prepare a proposal.
	s := blockchain.BlockSn{Epoch: epoch, S: 1}
	parent := voterChain.GetGenesisBlock()
	var notas []blockchain.Notarization
	b := blockchain.NewBlockFake(
		s, parent.GetBlockSn(), parent.GetNumber()+1, notas, nil, s.String())
	var p blockchain.Proposal
	if *useFake {
		p = blockchain.NewProposalFake("p1", b)
	} else {
		p = blockchain.NewProposalImpl(b, proposerSigner)
	}

	// Simulate how the voter receives a proposal and returns an error
	// because byzantineClientForTest always returns an error.
	dummyMsg := network.Message{}
	err = voter.AddProposal(p, &dummyMsg, BlockCreatedByOther)
	req.Error(err)
}

func TestMain(m *testing.M) {
	// Reduce the output to speed up the tests.
	lgr.SetLogLevel("/", lgr.LvlWarning)
	// We still need to initialize the hardfork configs which are loaded from the file.
	// server.SetupLogging(server.StdoutLogOutputMode, "", "")
	config.InitHardforkConfig("../../../config/")
	os.Exit(m.Run())
}
