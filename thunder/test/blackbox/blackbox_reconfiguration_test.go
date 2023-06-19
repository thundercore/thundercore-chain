//go:build !skipe2etest
// +build !skipe2etest

package blackbox

import (
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/consensus"
	"github.com/ethereum/go-ethereum/thunder/pala/network"
	"github.com/ethereum/go-ethereum/thunder/pala/testutils"
	"github.com/ethereum/go-ethereum/thunder/pala/testutils/detector"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/stretchr/testify/require"
)

// Voter reconfiguration is what we call "committee switch" in Thunder 0.5.
func TestVoterReconfigurationDetails(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)

	// Overview of the test.
	// * One proposer p1.
	// * The first generation of voters are (v1, v2)
	// * The second generation of voters are (v2, v3)
	// * Expect v3 is catching up with the bootnode before it becomes the voter.
	// * Expect v3 connects to p1 during the reconfiguration.
	// * Expect p1 drops the connection to v1 during the reconfiguration.
	// * Expect v2 continues in office.

	k := uint32(2)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	// Note that the genesis block is the 0th block.
	stopBlockSessionOffset := uint64(9)
	voterIds := [][]ConsensusId{
		MakeConsensusIds("v1", "v2"),
		MakeConsensusIds("v2", "v3"),
	}
	proposerList := blockchain.NewElectionResultFake(MakeConsensusIds("p1"), 0, 100)
	voterList := blockchain.NewElectionResultFake(voterIds[0], 0, 1)
	voterList2 := blockchain.NewElectionResultFake(voterIds[1], 0, 2)
	bootnodeId := ConsensusId("b1")
	bootnodeAddresses := []string{string(bootnodeId)}

	// Prepare the proposer.
	// Keep the proposer unchanged after the reconfiguration.
	r := consensus.NewReconfigurerFake("p1")
	r.AddReconfiguration(2, &consensus.ReconfigurationFake{
		ProposerList: proposerList,
		VoterList:    voterList2,
	})
	proposer, proposerChain := testutils.NewMediatorForTest(testutils.MediatorTestConfig{
		LoggingId:              "p1",
		MyId:                   ConsensusId("p1"),
		ProposerList:           proposerList,
		VoterList:              voterList,
		BootnodeConfig:         consensus.BootnodeConfig{TrustedAddresses: bootnodeAddresses},
		StopBlockSessionOffset: stopBlockSessionOffset,
		Reconfigurer:           r,
	})

	proposerNotificationChan := proposer.NewNotificationChannel()
	err := proposer.Start()
	req.NoError(err)

	// Prepare the bootnode.
	r = consensus.NewReconfigurerFake("b1")
	r.AddReconfiguration(2, &consensus.ReconfigurationFake{
		ProposerList: proposerList,
		VoterList:    voterList2,
	})
	bootnode, _ := testutils.NewMediatorForTest(testutils.MediatorTestConfig{
		LoggingId:              string(bootnodeId),
		MyId:                   bootnodeId,
		IsBootnode:             true,
		ProposerList:           proposerList,
		VoterList:              voterList,
		StopBlockSessionOffset: stopBlockSessionOffset,
		Reconfigurer:           r,
		BootnodeConfig:         testutils.BootnodeConfigForFake(),
	})
	err = bootnode.Start()
	req.NoError(err)

	// Prepare the voters.
	var voters []*consensus.Mediator
	var voterNotificationChans []<-chan interface{}
	var voterReconfiguers []consensus.Reconfigurer
	var voterChains []blockchain.BlockChain
	for i := 0; i < 3; i++ {
		idStr := fmt.Sprintf("v%d", i+1)
		r := consensus.NewReconfigurerFake(idStr)
		r.AddReconfiguration(2, &consensus.ReconfigurationFake{
			ProposerList: proposerList,
			VoterList:    voterList2,
		})
		voterReconfiguers = append(voterReconfiguers, r)

		v, chain := testutils.NewMediatorForTest(testutils.MediatorTestConfig{
			LoggingId:              idStr,
			MyId:                   ConsensusId(idStr),
			ProposerList:           proposerList,
			VoterList:              voterList,
			BootnodeConfig:         consensus.BootnodeConfig{TrustedAddresses: bootnodeAddresses},
			StopBlockSessionOffset: stopBlockSessionOffset,
			Reconfigurer:           r,
			Params: consensus.PalaParams{
				K:                          hardforkK,
				DelayOfMakingFirstProposal: 10 * time.Millisecond,
				// Ensure voters won't timeout even CPUs are very busy.
				VoterWaitingTimeBeforeClockMsg: time.Second,
			},
		})
		voterChains = append(voterChains, chain)
		voterNotificationChans = append(voterNotificationChans, v.NewNotificationChannel())
		voters = append(voters, v)

		err := v.Start()
		req.NoError(err)
	}

	// Register the debug helper.
	var mediators []*consensus.Mediator
	mediators = append(mediators, proposer)
	mediators = append(mediators, voters...)
	mediators = append(mediators, bootnode)

	handler := consensus.NewDumpDebugStateHandler(consensus.AsDumpers(mediators)...)
	signalChan := consensus.RegisterSignalHandlers(handler)
	defer utils.StopSignalHandler(signalChan)

	// Setup network connections.
	proposerHost := proposer.GetHostForTest()
	voterReconfiguers[2].(*consensus.ReconfigurerFake).SetNetworkReconfiguration(
		func(session blockchain.Session, bc blockchain.BlockChain, host *network.Host) error {
			network.FakeConnect(voters[2].GetHostForTest(), proposerHost)
			return nil
		})

	// v1, v2 connect to the proposer
	network.FakeConnect(voters[0].GetHostForTest(), proposerHost)
	network.FakeConnect(voters[1].GetHostForTest(), proposerHost)
	// All nodes connect to the bootnode
	bootnodeHost := bootnode.GetHostForTest()
	network.FakeConnect(proposerHost, bootnodeHost)
	for i := 0; i < len(voters); i++ {
		network.FakeConnect(voters[i].GetHostForTest(), bootnodeHost)
	}

	// Verify
	end := uint32(stopBlockSessionOffset)
	epoch := blockchain.NewEpoch(1, 1)
	epochInNewSession := epoch.NextSession()
	verifyFinalizedChain(
		t, proposer.GetConsensusId(), proposerNotificationChan, epoch, 1, end, true, nil)
	verifyFinalizedChain(
		t, proposer.GetConsensusId(), proposerNotificationChan, epochInNewSession, 1, 5, true, nil)
	b := proposerChain.GetBlock(blockchain.BlockSn{Epoch: epochInNewSession, S: 1})
	req.NotNil(b)
	parentSn := b.GetParentBlockSn()
	req.Equal(epoch, parentSn.Epoch)
	req.True(parentSn.S >= end+k, blockchain.DumpFakeChain(proposerChain, b, true))

	// Verify all voters for (1,1,s)
	for i := 0; i < len(voters); i++ {
		verifyFinalizedChain(
			t, voters[i].GetConsensusId(), voterNotificationChans[i], epoch, 1, end, true, nil)
	}
	// Verify the new voters for (2,1,s)
	verifyFinalizedChain(
		t, voters[1].GetConsensusId(), voterNotificationChans[1], epochInNewSession, 1, 5, true, nil)
	verifyFinalizedChain(
		t, voters[2].GetConsensusId(), voterNotificationChans[2], epochInNewSession, 1, 5, true, nil)

	// Expect p1 drops the connection to v1 because v1 is not a consensus node
	// in the new session.
Loop:
	for e := range voterNotificationChans[0] {
		switch v := e.(type) {
		case consensus.ConnectionClosedEvent:
			req.Equal(ConsensusId("p1"), v.Identity)
			break Loop
		}
	}

	// Stop proposers/voters.
	for _, m := range mediators {
		err = m.Stop()
		req.NoError(err)
		m.Wait()
	}

	// Expect (v1, v2) are voters of (1,1,1) ..., (1,1,14)
	for i := uint32(1); i <= end+k; i++ {
		sn := blockchain.BlockSn{Epoch: epoch, S: i}
		nota := proposerChain.GetNotarization(sn)
		req.NotNil(nota, "i=%d", i)
		voterIds := nota.(*blockchain.NotarizationFake).GetVoterIds()
		req.Equal(2, len(voterIds))
		req.Equal(ConsensusId("v1"), voterIds[0], "sn=%s, voterIds=%s", sn, voterIds)
		req.Equal(ConsensusId("v2"), voterIds[1], "sn=%s, voterIds=%s", sn, voterIds)
	}

	// Expect (v2, v3) are voters of (2,1,1), ..., (2,1,10)
	for i := uint32(1); i <= uint32(5)+k; i++ {
		sn := blockchain.BlockSn{Epoch: epochInNewSession, S: i}
		nota := proposerChain.GetNotarization(sn)
		req.NotNil(nota, "i=%d", i)
		voterIds := nota.(*blockchain.NotarizationFake).GetVoterIds()
		req.Equal(2, len(voterIds))
		req.Equal(ConsensusId("v2"), voterIds[0], "sn=%s, voterIds=%s", sn, voterIds)
		req.Equal(ConsensusId("v3"), voterIds[1], "sn=%s, voterIds=%s", sn, voterIds)
	}
}

// Note that this uses PalaNodeCluster to simplify the tests comapred to TestVoterReconfiguration.
func TestVoterReconfigurationTwice(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)

	// Overview of the test.
	// * Proposers: p0; voter candidates: v0, v1, v2; bootnodes: b1
	// * [v0] is the voters in session 1
	// * [v1, v2] is the voters in session 2
	// * [v0, v2] is the voters in session 3
	//
	// Expect non-consensus nodes catch up via the bootnode.

	// Create nodes.
	proposerIds := testutils.MakeIds("p", 1)
	voterIds := testutils.MakeIds("v", 3)
	bootnodeIds := testutils.MakeIds("b", 1)
	voterIdsA := voterIds[:1]
	voterIdsB := voterIds[1:]
	voterIdsC := []ConsensusId{voterIds[0], voterIds[2]}
	cfg := testutils.PalaNodeClusterConfig{
		ProposerIds:     proposerIds,
		VoterIds:        voterIds,
		BootnodesITrust: bootnodeIds,

		GenesisProposerIds: proposerIds,
		GenesisVoterIds:    voterIdsA,

		// The 5th block (e.g., (1,1,5)) in each session is the stop block of that session.
		ElectionStopBlockSessionOffset: 4,
	}
	cluster := testutils.NewPalaNodeCluster(cfg)

	p := cluster.Proposers[0]

	// Setup reconfiguration in session 2: [v0] -> [v1, v2]
	err := cluster.AddReconfiguration(2, proposerIds, voterIdsB,
		func(session blockchain.Session, id ConsensusId) {
			if idx := ConsensusIds(voterIds).FindIndex(id); idx < len(voterIds) && idx > 0 {
				network.FakeConnect(cluster.Voters[idx].GetHostForTest(), p.GetHostForTest())
			}
		})
	req.NoError(err)

	// Setup reconfiguration in session 3: [v1, v2] -> [v0, v2]
	err = cluster.AddReconfiguration(3, proposerIds, voterIdsC,
		func(session blockchain.Session, id ConsensusId) {
			// Do not reconnect v2; otherwise, v2 may reply the vote while the connection is not ready,
			// and thus the vote is missed. The result is the corresponding proposal is not notarized.
			if idx := ConsensusIds(voterIds).FindIndex(id); idx < len(voterIds) && idx == 0 {
				network.FakeConnect(cluster.Voters[idx].GetHostForTest(), p.GetHostForTest())
			}
		})
	req.NoError(err)

	// Start all nodes.
	cluster.StartAllNodes()

	// All connect to bootnodes
	cfm := testutils.NewConnectionFakeMap()
	testutils.ConnectAll(cluster.Bootnodes, cluster.AllNodes(), cfm)
	// Only the voters in session 1 connect to proposers.
	// Note that we don't handshake and verify identities when using fake connections.
	// Instead, the test code sets correct connections.
	testutils.ConnectAll(cluster.Proposers, cluster.Voters[:1], cfm)

	defer func() {
		err = cluster.Stop()
		req.NoError(err)
	}()

	// Expect progress.
	waitingTime := 500 * time.Millisecond
	testutils.ExpectProgress(
		req, waitingTime, cluster.AllNodes(), blockchain.NewBlockSn(3, 1, 3),
		"progress after 2 reconfigurations")

	// Verify blocks.
	chain := p.GetBlockChainForTest()
	expected := []blockchain.BlockSn{
		blockchain.NewBlockSn(1, 1, 5),
		blockchain.NewBlockSn(2, 1, 5),
	}
	for _, e := range expected {
		b := chain.GetBlock(e)
		req.NotNil(b, blockchain.DumpFakeChain(chain, chain.GetFinalizedHead(), true))
		req.Equal(e, b.GetBlockSn())
	}

	// Verify votes.
	tests := []struct {
		session  blockchain.Session
		voterIds []ConsensusId
	}{
		{session: 1, voterIds: voterIdsA},
		{session: 2, voterIds: voterIdsB},
		{session: 3, voterIds: voterIdsC},
	}

	for _, tt := range tests {
		nota := chain.GetNotarization(blockchain.NewBlockSn(uint32(tt.session), 1, 1))
		req.NotNil(nota, fmt.Sprintf("%s: %s",
			tt.session, blockchain.DumpFakeChain(chain, chain.GetFinalizedHead(), false)))
		req.Equal(tt.voterIds, nota.(*blockchain.NotarizationFake).GetVoterIds())
	}
}

// Note that this also covers "crash and restart" during the reconfiguration.
func TestFinalizedChainForkAfterStopBlock(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)

	// Overview of the test.
	// * Two proposer p0, p1; Voters voter v0, v1
	// * [v0] is the voters in session 1
	// * [v1] is the voters in session 2
	// * v0 and v1 have different finalized chain after the stop block
	//   and both starts during the reconfiguration.

	// Create nodes.
	proposerIds := testutils.MakeIds("p", 2)
	voterIds := testutils.MakeIds("v", 2)
	bootnodeIds := testutils.MakeIds("b", 1)
	voterIdsA := voterIds[:1]
	voterIdsB := voterIds[1:]
	cfg := testutils.PalaNodeClusterConfig{
		ProposerIds:     proposerIds,
		VoterIds:        voterIds,
		BootnodesITrust: bootnodeIds,

		GenesisProposerIds: proposerIds,
		GenesisVoterIds:    voterIdsA,

		// The 5th block (e.g., (1,1,5)) in each session is the stop block of that session.
		ElectionStopBlockSessionOffset: 4,
	}
	cluster := testutils.NewPalaNodeCluster(cfg)
	k := uint32(cluster.GetUnnotarizedWindow().GetValueAtSession(1))
	// Notarized chain:
	//                                                      [p0,v1,b0]
	// (1,1,1)<-(1,1,2)<-(1,1,3)<-(1,1,4)<-(1,1,5)<-(1,1,6)<-(1,1,7)
	//                                        ^
	//                                        |                    [p1,v0]
	//                                        +-(1,2,1)<-(1,2,2)<-(1,2,3)
	lastSnInSessionOne := blockchain.NewBlockSn(1, 1, 5+k)
	for _, node := range cluster.AllNodes() {
		chain := node.GetBlockChainForTest()
		generator := blockchain.NewChainGeneratorWithExistedFakeChain(chain, cluster.GetUnnotarizedWindow())
		generator.SetVoters(voterIdsA)
		// Prepare the chain which has finalized the stop block.
		generator.Init(lastSnInSessionOne)
		id := ConsensusId(node.GetConsensusId()) //FIXME: loggingId semantics
		if ConsensusIds(voterIdsA).Contains(id) || id == proposerIds[1] {
			// Create a finalized chain fork.
			generator.Branch(
				blockchain.NewBlockSn(1, 1, 5),
				blockchain.NewBlockSn(1, 2, 1+2))
			err := generator.NotarizeTail(generator.GetTails()[1])
			req.NoError(err)
			em := node.GetEpochManagerForTest()
			em.UpdateByClockMsgNota(blockchain.NewClockMsgNotaFake(blockchain.NewEpoch(1, 2), voterIdsA))
		} else {
			err := generator.NotarizeTail(generator.GetTails()[0])
			req.NoError(err)
		}
	}
	// Setup reconfiguration in session 2: [v0] -> [v1]
	err := cluster.AddReconfiguration(2, proposerIds, voterIdsB, nil)
	req.NoError(err)

	// Start all nodes.
	cluster.StartAllNodes()

	cfm := testutils.NewConnectionFakeMap()
	// To make p0, v1, b0 finish the reconfiguration first, make network partitions (p0, v1, b0) and (p1, v0)
	testutils.ConnectAll(append(cluster.Bootnodes, cluster.Proposers[0]), cluster.Voters[1:], cfm)

	defer func() {
		err = cluster.Stop()
		req.NoError(err)
	}()

	// Expect progress.
	waitingTime := 500 * time.Millisecond
	all := cluster.AllNodes()
	partitionA := append(cluster.Bootnodes, cluster.Proposers[0], cluster.Voters[1])
	partitionB := testutils.GetDifferenceSet(all, partitionA)
	testutils.ExpectProgress(req, waitingTime, partitionA, blockchain.NewBlockSn(2, 1, 3), "partition A")

	// Expect there is a fork.
	p1Chain := cluster.Proposers[1].GetBlockChainForTest()
	oldFinalizedHead := p1Chain.GetFinalizedHead()
	req.Equal(
		blockchain.NewBlockSn(1, 2, 1),
		p1Chain.GetBlockByNumber(oldFinalizedHead.GetNumber()).GetBlockSn())

	// Expect progress via the chain syncing.
	testutils.ConnectAll(cluster.Bootnodes, partitionB, cfm)
	testutils.ExpectProgress(req, waitingTime, partitionB, blockchain.NewBlockSn(2, 1, 3), "partition B")

	// Expect the finalized head changes.
	req.Equal(
		blockchain.NewBlockSn(1, 1, 6),
		p1Chain.GetBlockByNumber(oldFinalizedHead.GetNumber()).GetBlockSn())

	// Expect all chains have the same finalized chain.
	for _, node := range cluster.AllNodes() {
		chain := node.GetBlockChainForTest()
		b := chain.GetBlock(blockchain.NewBlockSn(2, 1, 1))
		req.NotNil(b)
		req.Equal(lastSnInSessionOne, b.GetParentBlockSn(),
			fmt.Sprintf("id=%s; chain=%s", node.GetConsensusId(),
				blockchain.DumpFakeChain(chain, chain.GetFinalizedHead(), false)))
	}
}

func TestFirstBlockAndStopBlockAreFinalizedAtTheSameTime(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)

	// Overview of the test.
	// * One proposer p0; Voters voter v0, v1
	// * [v0] is the voters in session 1
	// * [v1] is the voters in session 2
	// * [v0] is the voters in session 3
	// * The first block and the stop block in session 2 are finalized at the same time.

	// Create nodes.
	proposerIds := testutils.MakeIds("p", 1)
	voterIds := testutils.MakeIds("v", 2)
	bootnodeIds := testutils.MakeIds("b", 1)
	voterIdsA := voterIds[:1]
	voterIdsB := voterIds[1:]
	cfg := testutils.PalaNodeClusterConfig{
		ProposerIds:     proposerIds,
		VoterIds:        voterIds,
		BootnodesITrust: bootnodeIds,

		GenesisProposerIds: proposerIds,
		GenesisVoterIds:    voterIdsA,

		// The 5th block (e.g., (1,1,5)) in each session is the stop block of that session.
		ElectionStopBlockSessionOffset: 4,
	}
	cluster := testutils.NewPalaNodeCluster(cfg)
	k := uint32(cluster.GetUnnotarizedWindow().GetValueAtSession(1))
	// Notarized chain:
	//
	// (1,1,1)<-(1,1,2)<-(1,1,3)<-(1,1,4)<-(1,1,5)<-(1,1,6)<-(1,1,7)
	//                                                          ^
	//    +-----------------------------------------------------|
	//    |
	// (2,1,1)<-(2,2,1)<-(2,3,1)<-(2,4,1)
	lastSnInSessionOne := blockchain.NewBlockSn(1, 1, 5+k)
	for _, node := range cluster.AllNodes() {
		chain := node.GetBlockChainForTest()
		generator := blockchain.NewChainGeneratorWithExistedFakeChain(chain, cluster.GetUnnotarizedWindow())
		generator.SetVoters(voterIdsA)
		// Prepare the chain which has finalized the stop block.
		generator.Init(lastSnInSessionOne)
		// Prepare the chain in the next session.
		generator.SetVoters(voterIdsB)
		parentSn := lastSnInSessionOne
		for i := 1; i <= 4; i++ {
			sn := blockchain.NewBlockSn(2, uint32(i), 1)
			err := generator.Branch(parentSn, sn)
			req.NoError(err)
			parentSn = sn
		}
		tails := generator.GetTails()
		err := generator.NotarizeTail(tails[len(tails)-1])
		req.NoError(err)

		em := node.GetEpochManagerForTest()
		em.UpdateByClockMsgNota(blockchain.NewClockMsgNotaFake(blockchain.NewEpoch(2, 5), voterIdsB))
	}

	// Setup reconfiguration in session 2: [v0] -> [v1]
	p := cluster.Proposers[0]
	err := cluster.AddReconfiguration(2, proposerIds, voterIdsB,
		func(session blockchain.Session, id ConsensusId) {
			if ConsensusIds(voterIdsB).Contains(id) {
				idx := ConsensusIds(voterIds).FindIndex(id)
				network.FakeConnect(cluster.Voters[idx].GetHostForTest(), p.GetHostForTest())
			}
		})
	req.NoError(err)

	// Setup reconfiguration in session 3: [v1] -> [v0]
	err = cluster.AddReconfiguration(3, proposerIds, voterIdsA,
		func(session blockchain.Session, id ConsensusId) {
			if ConsensusIds(voterIdsA).Contains(id) {
				idx := ConsensusIds(voterIds).FindIndex(id)
				network.FakeConnect(cluster.Voters[idx].GetHostForTest(), p.GetHostForTest())
			}
		})
	req.NoError(err)

	// Start all nodes.
	cluster.StartAllNodes()

	cfm := testutils.NewConnectionFakeMap()
	testutils.ConnectAll(cluster.Bootnodes, cluster.Voters, cfm)
	defer func() {
		err = cluster.Stop()
		req.NoError(err)
	}()

	// Expect progress.
	waitingTime := 500 * time.Millisecond
	testutils.ExpectProgress(req, waitingTime, cluster.AllNodes(), blockchain.NewBlockSn(3, 1, 3), "all nodes")

	chain := cluster.Proposers[0].GetBlockChainForTest()
	b := chain.GetBlock(blockchain.NewBlockSn(3, 1, 1))
	req.NotNil(b)
	req.Equal(blockchain.NewBlockSn(2, 5, 1+2), b.GetParentBlockSn())
}

func TestProcessBlocksMoreThanOneSessionInOneSyncMessage(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)

	// Overview of the test.
	// * One voter catches blocks from one proposer.
	// * The fetched blocks are more than one session and expect all blocks are processed.

	// Create nodes.
	proposerIds := testutils.MakeIds("p", 1)
	voterIds := testutils.MakeIds("v", 1)
	cfg := testutils.PalaNodeClusterConfig{
		ProposerIds: proposerIds,
		VoterIds:    voterIds,

		GenesisProposerIds: proposerIds,
		GenesisVoterIds:    voterIds,

		// The 5th block (e.g., (1,1,3)) in each session is the stop block of that session.
		ElectionStopBlockSessionOffset: 2,
	}
	cluster := testutils.NewPalaNodeCluster(cfg)
	// Notarized chain:
	//
	// (1,1,1)<-(1,1,2)<-(1,1,3)<-(1,1,4)<-(1,1,5)
	//                                        ^
	//    +-----------------------------------|
	//    |
	// (2,1,1)<-(2,1,2)<-(2,1,3)<-(2,1,4)
	lastSnInSessionOne := blockchain.NewBlockSn(1, 1, 3+2)
	chain := cluster.Proposers[0].GetBlockChainForTest()
	generator := blockchain.NewChainGeneratorWithExistedFakeChain(chain, cluster.GetUnnotarizedWindow())
	generator.SetVoters(voterIds)
	// Prepare the chain which has finalized the stop block.
	generator.Init(lastSnInSessionOne)
	// Prepare the chain in the next session.
	parentSn := lastSnInSessionOne
	sn := blockchain.NewBlockSn(2, 1, 4)
	err := generator.Branch(parentSn, sn)
	req.NoError(err)
	parentSn = sn
	tails := generator.GetTails()
	err = generator.NotarizeTail(tails[len(tails)-1])
	req.NoError(err)

	// Setup reconfiguration in session 2
	err = cluster.AddReconfiguration(2, proposerIds, voterIds, nil)
	req.NoError(err)

	// Start all nodes.
	cluster.StartAllNodes()

	// Connect nodes. Only allow receiving one sync message which contains all required blocks.
	allowedSyncMessage := 1
	net := consensus.NewNetworkSimulator()
	net.AddRule(consensus.NetworkSimulatorRule{
		From: nil,
		To:   []ConsensusId{cluster.Voters[0].GetConsensusId()},
		Type: consensus.MessageFresherHeadDataV2,
		Action: &network.FilterAction{
			PreCallback: func(from ConsensusId, to ConsensusId, typ uint8, blob []byte) network.PassedOrDropped {
				if allowedSyncMessage > 0 {
					allowedSyncMessage--
					return network.Passed
				}
				return network.Dropped
			},
		},
	})
	net.Connect(cluster.Voters[0].GetHostForTest(), cluster.Proposers[0].GetHostForTest())

	defer func() {
		err = cluster.Stop()
		req.NoError(err)
	}()

	// Expect progress.
	waitingTime := 500 * time.Millisecond
	testutils.ExpectProgress(req, waitingTime, cluster.Voters, blockchain.NewBlockSn(2, 1, 2))
}
