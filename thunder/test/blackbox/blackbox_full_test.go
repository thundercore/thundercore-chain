//go:build !skipe2etest
// +build !skipe2etest

// Use a different package to ensure we only test the public API.
package blackbox

import (
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/config"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/consensus"
	"github.com/ethereum/go-ethereum/thunder/pala/network"
	"github.com/ethereum/go-ethereum/thunder/pala/testutils"
	"github.com/ethereum/go-ethereum/thunder/pala/testutils/detector"

	"github.com/stretchr/testify/require"
)

const (
	// always set this to a multiple of 3 to ensure the test cases are testing tight bounds
	numVotersForTest    = 30
	numBootnodesForTest = 3
	numProposersForTest = 3

	waitForProgressTime   = 2000 * time.Millisecond
	waitForNoProgressTime = 200 * time.Millisecond
)

func TestNormalTest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow tests in short mode")
	}

	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	// create honest nodes
	proposerIds := testutils.MakeIds("p", numProposersForTest)
	voterIds := testutils.MakeIds("v", numVotersForTest)
	bootnodesITrust := testutils.MakeIds("b", numBootnodesForTest)
	cfg := testutils.PalaNodeClusterConfig{
		ProposerIds:     proposerIds,
		VoterIds:        voterIds,
		BootnodesITrust: bootnodesITrust,

		GenesisProposerIds: proposerIds,
		GenesisVoterIds:    voterIds,
	}
	nodes := testutils.NewPalaNodeCluster(cfg)
	somenode := nodes.Voters[0]

	// start all honest nodes
	nodes.StartAllNodes()

	// connect everyone
	cfm := testutils.NewConnectionFakeMap()
	testutils.ConnectAll(testutils.ConcatMediatorSlices(nodes.Proposers, nodes.Bootnodes), nodes.Voters, cfm)

	t.Run("normal case", func(t *testing.T) {
		req := require.New(t)
		// expect progress
		testutils.ExpectProgress(req, waitForProgressTime, []*consensus.Mediator{somenode}, blockchain.BlockSn{})
	})

	t.Run("cleanup", func(t *testing.T) {
		req := require.New(t)
		err := nodes.Stop()
		req.NoError(err)
	})
}

func TestNetworkPartition(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow tests in short mode")
	}

	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)

	// create and start nodes
	proposerIds := testutils.MakeIds("p", numProposersForTest)
	voterIds := testutils.MakeIds("v", numVotersForTest)
	cfg := testutils.PalaNodeClusterConfig{
		ProposerIds:     proposerIds,
		VoterIds:        voterIds,
		BootnodesITrust: testutils.MakeIds("b", numBootnodesForTest),

		GenesisProposerIds: proposerIds,
		GenesisVoterIds:    voterIds,
	}
	nodes := testutils.NewPalaNodeCluster(cfg)
	req.True(len(nodes.Proposers) > 0, "expected at least one proposer")
	req.True(len(nodes.Voters) > 2, "expected at least three voters")
	nodes.StartAllNodes()

	somenodeA := nodes.Voters[0]
	somenodeB := nodes.Voters[len(nodes.Voters)-1]

	cfm := testutils.NewConnectionFakeMap()

	t.Run("normal case", func(t *testing.T) {
		req := require.New(t)

		// expect no progress because nodes are not connected
		testutils.ExpectNoProgress(req, waitForNoProgressTime, []*consensus.Mediator{somenodeA, somenodeB})

		// fully connect all nodes
		testutils.ConnectAll(testutils.ConcatMediatorSlices(nodes.Proposers, nodes.Bootnodes), nodes.Voters, cfm)

		// expect progress
		testutils.ExpectProgress(req, waitForProgressTime, []*consensus.Mediator{somenodeA}, blockchain.BlockSn{})
	})

	{
		// create 50/50 split
		var proposersA, proposersB, votersA, votersB, bootnodesA, bootnodesB []*consensus.Mediator
		proposersA = nodes.Proposers[:len(nodes.Proposers)/2]
		proposersB = nodes.Proposers[len(nodes.Proposers)/2:]
		votersA = nodes.Voters[:len(nodes.Voters)/2]
		votersB = nodes.Voters[len(nodes.Voters)/2:]
		if len(nodes.Bootnodes) > 0 {
			bootnodesA = nodes.Bootnodes[:len(nodes.Bootnodes)/2]
			bootnodesB = nodes.Bootnodes[len(nodes.Bootnodes)/2:]
		}
		nodesA := testutils.ConcatMediatorSlices(proposersA, votersA, bootnodesA)
		nodesB := testutils.ConcatMediatorSlices(proposersB, votersB, bootnodesB)

		t.Run("50/50 partition case", func(t *testing.T) {
			req := require.New(t)

			// create network partition
			for _, e := range nodesA {
				for _, f := range nodesB {
					id1 := e.GetConsensusId()
					id2 := f.GetConsensusId()
					if cfm.IsConnected(id1, id2) {
						cfm.RemoveConnection(id1, id2)
					}
				}
			}

			testutils.ExpectNoProgress(req, waitForNoProgressTime, []*consensus.Mediator{somenodeA, somenodeB})
		})

		t.Run("50/50 recovery case", func(t *testing.T) {
			req := require.New(t)

			// reconnect all nodes
			testutils.ConnectAll(testutils.ConcatMediatorSlices(nodes.Proposers, nodes.Bootnodes), nodes.Voters, cfm)

			// expect progress again
			testutils.ExpectProgress(req, waitForProgressTime, []*consensus.Mediator{somenodeA, somenodeB}, blockchain.BlockSn{})
		})
	}
	{
		// create 1/3 (A) - 2/3 (B) split
		var proposersA, proposersB, votersA, votersB, bootnodesA, bootnodesB []*consensus.Mediator
		proposersA = nodes.Proposers[:len(nodes.Proposers)/3]
		proposersB = nodes.Proposers[len(nodes.Proposers)/3:]
		votersA = nodes.Voters[:len(nodes.Voters)/3]
		votersB = nodes.Voters[len(nodes.Voters)/3:]
		if len(nodes.Bootnodes) > 0 {
			bootnodesA = nodes.Bootnodes[:len(nodes.Bootnodes)/3]
			bootnodesB = nodes.Bootnodes[len(nodes.Bootnodes)/3:]
		}

		nodesA := testutils.ConcatMediatorSlices(proposersA, votersA, bootnodesA)
		nodesB := testutils.ConcatMediatorSlices(proposersB, votersB, bootnodesB)

		t.Run("1/3 partition case", func(t *testing.T) {
			req := require.New(t)

			// create network partition
			for _, e := range nodesA {
				for _, f := range nodesB {
					id1 := e.GetConsensusId()
					id2 := f.GetConsensusId()
					if cfm.IsConnected(id1, id2) {
						cfm.RemoveConnection(id1, id2)
					}
				}
			}

			// expect no progress in group A and expect progress in group B
			testutils.ExpectNoProgress(req, waitForNoProgressTime, []*consensus.Mediator{somenodeA})
			testutils.ExpectProgress(req, waitForProgressTime, []*consensus.Mediator{somenodeB}, blockchain.BlockSn{})
		})

		t.Run("1/3 recovery case", func(t *testing.T) {
			req := require.New(t)

			// reconnect all nodes
			testutils.ConnectAll(testutils.ConcatMediatorSlices(nodes.Proposers, nodes.Bootnodes), nodes.Voters, cfm)

			// expect progress again in group A
			testutils.ExpectProgress(req, waitForProgressTime, []*consensus.Mediator{somenodeA, somenodeB}, blockchain.BlockSn{})
		})
	}

	t.Run("cleanup", func(t *testing.T) {
		err := nodes.Stop()
		req := require.New(t)
		req.NoError(err)
	})
}

func TestNetworkDelay(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow tests in short mode")
	}

	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)

	// this can not be too high or it will not satisfy period of synchrony requirements
	// there should be a formula for a tight bound here however due to non deterministic execution of time based code
	// we choose 50ms which should be significantly lower than the tight bound to ensure the test always passes
	delayTime := time.Millisecond * 50

	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(2, 0)

	// create and start nodes
	proposerIds := testutils.MakeIds("p", numProposersForTest)
	voterIds := testutils.MakeIds("v", numVotersForTest)
	cfg := testutils.PalaNodeClusterConfig{
		ProposerIds:     proposerIds,
		VoterIds:        voterIds,
		BootnodesITrust: testutils.MakeIds("b", numBootnodesForTest),
		Params: consensus.PalaParams{
			K:                              hardforkK,
			DelayOfMakingFirstProposal:     100 * time.Millisecond,
			VoterWaitingTimeBeforeClockMsg: 600 * time.Millisecond,
		},

		GenesisProposerIds: proposerIds,
		GenesisVoterIds:    voterIds,
	}

	nodes := testutils.NewPalaNodeCluster(cfg)
	req.True(len(nodes.Proposers) > 0, "expected at least one proposer")
	req.True(len(nodes.Voters) > 2, "expected at least three voters")
	nodes.StartAllNodes()

	somenodeA := nodes.Voters[0]

	cfm := testutils.NewConnectionFakeMap()
	wg := sync.WaitGroup{}
	stopCh := make(chan interface{})
	testutils.ConnectAllWithFilter(testutils.ConcatMediatorSlices(nodes.Proposers, nodes.Bootnodes), nodes.Voters, cfm,
		network.Delay{Mean: delayTime}, &wg, stopCh, network.EmptyFilter)

	t.Run("normal case", func(t *testing.T) {
		req := require.New(t)

		// expect progress, wait a little longer this time due to message delay
		testutils.ExpectProgress(req, waitForProgressTime, []*consensus.Mediator{somenodeA}, blockchain.BlockSn{})
	})

	t.Run("cleanup", func(t *testing.T) {
		err := nodes.Stop()
		req := require.New(t)
		req.NoError(err)
		close(stopCh)
		wg.Wait()
	})
}

// removed for now due to intermittent failures when run with -race e.g.
// go test thunder2/consensus_test -run Slow_FaultyVerifier --count=10 -race
func TestDisasterRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow tests in short mode")
	}

	req := require.New(t)

	// create and start nodes
	proposerIds := testutils.MakeIds("p", numProposersForTest)
	voterIds := testutils.MakeIds("v", numVotersForTest)
	cfg := testutils.PalaNodeClusterConfig{
		ProposerIds:     proposerIds,
		VoterIds:        voterIds,
		BootnodesITrust: testutils.MakeIds("b", numBootnodesForTest),

		GenesisProposerIds: proposerIds,
		GenesisVoterIds:    voterIds,
	}
	nodes := testutils.NewPalaNodeCluster(cfg)
	req.True(len(nodes.Proposers) > 0, "expected at least one proposer")
	req.True(len(nodes.Voters) > 2, "expected at least 3 voters")
	nodes.StartAllNodes()

	somenodeA := nodes.Voters[0]
	somenodeB := nodes.Voters[len(nodes.Voters)-1]

	cfm := testutils.NewConnectionFakeMap()
	// fully connect all nodes
	testutils.ConnectAll(testutils.ConcatMediatorSlices(nodes.Proposers, nodes.Bootnodes), nodes.Voters, cfm)

	t.Run("normal case", func(t *testing.T) {
		req := require.New(t)

		// expect progress
		testutils.ExpectProgress(req, waitForProgressTime, []*consensus.Mediator{somenodeA, somenodeB}, blockchain.BlockSn{})
	})

	{
		// create 1/3+1 (A) - 2/3-1 (B) split in voters and crash/lose data in group B
		// this is the threshold tolerance for guaranteed consistency
		votersA := nodes.Voters[:len(nodes.Voters)/3+1]
		votersB := nodes.Voters[len(nodes.Voters)/3+1:]
		nodesA := testutils.ConcatMediatorSlices(nodes.Proposers, nodes.Bootnodes, votersA)
		nodesB := votersB

		t.Run("two thirds minus one crash case", func(t *testing.T) {
			req := require.New(t)

			// disconnect and crash nodesB
			for _, e := range nodesB {
				for _, f := range testutils.ConcatMediatorSlices(nodesA, nodesB) {
					id1 := e.GetConsensusId()
					id2 := f.GetConsensusId()
					if cfm.IsConnected(id1, id2) {
						cfm.RemoveConnection(id1, id2)
					}
				}
			}
			testutils.StopNodesAndWipeData(nodesB)

			testutils.ExpectNoProgress(req, waitForNoProgressTime, []*consensus.Mediator{somenodeA})

			// TODO(thunder) check for max finalized chain and cache

		})

		t.Run("two thirds minus one recovery case", func(t *testing.T) {
			req := require.New(t)

			// restart the nodes and reconnect them
			testutils.StartNodes(nodesB)
			testutils.ConnectAll(testutils.ConcatMediatorSlices(nodes.Proposers, nodes.Bootnodes), nodes.Voters, cfm)

			// expect progress again
			testutils.ExpectProgress(req, waitForProgressTime, []*consensus.Mediator{nodes.Proposers[0], somenodeA, somenodeB}, blockchain.BlockSn{})

			// TODO(thunder) check for no loss in consistency (compare to cached value above)
			// TODO(thunder) check for max finalized chain and cache
		})
	}
	{
		// crash every node except somenodeA
		nodesA := nodes.Voters[0:1] // same as somenodeA
		nodesB := testutils.ConcatMediatorSlices(nodes.Voters[1:], nodes.Proposers, nodes.Bootnodes)

		t.Run("disaster case", func(t *testing.T) {
			req := require.New(t)

			// disconnect crashed nodes
			for _, e := range nodesB {
				for _, f := range testutils.ConcatMediatorSlices(nodesA, nodesB) {
					id1 := e.GetConsensusId()
					id2 := f.GetConsensusId()
					if cfm.IsConnected(id1, id2) {
						cfm.RemoveConnection(id1, id2)
					}
				}
			}
			testutils.StopNodesAndWipeData(nodesB)

			testutils.ExpectNoProgress(req, waitForNoProgressTime, []*consensus.Mediator{nodesA[0]})
		})

		t.Run("disaster recovery case", func(t *testing.T) {
			req := require.New(t)

			// Possible loss of consistency in this test case will result honest proposer trying to add a valid block t
			// that already exists in the blockchain.
			// i.e. nodesB group may finalize a new block that conflicts with a block that was finalized before the
			// crash. Since nodesB has at least 2/3 nodes, they can finalize new blocks without recovering data from
			// somenodeA.
			for _, e := range nodes.Proposers {
				e.GetBlockChainForTest().(*blockchain.BlockChainImpl).AllowBadBehaviorForTest()
			}

			// restart the nodes and reconnect them
			testutils.StartNodes(nodesB)
			testutils.ConnectAll(testutils.ConcatMediatorSlices(nodes.Proposers, nodes.Bootnodes), nodes.Voters, cfm)

			// possible loss of consistency means that nodesB may produce a different chain than somenodeA which
			// did not crash
			// in this case, somenodeA will not make progress so check somenodeB for progress instead
			testutils.ExpectProgress(req, waitForProgressTime, []*consensus.Mediator{somenodeB}, blockchain.BlockSn{})

			// TODO(thunder) check for possible loss of consistency and log a message if so
		})
	}

	t.Run("cleanup", func(t *testing.T) {
		err := nodes.Stop()
		req := require.New(t)
		req.NoError(err)
	})
}
