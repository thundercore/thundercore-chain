//go:build !skipe2etest
// +build !skipe2etest

// Use a different package to ensure we only test the public API.
package blackbox

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/consensus"
	"github.com/ethereum/go-ethereum/thunder/pala/network"
	"github.com/ethereum/go-ethereum/thunder/pala/testutils"
	"github.com/ethereum/go-ethereum/thunder/pala/testutils/detector"
	"github.com/ethereum/go-ethereum/thunder/pala/types"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/stretchr/testify/require"
)

type ConsensusId = types.ConsensusId

var ConsensusIds = types.ConsensusIds

var MakeConsensusIds = types.MakeConsensusIds

var haveTestedChainOfTrust bool

// Expect the |mediators| notify FinalizedChainExtendedEvent with sn in range [|beginS|, |endS|]
// at the same |epoch|.
func verifyFinalizedChain(
	t *testing.T, id ConsensusId, ch <-chan interface{},
	epoch blockchain.Epoch, beginS uint32, endS uint32, verifyProgress bool,
	chain blockchain.BlockChain) {
	last := blockchain.BlockSn{Epoch: epoch, S: endS}
	fcS := beginS
	for e := range ch {
		switch v := e.(type) {
		case consensus.FreshestNotarizedChainExtendedEvent:
			// Skip checking the event. Note that some BlockSn may be skipped.
			// For example, if k=2 and the node receives block(1,1), block(1,2) and nota(1,2),
			// then FreshestNotarizedChainExtendedEvent(1,1) is skipped.
			// The sequence does happen during the test because the node finishes the handshake
			// after nota(1,1) is broadcasted.
		case consensus.FinalizedChainExtendedEvent:
			if verifyProgress {
				expected := blockchain.BlockSn{Epoch: epoch, S: fcS}
				if expected.Epoch.Compare(v.Sn.Epoch) > 0 {
					// Skip the old events from the last run.
					continue
				}
				var s string
				if expected != v.Sn && chain != nil {
					s = blockchain.DumpFakeChain(chain, chain.GetFreshestNotarizedHead(), false)
				}
				require.Equal(t, expected, v.Sn, "id=%s; chain=%s", id, s)
				fcS++
			}
			if v.Sn == last {
				return
			}
			if v.Sn.Compare(last) > 0 {
				debug.Bug("v.Sn %s > last %s", v.Sn, last)
			}
		}
	}
	require.FailNow(t, "%s is not received", last)
}

func TestLivenessAndDisasterRecovery(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	epoch := blockchain.NewEpoch(1, 1)

	// Prepare the proposer
	beginEpoch := blockchain.Epoch{}
	endEpoch := blockchain.NewEpoch(1, 2)
	proposerList := blockchain.NewElectionResultFake(MakeConsensusIds("p1"), beginEpoch.Session, endEpoch.Session)
	voterIds := MakeConsensusIds("v1", "v2", "v3")
	voterList := blockchain.NewElectionResultFake(voterIds, beginEpoch.Session, endEpoch.Session)
	newProposer := func(epoch blockchain.Epoch) (*consensus.Mediator, blockchain.BlockChain) {
		em := blockchain.NewEpochManagerFake()
		cNota := blockchain.NewClockMsgNotaFake(epoch, voterIds)
		em.UpdateByClockMsgNota(cNota)
		mediator, chain := testutils.NewMediatorForTest(testutils.MediatorTestConfig{
			LoggingId:    "p1",
			MyId:         ConsensusId("p1"),
			ProposerList: proposerList,
			VoterList:    voterList,
			EpochManager: em,
		})
		return mediator, chain
	}
	proposer, _ := newProposer(epoch)
	proposerNotificationChan := proposer.NewNotificationChannel()

	// Prepare three voters
	voterEpochManagers := []blockchain.EpochManager{}
	var voters []*consensus.Mediator
	var voterNotificationChans []<-chan interface{}
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("v%d", i+1)
		em := blockchain.NewEpochManagerFake()
		cNota := blockchain.NewClockMsgNotaFake(epoch, voterIds)
		em.UpdateByClockMsgNota(cNota)
		voterEpochManagers = append(voterEpochManagers, em)
		v, _ := testutils.NewMediatorForTest(testutils.MediatorTestConfig{
			LoggingId:    id,
			MyId:         ConsensusId(id),
			ProposerList: proposerList,
			VoterList:    voterList,
			EpochManager: em,
		})
		voterNotificationChans = append(voterNotificationChans, v.NewNotificationChannel())
		voters = append(voters, v)
	}

	// Register the debug helper.
	var mediators []*consensus.Mediator
	mediators = append(mediators, proposer)
	mediators = append(mediators, voters...)

	handler := consensus.NewDumpDebugStateHandler(consensus.AsDumpers(mediators)...)
	signalChan := consensus.RegisterSignalHandlers(handler)
	defer utils.StopSignalHandler(signalChan)

	const nBlock = 30

	t.Run("normal case", func(t *testing.T) {
		detector.SetTrace()
		defer detector.Verify(t)

		req := require.New(t)

		err := proposer.Start()
		req.NoError(err)

		proposerHost := proposer.GetHostForTest()
		for _, v := range voters {
			err := v.Start()
			req.NoError(err)
			network.FakeConnect(v.GetHostForTest(), proposerHost)
		}

		// Expect the proposer and voters to finalize blocks.
		epoch := blockchain.NewEpoch(1, 1)
		verifyFinalizedChain(
			t, proposer.GetConsensusId(), proposerNotificationChan, epoch, 1, nBlock, true, nil)
		for i := 0; i < len(voters); i++ {
			verifyFinalizedChain(
				t, voters[i].GetConsensusId(), voterNotificationChans[i], epoch, 1, nBlock, true, nil)
		}
		// Stop proposers/voters.
		for _, m := range mediators {
			err = m.Stop()
			req.NoError(err)
			m.Wait()
		}
	})

	t.Run("wipe out proposer's data", func(t *testing.T) {
		detector.SetTrace()
		defer detector.Verify(t)

		req := require.New(t)

		// Manually update the epoch so that the proposer will propose (1,x,1)
		// after performing reconciliation. To test this case many times in a short time,
		// this manual update is necessary to reduce the waiting time to send clock messages.
		epoch = epoch.NextEpoch()
		cNota := blockchain.NewClockMsgNotaFake(epoch, voterIds)
		for _, em := range voterEpochManagers {
			em.UpdateByClockMsgNota(cNota)
		}

		// Create a new proposer to simulate wiping out the proposer's data.
		proposer, proposerChain := newProposer(epoch)
		proposerNotificationChan := proposer.NewNotificationChannel()
		mediators[0] = proposer

		// Restart the consensus nodes..
		err := proposer.Start()
		req.NoError(err)

		proposerHost := proposer.GetHostForTest()
		for _, v := range voters {
			err := v.Start()
			req.NoError(err)
			network.FakeConnect(v.GetHostForTest(), proposerHost)
		}

		// Verify the proposer.
		//
		// Expect the old data are back.
		// Note that when doing the chain sync, nodes only accept notarized blocks,
		// so we should not check more than nBlock.
		epoch := blockchain.NewEpoch(1, 1)
		verifyFinalizedChain(
			t, proposer.GetConsensusId(), proposerNotificationChan, epoch, 1, nBlock, true, proposerChain)
		// Expect the liveness is back.
		testutils.ExpectProgress(
			req, 3*time.Second, []*consensus.Mediator{proposer}, blockchain.NewBlockSn(1, 2, 1))
		var verified bool
		for i := 0; i < 5; i++ {
			epoch = epoch.NextEpoch()
			// Verify the parent block.
			sn := blockchain.BlockSn{Epoch: epoch, S: 1}
			b := proposerChain.GetBlock(sn)
			if b == nil {
				// We don't know how many timeouts happen until the proposer catches up
				// and make a valid proposal.
				continue
			}
			parentSn := b.GetParentBlockSn()
			req.Equal(blockchain.NewEpoch(1, 1), parentSn.Epoch)
			req.True(parentSn.S >= uint32(nBlock)+testutils.DefaultMaxUnnotarizedProposals,
				blockchain.DumpFakeChain(proposerChain, b, true))
			verified = true
			break
		}
		req.True(verified, "no liveness")

		// Verify voters.
		for i := 0; i < len(voters); i++ {
			verifyFinalizedChain(
				t, voters[i].GetConsensusId(), voterNotificationChans[i], epoch, 1, 10, true, nil)
		}

		// Stop proposers/voters.
		for _, m := range mediators {
			err = m.Stop()
			req.NoError(err)
			m.Wait()
		}
	})
}

func TestCatchUpAndVote(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)
	k := uint32(2)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	epoch := blockchain.NewEpoch(1, 2)
	voterIds := MakeConsensusIds("v1")
	em := blockchain.NewEpochManagerFake()
	cNota := blockchain.NewClockMsgNotaFake(epoch, voterIds)
	em.UpdateByClockMsgNota(cNota)
	beginEpoch := blockchain.Epoch{}
	proposerList := blockchain.NewElectionResultFake(MakeConsensusIds("p1"), beginEpoch.Session, epoch.Session)
	voterList := blockchain.NewElectionResultFake(voterIds, beginEpoch.Session, epoch.Session)
	proposer, proposerChain := testutils.NewMediatorForTest(testutils.MediatorTestConfig{
		LoggingId:    "p1",
		MyId:         ConsensusId("p1"),
		ProposerList: proposerList,
		VoterList:    voterList,
		EpochManager: em,
	})
	proposerHost := proposer.GetHostForTest()
	proposerNotificationChan := proposer.NewNotificationChannel()

	voter, _ := testutils.NewMediatorForTest(testutils.MediatorTestConfig{
		LoggingId:    "v1",
		MyId:         ConsensusId("v1"),
		ProposerList: proposerList,
		VoterList:    voterList,
	})
	voterNotificationChan := voter.NewNotificationChannel()

	// Let the proposer have longer freshest notarized chain,
	// so we can test the voter will catch up.
	pe, _ := epoch.PreviousEpoch()
	blockchain.PrepareFakeChain(req, proposerChain, blockchain.GetGenesisBlockSn(),
		pe, hardforkK, voterIds,
		[]string{"1", "2", "3", "4", "5", "6", "7", "8", "9"})

	err := voter.Start()
	req.NoError(err)

	err = proposer.Start()
	req.NoError(err)

	// Simulate the voter connects to the proposer.
	network.FakeConnect(voter.GetHostForTest(), proposerHost)

	// Verify
	verifyFinalizedChain(
		t, proposer.GetConsensusId(), proposerNotificationChan, epoch, 1, 10, false, nil)
	verifyFinalizedChain(
		t, voter.GetConsensusId(), voterNotificationChan, epoch, 1, 10, false, nil)

	// Stop proposers/voters.
	var mediators []*consensus.Mediator
	mediators = append(mediators, proposer, voter)
	for _, m := range mediators {
		err = m.Stop()
		req.NoError(err)
		m.Wait()
	}
}

func TestProposerSwitch(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	t.Run("simple case", func(t *testing.T) {
		detector.SetTrace()
		defer detector.Verify(t)

		req := require.New(t)

		// Prepare one proposer and one voter. The proposer becomes the primary one at epoch 3.
		proposerList := blockchain.NewElectionResultFake(MakeConsensusIds("p1", "p2", "p3"), 1, 1)
		voterList := blockchain.NewElectionResultFake(MakeConsensusIds("v1"), 1, 1)

		timer := consensus.NewTimerFake(blockchain.NewEpoch(1, 1))
		epoch3 := blockchain.NewEpoch(1, 3)
		timer.(*consensus.TimerFake).AllowAdvancingEpochTo(epoch3, 50*time.Millisecond)
		proposer3, proposerChain3 := testutils.NewMediatorForTest(testutils.MediatorTestConfig{
			LoggingId:    "p3",
			MyId:         ConsensusId("p3"),
			ProposerList: proposerList,
			VoterList:    voterList,
		})
		err := proposer3.Start()
		req.NoError(err)
		proposerNotificationChan3 := proposer3.NewNotificationChannel()

		voter, _ := testutils.NewMediatorForTest(testutils.MediatorTestConfig{
			LoggingId:    "v1",
			MyId:         ConsensusId("v1"),
			ProposerList: proposerList,
			VoterList:    voterList,
			Timer:        timer,
		})
		voterNotificationChan := voter.NewNotificationChannel()
		err = voter.Start()
		req.NoError(err)

		network.FakeConnect(voter.GetHostForTest(), proposer3.GetHostForTest())

		// Register the debug helper.
		var mediators []*consensus.Mediator
		mediators = append(mediators, proposer3, voter)

		handler := consensus.NewDumpDebugStateHandler(consensus.AsDumpers(mediators)...)
		signalChan := consensus.RegisterSignalHandlers(handler)
		defer utils.StopSignalHandler(signalChan)

		// Expect the liveness starts at epoch=3.
		verifyFinalizedChain(
			t, proposer3.GetConsensusId(), proposerNotificationChan3, epoch3, 1, 10, true, nil)
		verifyFinalizedChain(
			t, voter.GetConsensusId(), voterNotificationChan, epoch3, 1, 10, true, nil)

		b := proposerChain3.GetBlock(blockchain.BlockSn{Epoch: epoch3, S: 1})
		req.NotNil(b)
		parentSn := b.GetParentBlockSn()
		req.Equal(blockchain.GetGenesisBlockSn(), parentSn)

		// Stop proposers/voters.
		for _, m := range mediators {
			err = m.Stop()
			req.NoError(err)
			m.Wait()
		}
	})

	t.Run("switch to another and switch back to the original one", func(t *testing.T) {
		detector.SetTrace()
		defer detector.Verify(t)

		req := require.New(t)

		//
		// Prepare two proposers and three voters.
		//
		k := uint32(2)
		proposerList := blockchain.NewElectionResultFake(MakeConsensusIds("p1", "p2"), 1, 1)
		voterList := blockchain.NewElectionResultFake(MakeConsensusIds("v1", "v2", "v3"), 1, 1)

		// Prepare two proposers
		var proposers []*consensus.Mediator
		var proposerChains []blockchain.BlockChain
		var proposerNotificationChans []<-chan interface{}
		for i := 0; i < 2; i++ {
			id := fmt.Sprintf("p%d", i+1)
			p, chain := testutils.NewMediatorForTest(testutils.MediatorTestConfig{
				LoggingId:    id,
				MyId:         ConsensusId(id),
				ProposerList: proposerList,
				VoterList:    voterList,
			})

			err := p.Start()
			req.NoError(err)

			proposers = append(proposers, p)
			proposerChains = append(proposerChains, chain)
			proposerNotificationChans = append(
				proposerNotificationChans, p.NewNotificationChannel())
		}

		// Prepare three voters
		voterTimers := make(map[ConsensusId]consensus.Timer)
		var voters []*consensus.Mediator
		for i := 0; i < 3; i++ {
			idStr := fmt.Sprintf("v%d", i+1)
			id := ConsensusId(idStr)
			timer := consensus.NewTimerFake(blockchain.NewEpoch(1, 1))
			voterTimers[id] = timer
			v, _ := testutils.NewMediatorForTest(testutils.MediatorTestConfig{
				LoggingId:    idStr,
				MyId:         ConsensusId(idStr),
				ProposerList: proposerList,
				VoterList:    voterList,
				Timer:        timer,
			})
			voters = append(voters, v)

			err := v.Start()
			req.NoError(err)
		}

		// Register the debug helper.
		var mediators []*consensus.Mediator
		mediators = append(mediators, proposers...)

		mediators = append(mediators, voters...)

		handler := consensus.NewDumpDebugStateHandler(consensus.AsDumpers(mediators)...)
		signalChan := consensus.RegisterSignalHandlers(handler)
		defer utils.StopSignalHandler(signalChan)

		//
		// Prepare network connections.
		//
		// Simulate that p1 is offline after (1,1,10) is notarized.
		// Expect p2 takes over afterward.
		net := consensus.NewNetworkSimulator()
		epoch1 := blockchain.NewEpoch(1, 1)
		epoch2 := blockchain.NewEpoch(1, 2)
		epoch3 := blockchain.NewEpoch(1, 3)
		net.AddRule(consensus.NetworkSimulatorRule{
			From: MakeConsensusIds("p1"),
			To:   nil,
			Type: consensus.MessageNotarization,
			Sn:   blockchain.BlockSn{Epoch: epoch1, S: 10},
			Action: &network.FilterAction{
				PostCallback: func(from ConsensusId, to ConsensusId, typ uint8, blob []byte) network.PassedOrDropped {
					if timer, ok := voterTimers[to]; ok {
						timer.(*consensus.TimerFake).AllowAdvancingEpochTo(epoch2, 50*time.Millisecond)
					}
					return network.Dropped
				},
			},
		})
		// Simulate that p1 is online after (1,2,1)
		net.AddRule(consensus.NetworkSimulatorRule{
			From: MakeConsensusIds("p2"),
			To:   MakeConsensusIds("v1"),
			Type: consensus.MessageNotarization,
			Sn:   blockchain.BlockSn{Epoch: epoch2, S: 1},
			Action: &network.FilterAction{
				PostCallback: func(from ConsensusId, to ConsensusId, typ uint8, blob []byte) network.PassedOrDropped {
					net.Connect(proposers[0].GetHostForTest(), proposers[1].GetHostForTest())
					for _, v := range voters {
						net.Connect(v.GetHostForTest(), proposers[0].GetHostForTest())
					}
					return network.Passed
				},
			},
		})
		// Simulate that p2 is offline after (1,2,10) is notarized.
		// Expect p1 takes over afterward.
		net.AddRule(consensus.NetworkSimulatorRule{
			From: MakeConsensusIds("p2"),
			To:   nil,
			Type: consensus.MessageNotarization,
			Sn:   blockchain.BlockSn{Epoch: epoch2, S: 10},
			Action: &network.FilterAction{
				PostCallback: func(from ConsensusId, to ConsensusId, typ uint8, blob []byte) network.PassedOrDropped {
					if timer, ok := voterTimers[to]; ok {
						timer.(*consensus.TimerFake).AllowAdvancingEpochTo(epoch3, 50*time.Millisecond)
					}
					return network.Dropped
				},
			},
		})
		// Connect hosts.
		net.Connect(proposers[1].GetHostForTest(), proposers[0].GetHostForTest())
		for _, v := range voters {
			for _, p := range proposers {
				net.Connect(v.GetHostForTest(), p.GetHostForTest())
			}
		}

		// Test
		loggingId := proposers[0].GetConsensusId()
		ch := proposerNotificationChans[0]
		chain := proposerChains[0]
		verifyFinalizedChain(t, loggingId, ch, epoch1, 1, 10-2*k, true, chain)
		verifyFinalizedChain(t, loggingId, ch, epoch2, 1, 10-2*k, true, chain)
		verifyFinalizedChain(t, loggingId, ch, epoch3, 1, 10, true, chain)

		// Stop proposers/voters.
		for _, m := range mediators {
			err := m.Stop()
			req.NoError(err)
			m.Wait()
		}
	})
}

func TestChainOfTrust(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	// Create a chain (1, 1, 1), ..., (1, 2, 1), ..., (2, 1, 1), ..., (2, 2, 1), ...
	// and verify that we have the required notarizations and clock message notarizations
	// on the chain.

	if haveTestedChainOfTrust {
		return
	}
	haveTestedChainOfTrust = true

	// TODO(thunder): add the test after the test helper functions are added.
}

func TestMain(m *testing.M) {
	// We still need to initialize the hardfork configs which are loaded from the file.
	// server.SetupLogging(server.StdoutLogOutputMode, "", "")
	config.InitHardforkConfig("../../../config/")
	os.Exit(m.Run())
}

// TODO(thunder): test a voter is much behind and hard to catch up?
