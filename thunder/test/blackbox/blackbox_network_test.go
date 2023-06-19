//go:build !skipe2etest
// +build !skipe2etest

// Use a different package to ensure we only test the public API.
package blackbox

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/consensus"
	"github.com/ethereum/go-ethereum/thunder/pala/network"
	"github.com/ethereum/go-ethereum/thunder/pala/testutils"
	"github.com/ethereum/go-ethereum/thunder/pala/testutils/detector"

	"github.com/stretchr/testify/require"
)

const testWaitingTime = 200 * time.Millisecond

var connectingConfig = network.ConnectingConfig{
	// RetryTime >> WaitingTime; otherwise, there may be two goroutines
	// trying to connect to the same target simultaneously and make tests fail.
	RetryTime: 100 * time.Millisecond,
	// The value should >= testWaitingTime
	WaitingTime: 20 * time.Millisecond,
	// The value should < testWaitingTime
	BackOffBegin: 10 * time.Millisecond,
	BackOffEnd:   10 * time.Millisecond,
}

var palaDefaultMaxUnnotarizedProposals = uint32(2)

var palaParamsForRealNetwork = consensus.PalaParams{
	DelayOfMakingFirstProposal:     100 * time.Millisecond,
	VoterWaitingTimeBeforeClockMsg: 600 * time.Millisecond,
}

func createProposer(
	id ConsensusId, proposerList, voterList blockchain.ElectionResultFake, bootnodeAddresses []string,
) *consensus.Mediator {
	return createProposerWithAddresses(id, proposerList, voterList, bootnodeAddresses, nil)
}

func createProposerWithAddresses(
	id ConsensusId, proposerList, voterList blockchain.ElectionResultFake, bootnodeAddresses []string,
	proposerAddresses map[ConsensusId]string,
) *consensus.Mediator {
	palaParam := palaParamsForRealNetwork
	palaParam.K = config.NewInt64HardforkConfig("consensus.k", "")
	palaParam.K.SetTestValueAtSession(int64(palaDefaultMaxUnnotarizedProposals), 0)

	m, _ := testutils.NewMediatorForTest(testutils.MediatorTestConfig{
		LoggingId:         string(id),
		ProposerAddresses: proposerAddresses,
		MyId:              id,
		ProposerList:      proposerList,
		VoterList:         voterList,
		BootnodeConfig:    consensus.BootnodeConfig{TrustedAddresses: bootnodeAddresses},
		ConnectingConfig:  connectingConfig,
		Params:            palaParam,
	})
	return m
}

func createVoter(id ConsensusId, proposerList, voterList blockchain.ElectionResultFake, bootnodeAddresses []string,
) *consensus.Mediator {
	return createVoterWithAddresses(id, proposerList, voterList, bootnodeAddresses, nil)
}

func createVoterWithAddresses(
	id ConsensusId, proposerList, voterList blockchain.ElectionResultFake, bootnodeAddresses []string,
	proposerAddresses map[ConsensusId]string,
) *consensus.Mediator {
	palaParam := palaParamsForRealNetwork
	palaParam.K = config.NewInt64HardforkConfig("consensus.k", "")
	palaParam.K.SetTestValueAtSession(int64(palaDefaultMaxUnnotarizedProposals), 0)

	m, _ := testutils.NewMediatorForTest(testutils.MediatorTestConfig{
		LoggingId:         string(id),
		ProposerAddresses: proposerAddresses,
		MyId:              id,
		ProposerList:      proposerList,
		VoterList:         voterList,
		BootnodeConfig:    consensus.BootnodeConfig{TrustedAddresses: bootnodeAddresses},
		ConnectingConfig:  connectingConfig,
		Params:            palaParam,
	})
	return m
}

func verifyConnectionIsReady(req *require.Assertions, ch <-chan interface{}, id ConsensusId) {
	select {
	case e := <-ch:
		switch v := e.(type) {
		case consensus.ConnectionOpenEvent:
			req.Equal(id, v.Identity)
		default:
			req.FailNow("first event is not ConnectionOpenEvent",
				fmt.Sprintf("%T:%v", v, v))
		}
	case <-time.NewTimer(testWaitingTime).C:
		req.FailNow(fmt.Sprintf("no connection to %s", id))
	}
}

func verifyNoEvent(req *require.Assertions, ch <-chan interface{}) {
	select {
	case e := <-ch:
		req.FailNow("expect no event", fmt.Sprintf("%T %+v", e, e))
	case <-time.NewTimer(testWaitingTime).C:
	}
}

func verifyConnectionIsClosed(req *require.Assertions, ch <-chan interface{}, id ConsensusId) {
	select {
	case e := <-ch:
		switch v := e.(type) {
		case consensus.ConnectionClosedEvent:
			req.Equal(id, v.Identity)
		default:
			req.FailNow("first event is not ConnectionClosedEvent",
				fmt.Sprintf("%T:%v", v, v))
		}
	case <-time.NewTimer(testWaitingTime).C:
		req.FailNow("no closed event")
	}
}

// Aka the challenge-response authentication.
func TestRoleAuthentication(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	beginEpoch := blockchain.Epoch{}
	endEpoch := blockchain.NewEpoch(1, 1)
	proposerList := blockchain.NewElectionResultFake(MakeConsensusIds("p1"), beginEpoch.Session, endEpoch.Session)
	voterList := blockchain.NewElectionResultFake(MakeConsensusIds("v1"), beginEpoch.Session, endEpoch.Session)

	t.Run("voters connects to the proposer", func(t *testing.T) {
		detector.SetTrace()
		defer detector.Verify(t)

		req := require.New(t)

		proposerAddresses := map[ConsensusId]string{"p1": "localhost:0"}
		proposer := createProposerWithAddresses("p1", proposerList, voterList, nil, proposerAddresses)
		proposerNotificationChan := proposer.NewNotificationChannel()
		err := proposer.Start()
		req.NoError(err)
		defer func() { proposer.StopAndWait() }()

		// Update the port.
		// In theory, we cannot guarantee the proposer has started accepting, so keep trying.
		for strings.HasSuffix(proposerAddresses["p1"], ":0") {
			proposerAddresses["p1"] = proposer.GetHostForTest().GetBoundIPPort()
		}

		var voters []*consensus.Mediator
		var voterNotificationChans []<-chan interface{}
		for i := 1; i <= 2; i++ {
			id := ConsensusId(fmt.Sprintf("v%d", i))
			v := createVoterWithAddresses(id, proposerList, voterList, nil, proposerAddresses)
			err = v.Start()
			req.NoError(err)
			defer func() { v.StopAndWait() }()
			voters = append(voters, v)
			voterNotificationChans = append(voterNotificationChans, v.NewNotificationChannel())
		}

		// Verify.
		verifyConnectionIsReady(req, proposerNotificationChan, "v1")
		verifyConnectionIsReady(req, voterNotificationChans[0], "p1")
		verifyNoEvent(req, voterNotificationChans[1])
	})

	t.Run("an invalid voter connects to the bootnode", func(t *testing.T) {
		detector.SetTrace()
		defer detector.Verify(t)

		req := require.New(t)

		bootnodeId := ConsensusId("b1")
		bootnodeAddresses := []string{string(bootnodeId)}
		bootnode, _ := testutils.NewMediatorForTest(testutils.MediatorTestConfig{
			LoggingId:      string(bootnodeId),
			MyId:           bootnodeId,
			IsBootnode:     true,
			ProposerList:   proposerList,
			VoterList:      voterList,
			BootnodeConfig: consensus.BootnodeConfig{TrustedAddresses: bootnodeAddresses},
		})
		bootnodeNotificationChan := bootnode.NewNotificationChannel()
		err := bootnode.Start()
		req.NoError(err)
		defer func() { bootnode.StopAndWait() }()

		voter := createVoter("invalid-voter", proposerList, voterList, bootnodeAddresses)
		voterNotificationChan := voter.NewNotificationChannel()
		err = voter.Start()
		req.NoError(err)
		defer func() { voter.StopAndWait() }()

		network.FakeConnect(voter.GetHostForTest(), bootnode.GetHostForTest())

		// Verify.
		verifyConnectionIsReady(req, bootnodeNotificationChan, "invalid-voter")
		verifyConnectionIsReady(req, voterNotificationChan, "b1")
	})
}

func TestDuplicatedConnections(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	beginEpoch := blockchain.Epoch{}
	endEpoch := blockchain.NewEpoch(1, 1)
	proposerList := blockchain.NewElectionResultFake(MakeConsensusIds("p1"), beginEpoch.Session, endEpoch.Session)
	// To simplify the received events, require two voters and only run one voter
	// to stop the liveness.
	voterList := blockchain.NewElectionResultFake(MakeConsensusIds("v1", "v2"), beginEpoch.Session, endEpoch.Session)

	t.Run("test fake connections", func(t *testing.T) {
		detector.SetTrace()
		defer detector.Verify(t)

		req := require.New(t)

		proposer := createProposer("p1", proposerList, voterList, nil)
		proposerNotificationChan := proposer.NewNotificationChannel()
		err := proposer.Start()
		req.NoError(err)
		defer func() { proposer.StopAndWait() }()

		voter := createVoter("v1", proposerList, voterList, nil)
		voterNotificationChan := voter.NewNotificationChannel()
		err = voter.Start()
		req.NoError(err)
		defer func() { voter.StopAndWait() }()

		network.FakeConnect(voter.GetHostForTest(), proposer.GetHostForTest())

		// Verify.
		verifyConnectionIsReady(req, proposerNotificationChan, "v1")
		verifyConnectionIsReady(req, voterNotificationChan, "p1")

		// Connect again.
		network.FakeConnect(voter.GetHostForTest(), proposer.GetHostForTest())

		// Expect the old connections are closed.
		verifyConnectionIsClosed(req, proposerNotificationChan, "v1")
		verifyConnectionIsClosed(req, voterNotificationChan, "p1")

		// Expect the new connections are established.
		verifyConnectionIsReady(req, proposerNotificationChan, "v1")
		verifyConnectionIsReady(req, voterNotificationChan, "p1")
	})

	t.Run("test real connections", func(t *testing.T) {
		detector.SetTrace()
		defer detector.Verify(t)

		req := require.New(t)

		proposerAddresses := map[ConsensusId]string{
			"p1": fmt.Sprintf("localhost:%d", testutils.NextTestingPort(testutils.TestGroupConsensus)),
		}

		proposer := createProposerWithAddresses("p1", proposerList, voterList, nil, proposerAddresses)
		proposerNotificationChan := proposer.NewNotificationChannel()
		err := proposer.Start()
		req.NoError(err)
		defer func() { proposer.StopAndWait() }()

		voter := createVoterWithAddresses("v1", proposerList, voterList, nil, proposerAddresses)
		voterNotificationChan := voter.NewNotificationChannel()
		err = voter.Start()
		req.NoError(err)
		defer func() { voter.StopAndWait() }()

		// Verify.
		verifyConnectionIsReady(req, proposerNotificationChan, "v1")
		verifyConnectionIsReady(req, voterNotificationChan, "p1")

		for i := 0; i < 3; i++ {
			// Force reconnect
			voter.ConnectForTest(proposerAddresses)

			// Expect no event because the action is skipped due to using the same address.
			verifyNoEvent(req, proposerNotificationChan)
			verifyNoEvent(req, voterNotificationChan)
		}
	})
}

func TestConnectCancel(t *testing.T) {
	d := detector.NewBundleDetector()
	d.SetTrace()
	defer d.Verify(t)

	req := require.New(t)

	proposerIds := MakeConsensusIds("p1")
	voterIds := MakeConsensusIds("v1")
	beginEpoch := blockchain.Epoch{}
	endEpoch := blockchain.NewEpoch(1, 1)
	proposerList := blockchain.NewElectionResultFake(proposerIds, beginEpoch.Session, endEpoch.Session)
	proposerAddresses := map[ConsensusId]string{
		"p1": fmt.Sprintf("localhost:%d", testutils.NextTestingPort(testutils.TestGroupConsensus)),
	}
	voterList := blockchain.NewElectionResultFake(voterIds, beginEpoch.Session, endEpoch.Session)
	v := createVoterWithAddresses(voterIds[0], proposerList, voterList, nil, proposerAddresses)
	err := v.Start()
	req.NoError(err)
	v.StopAndWait()
	v.GetHostForTest().CloseAllConnections()
}

func TestKeepReconnecting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow tests in short mode")
	}

	d := detector.NewBundleDetector()
	d.SetTrace()
	defer d.Verify(t)

	req := require.New(t)

	proposerIds := MakeConsensusIds("p1", "p2")
	proposerList := blockchain.NewElectionResultFake(proposerIds, 1, 1)
	// To simplify the received events, require two voters and only run one voter
	// to stop the liveness.
	voterList := blockchain.NewElectionResultFake(MakeConsensusIds("v1", "v2"), 1, 1)

	// The voter keeps connecting the proposers even before the proposers start.
	// Thus, we need to use designated ports instead of anonymous ports.
	proposerAddresses := map[ConsensusId]string{
		"p1": fmt.Sprintf("localhost:%d", testutils.NextTestingPort(testutils.TestGroupConsensus)),
		"p2": fmt.Sprintf("localhost:%d", testutils.NextTestingPort(testutils.TestGroupConsensus)),
	}

	var proposers []*consensus.Mediator
	for _, id := range proposerIds {
		p := createProposerWithAddresses(id, proposerList, voterList, nil, proposerAddresses)
		proposers = append(proposers, p)
	}
	voter := createVoterWithAddresses("v1", proposerList, voterList, nil, proposerAddresses)
	voterNotificationChan := voter.NewNotificationChannel()

	err := voter.Start()
	req.NoError(err)
	defer voter.StopAndWait()

	//
	// Verify reconnecting after proposers start.
	//
	verifyNoEvent(req, voterNotificationChan)
	for _, p := range proposers {
		// Start the proposer and expect v1 connected to the proposer.
		err := p.Start()
		req.NoError(err)
		defer p.StopAndWait()

		verifyConnectionIsReady(req, voterNotificationChan, p.GetConsensusId())
	}

	//
	// Verify reconnecting after connections are closed.
	//
	voter.GetHostForTest().CloseAllConnections()

	closed := make(map[ConsensusId]bool)
	for i := 0; i < len(proposers); i++ {
		// Expect closed event.
		select {
		case e := <-voterNotificationChan:
			switch v := e.(type) {
			case consensus.ConnectionClosedEvent:
				closed[v.Identity] = true
			default:
				req.FailNow("first event is not ConnectionClosedEvent",
					fmt.Sprintf("%T:%v", v, v))
			}
		case <-time.NewTimer(testWaitingTime).C:
			req.FailNow("no closed event")
		}
	}
	for _, id := range proposerIds {
		req.True(closed[id], id)
	}

	// Verify the voter reconnects to proposers.
	connected := make(map[ConsensusId]bool)
	for i := 0; i < len(proposers); i++ {
		select {
		case e := <-voterNotificationChan:
			switch v := e.(type) {
			case consensus.ConnectionOpenEvent:
				connected[v.Identity] = true
			default:
				req.FailNow("first event is not ConnectionOpenEvent",
					fmt.Sprintf("%T:%v", v, v))
			}
		case <-time.NewTimer(testWaitingTime).C:
			req.FailNow("no ConnectionOpenEvent", fmt.Sprintf("i=%d", i))
		}
	}
	for _, id := range proposerIds {
		req.True(connected[id], id)
	}
}

// portFromAddrPort("localhost:8888") -> 8888
func portFromAddrPort(addrPort string) int64 {
	i := strings.IndexRune(addrPort, ':')
	if i == -1 {
		return 8888
	}
	portStr := addrPort[i+1:]
	port, err := strconv.ParseInt(portStr, 10, 64)
	if err != nil {
		debug.Bug("ParseInt(%q) failed: %s", portStr, err)
	}
	return port
}

func TestLivenessUsingRealNetwork(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	epoch := blockchain.NewEpoch(1, 1)
	proposerAddresses := map[ConsensusId]string{
		"p1": fmt.Sprintf("localhost:%d", testutils.NextTestingPort(testutils.TestGroupConsensus)),
	}
	proposerList := blockchain.NewElectionResultFake(MakeConsensusIds("p1"), epoch.Session, epoch.Session)
	voterIds := MakeConsensusIds("v1", "v2", "v3")
	voterList := blockchain.NewElectionResultFake(voterIds, epoch.Session, epoch.Session)
	bootnodeAddresses := []string{
		fmt.Sprintf("localhost:%d", testutils.NextTestingPort(testutils.TestGroupConsensus)),
		fmt.Sprintf("localhost:%d", testutils.NextTestingPort(testutils.TestGroupConsensus)),
	}

	// Prepare the proposer
	palaParam := palaParamsForRealNetwork
	palaParam.K = config.NewInt64HardforkConfig("consensus.k", "")
	palaParam.K.SetTestValueAtSession(int64(palaDefaultMaxUnnotarizedProposals), 0)

	proposer, _ := testutils.NewMediatorForTest(testutils.MediatorTestConfig{
		LoggingId:         "p1",
		ProposerAddresses: proposerAddresses,
		MyId:              ConsensusId("p1"),
		ProposerList:      proposerList,
		VoterList:         voterList,
		BootnodeConfig:    consensus.BootnodeConfig{TrustedAddresses: bootnodeAddresses},
		ConnectingConfig:  connectingConfig,
		Params:            palaParam,
	})

	// Prepare three voters
	var voters []*consensus.Mediator
	var voterNotificationChans []<-chan interface{}
	for _, id := range voterIds {
		v, _ := testutils.NewMediatorForTest(testutils.MediatorTestConfig{
			LoggingId:         string(id),
			ProposerAddresses: proposerAddresses,
			MyId:              id,
			ProposerList:      proposerList,
			VoterList:         voterList,
			BootnodeConfig:    consensus.BootnodeConfig{TrustedAddresses: bootnodeAddresses},
			ConnectingConfig:  connectingConfig,
			Params:            palaParam,
		})
		voterNotificationChans = append(voterNotificationChans, v.NewNotificationChannel())
		voters = append(voters, v)
	}

	// Prepare two bootnodes
	var bootnodes []*consensus.Mediator
	var bootnodeNotificationChans []<-chan interface{}
	for i, addr := range bootnodeAddresses {
		bootnodekConfig := consensus.BootnodeConfig{
			ListenPort:       portFromAddrPort(addr),
			OwnPublicAddress: addr,
			TrustedAddresses: bootnodeAddresses,
		}
		idStr := fmt.Sprintf("b%d", i+1)
		b, _ := testutils.NewMediatorForTest(testutils.MediatorTestConfig{
			LoggingId:         idStr,
			MyId:              ConsensusId(idStr),
			ProposerAddresses: proposerAddresses,
			ProposerList:      proposerList,
			VoterList:         voterList,
			BootnodeConfig:    bootnodekConfig,
			ConnectingConfig:  connectingConfig,
			Params:            palaParam,
		})
		bootnodeNotificationChans = append(bootnodeNotificationChans, b.NewNotificationChannel())
		bootnodes = append(bootnodes, b)
	}

	// Register the debug helper.
	var mediators []*consensus.Mediator
	mediators = append(mediators, proposer)
	mediators = append(mediators, voters...)
	mediators = append(mediators, bootnodes...)

	sh := consensus.NewDumpDebugStateHandler(consensus.AsDumpers(mediators)...)
	signalChan := consensus.RegisterSignalHandlers(sh)
	defer utils.StopSignalHandler(signalChan)

	req := require.New(t)

	// Start the proposer and voters.
	for _, m := range mediators {
		err := m.Start()
		req.NoError(err)
	}

	ms := []*consensus.Mediator{proposer}
	ms = append(ms, voters...)
	ms = append(ms, bootnodes...)
	// Wait until there is some progress. Note that there may be a timeout at the beginning
	// since the timeout period is short in the test. Thus, don't verify the detailed BlockSn.
	for i := 0; i < 10; i++ {
		testutils.ExpectProgress(req, time.Second, ms, blockchain.BlockSn{})
	}

	for _, m := range mediators {
		err := m.Stop()
		req.NoError(err)
		m.Wait()
	}
}
