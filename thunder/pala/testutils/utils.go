package testutils

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"
	"path"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/consensus"
	"github.com/ethereum/go-ethereum/thunder/pala/consensus/chainsync"
	"github.com/ethereum/go-ethereum/thunder/pala/metrics"
	"github.com/ethereum/go-ethereum/thunder/pala/network"
	"github.com/ethereum/go-ethereum/thunder/pala/types"
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"
	"github.com/ethereum/go-ethereum/thunder/thunderella/testutils"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"
)

type ConsensusId = types.ConsensusId

var ConsensusIds = types.ConsensusIds

var (
	logger       = lgr.NewLgr("/testutils")
	timeoutDelay = 300 * time.Millisecond

	DefaultMaxUnnotarizedProposals = uint32(2)

	DefaultPalaParamsForTest = consensus.PalaParams{
		DelayOfMakingFirstProposal:     10 * time.Millisecond,
		VoterWaitingTimeBeforeClockMsg: 60 * time.Millisecond,
	}
)

type commInfoCmpFunc func(req *require.Assertions, tries int, commInfo *committee.CommInfo) bool

type MediatorTestConfig struct {
	LoggingId              string
	ProposerAddresses      map[ConsensusId]string
	MyId                   ConsensusId
	ProposerList           blockchain.ElectionResultFake
	VoterList              blockchain.ElectionResultFake
	IsBootnode             bool
	Params                 consensus.PalaParams
	StopBlockSessionOffset uint64
	BlockDelayInMS         uint64
	Reconfigurer           consensus.Reconfigurer
	EpochManager           blockchain.EpochManager
	Timer                  consensus.Timer
	Metrics                metrics.PalaMetrics
	BootnodeConfig         consensus.BootnodeConfig
	ConnectingConfig       network.ConnectingConfig
}

//------------------------------------------------------------------------------

var testingPort = uint32(10000)

type TestGroup int

const (
	TestGroupConsensus = 0
	TestGroupServer    = 1
	TestGroupNetwork   = 2
)

func NextTestingPort(g TestGroup) int {
	for {
		p := testingPort
		if atomic.CompareAndSwapUint32(&testingPort, p, p+1) {
			return int(p) + int(g)*1000
		}
	}
}

func NewTestCommInfo() committee.CommInfo {
	return testutils.TestingCommInfo
}

type FakeRpcSwitch struct {
	running       bool
	statusChanges []bool
	err           error
}

func (r *FakeRpcSwitch) SuspendRpc() {
	r.running = false
	r.statusChanges = append(r.statusChanges, r.running)
}

func (r *FakeRpcSwitch) ResumeRpc() error {
	if r.err != nil {
		return r.err
	}
	r.running = true
	r.statusChanges = append(r.statusChanges, r.running)
	return nil
}

func (r *FakeRpcSwitch) Error() error {
	return r.err
}

func (r *FakeRpcSwitch) Status() bool {
	return r.running
}

func (r *FakeRpcSwitch) GetStatusChanges() []bool {
	return r.statusChanges
}

func NewFakeRpcSwitch() consensus.RpcSwitch {
	return &FakeRpcSwitch{
		running:       true,
		statusChanges: []bool{},
	}
}

// NOTE: we'll reuse this function in many places (e.g., a benchmark program),
// so do not access code related to testing.
func NewMediatorForTest(cfg MediatorTestConfig) (*consensus.Mediator, blockchain.BlockChain) {
	if cfg.MyId == "" {
		debug.Bug("cfg.MyId must be assigned")
	}

	if cfg.StopBlockSessionOffset == 0 {
		cfg.StopBlockSessionOffset = 1000000
	}

	k := int64(0)
	if cfg.Params.K != nil {
		k = cfg.Params.K.GetValueAtSession(0)
	}

	if k == 0 {
		cfg.Params = DefaultPalaParamsForTest
		cfg.Params.K = config.NewInt64HardforkConfig("consensus.k", "")
		cfg.Params.K.SetTestValueAtSession(int64(DefaultMaxUnnotarizedProposals), 0)
	}

	chain, _ := blockchain.NewBlockChainFakeWithDelay(
		cfg.Params.K, time.Duration(cfg.BlockDelayInMS)*time.Millisecond, cfg.StopBlockSessionOffset)
	unmarshaller := &blockchain.DataUnmarshallerFake{}

	role := consensus.CreateRoleAssignerForTest(
		cfg.LoggingId,
		cfg.MyId,
		consensus.IsBootnodeViaBootnodeConfig(cfg.BootnodeConfig),
		cfg.Params.K,
		int64(cfg.StopBlockSessionOffset),
	)
	stakes := consensus.MakeStakes(len(cfg.ProposerList.GetConsensusIds()), big.NewInt(int64(100)))
	for s, end := cfg.ProposerList.GetRange(); s <= end; s++ {
		role.(*consensus.RoleAssignerImpl).AddSessionCommittee(blockchain.Session(s), cfg.ProposerList.GetConsensusIds(), cfg.VoterList.GetConsensusIds(), stakes)
	}
	verifier := blockchain.NewVerifierFake(
		cfg.MyId, cfg.ProposerList, cfg.VoterList)
	if cfg.Reconfigurer == nil {
		cfg.Reconfigurer = consensus.NewReconfigurerFake("anonymous")
	}
	if cfg.EpochManager == nil {
		cfg.EpochManager = blockchain.NewEpochManagerFake()
	}
	if cfg.Timer == nil {
		cfg.Timer = consensus.NewTimer(cfg.EpochManager.GetEpoch())
	}
	syncDuration := time.Duration(cfg.BlockDelayInMS) * time.Millisecond
	if syncDuration == 0 {
		syncDuration = 100 * time.Millisecond
	}

	mediatorCfg := consensus.MediatorConfig{
		LoggingId:          cfg.LoggingId,
		Params:             cfg.Params,
		NetworkId:          123, // Just some fixed value is enough for the test.
		BlockChain:         chain,
		DataUnmarshaller:   unmarshaller,
		Reconfigurer:       cfg.Reconfigurer,
		EpochManager:       cfg.EpochManager,
		Role:               role,
		ConnectingConfig:   cfg.ConnectingConfig,
		BootnodeConfig:     cfg.BootnodeConfig,
		Verifier:           verifier,
		ClockMessageTimer:  cfg.Timer,
		SyncDuration:       syncDuration,
		Selector:           chainsync.SelectMax,
		Metrics:            cfg.Metrics,
		ClientPuzzleMgrCfg: &network.ClientPuzzleMgrCfg{Preference: network.GetPreferenceForTest()},
		RpcSwitch:          NewFakeRpcSwitch(),
		RpcMaxDelayBlock:   3,
		RpcSuspendBuffer:   100 * time.Millisecond,
	}

	mediator := consensus.NewMediator(mediatorCfg)
	if cfg.ProposerAddresses != nil {
		chain.(*blockchain.BlockChainImpl).SetProposerAddressesForTest(
			cfg.EpochManager.GetEpoch().Session, cfg.ProposerAddresses)
	} else {
		mediator.UseFakeNetworkForTest()
	}
	return mediator, chain
}

func ConcatMediatorSlices(medss ...[]*consensus.Mediator) []*consensus.Mediator {
	l := 0
	for _, meds := range medss {
		l += len(meds)
	}
	r := make([]*consensus.Mediator, 0, l)
	for _, meds := range medss {
		r = append(r, meds...)
	}
	return r

}

func MakeIds(prefix string, num int) []ConsensusId {
	r := make([]ConsensusId, num)
	for i := 0; i < num; i++ {
		r[i] = ConsensusId(fmt.Sprintf("%s%d", prefix, i))
	}
	return r
}

func ExpectProgress(
	req *require.Assertions, dur time.Duration, nodes []*consensus.Mediator, target blockchain.BlockSn,
	msgAndArgs ...interface{}) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var sb strings.Builder
	for _, m := range nodes {
		wg.Add(1)
		go func(med *consensus.Mediator) {
			defer wg.Done()
			timer := time.NewTimer(dur)
			ch := med.NewNotificationChannel()
			defer med.RemoveNotificationChannel(ch)
			for {
				select {
				case evt := <-ch:
					switch v := evt.(type) {
					case consensus.FinalizedChainExtendedEvent:
						if target.IsNil() || v.Sn.Compare(target) >= 0 {
							return
						}
					}
				case <-timer.C:
					bc := med.GetBlockChainForTest()
					mu.Lock()
					sb.WriteString(fmt.Sprintf("node: %s\t(finalized head: %s %d)\n",
						med.GetConsensusId(),
						bc.GetFinalizedHeadSn(),
						bc.GetFinalizedHead().GetNumber()))
					mu.Unlock()
					return
				}
			}
		}(m)
	}
	wg.Wait()
	if sb.String() != "" {
		var sb0 strings.Builder
		if len(msgAndArgs) > 0 {
			fmtStr := msgAndArgs[0].(string)
			args := msgAndArgs[1:]
			sb0.WriteString(fmt.Sprintf(fmtStr, args...))
			sb0.WriteRune('\n')
		}
		sb0.WriteString("Failed node states:\n")
		sb0.WriteString(sb.String())
		req.Fail("expected progress", sb0.String())
	}
}

func ExpectReconfiguration(req *require.Assertions, dur time.Duration, nodes []*consensus.Mediator, cmpFunc commInfoCmpFunc) {
	wg := sync.WaitGroup{}
	for _, m := range nodes {
		wg.Add(1)
		go func(med *consensus.Mediator) {
			defer wg.Done()
			timer := time.NewTimer(dur)
			ch := med.NewNotificationChannel()
			defer med.RemoveNotificationChannel(ch)
			var session blockchain.Session
			tries := 0
		Loop:
			for {
				select {
				case evt := <-ch:
					switch v := evt.(type) {
					case consensus.FinalizedChainExtendedEvent:
						if v.ReconfigurationBeginTriggered {
							commInfo := med.GetBlockChainForTest().(*blockchain.BlockChainImpl).GetCommInfo(v.Sn.Epoch.Session + 1)
							tries++
							if !cmpFunc(req, tries, commInfo) {
								continue
							}
							session = v.Sn.Epoch.Session
							break Loop
						}
					}
				case <-timer.C:
					req.Fail("Reconfiguration did not happen")
				}
			}
			for {
				select {
				case evt := <-ch:
					switch v := evt.(type) {
					case consensus.FinalizedChainExtendedEvent:
						if v.ReconfigurationEndTriggered {
							req.Greater(uint32(v.Sn.Epoch.Session), uint32(session))
							return
						}
					}
				case <-timer.C:
					req.Failf("Reconfiguration did not end", "session %s", session)
				}
			}
		}(m)
	}
	wg.Wait()
}

func ExpectNoProgress(req *require.Assertions, dur time.Duration, nodes []*consensus.Mediator) {
	// let buffered messages resolve (may be some progress)
	time.Sleep(time.Millisecond * 200)

	// get current block number
	lastBlock := uint64(0)
	for _, e := range nodes {
		lb := e.GetBlockChainForTest().GetFinalizedHead().GetNumber()
		if lb > lastBlock {
			lastBlock = lb
		}
	}

	// expect no progress
	time.Sleep(dur)
	for _, e := range nodes {
		req.True(lastBlock >= e.GetBlockChainForTest().GetFinalizedHead().GetNumber(),
			"expected no progress")
	}
}

func CheckVoters(sortedVotingKeys [][32]byte) commInfoCmpFunc {
	return func(req *require.Assertions, tries int, commInfo *committee.CommInfo) bool {
		votingKeys := make([][32]byte, commInfo.NumCommittee())
		req.Equal(len(sortedVotingKeys), len(commInfo.MemberInfo), "voting key sizes are differenet")
		for i, c := range commInfo.MemberInfo {
			votingKeys[i] = sha256.Sum256(c.PubVoteKey.ToBytes())
		}
		sort.Slice(votingKeys, func(i, j int) bool {
			return bytes.Compare(votingKeys[i][:], votingKeys[j][:]) < 0
		})

		// bidding might take effect at the next session, give it a chance
		if tries > 1 {
			req.Equal(sortedVotingKeys, votingKeys, "voting keys are different")
		}
		return reflect.DeepEqual(sortedVotingKeys, votingKeys)
	}
}

func CheckVoterSize(size int) commInfoCmpFunc {
	return func(req *require.Assertions, tries int, commInfo *committee.CommInfo) bool {
		// bidding might take effect at the next session, give it a chance
		if tries > 1 {
			req.Equal(size, commInfo.NumCommittee(), "number of voters are as expected")
		}
		return commInfo.NumCommittee() == size
	}
}

// ConnectionFakeMap tracks network connections such that they can be open/closed.
// Note that the logging id (i.e. GetLoggingId()) must be unique for each node or this will break.
// Also note that ConnectionFakeMap only tracks connections that were added through AddConnection method.
// Outside connections and disconnects must be manually added and removed to ensure the ConnectionFakeMap is in sync.
type ConnectionFakeMap struct {
	// map of node ID to map of connected node ID to ConnectionFakePair
	// each ConnectionFakePair will show up twice to allow easy access from either Node
	// uses the node's logging ID as keys, make sure they are all unique
	connections map[ConsensusId](map[ConsensusId]network.ConnectionFakePair)
}

func NewConnectionFakeMap() *ConnectionFakeMap {
	return &ConnectionFakeMap{
		connections: make(map[ConsensusId](map[ConsensusId]network.ConnectionFakePair)),
	}
}

func (cfm *ConnectionFakeMap) RemoveConnection(id1, id2 ConsensusId) {
	logger.Info("removing connection between %s %s", id1, id2)
	cm1 := cfm.connections[id1]
	cm2 := cfm.connections[id2]

	// closing one end will close the other
	cm1[id2].Close()

	// clean out our connection
	delete(cm1, id2)
	delete(cm2, id1)
}

// IsConnected retruns true if a connection exists
// note IsConnected does not check if the connection was closed, it is up to the user to remove closed connections
// i.e. if a node is shut down, it will close the connection but ConnectionFakeMap will not know about it
func (cfm *ConnectionFakeMap) IsConnected(id1, id2 ConsensusId) bool {
	if m, ok := cfm.connections[id1]; ok {
		_, ok2 := m[id2]
		return ok2
	}
	return false
}

func (cfm *ConnectionFakeMap) AddConnection(id1, id2 ConsensusId, pair network.ConnectionFakePair) {
	m1, ok1 := cfm.connections[id1]
	if !ok1 {
		m1 = make(map[ConsensusId]network.ConnectionFakePair)
		cfm.connections[id1] = m1
	}
	m2, ok2 := cfm.connections[id2]
	if !ok2 {
		m2 = make(map[ConsensusId]network.ConnectionFakePair)
		cfm.connections[id2] = m2
	}
	m1[id2] = pair
	m2[id1] = pair
}

func ConnectAll(hubs []*consensus.Mediator, spokes []*consensus.Mediator, cfm *ConnectionFakeMap) {
	ConnectAllWithFilter(hubs, spokes, cfm, network.Delay{}, nil, nil, nil)
}

func ConnectAllWithFilter(hubs []*consensus.Mediator, spokes []*consensus.Mediator, cfm *ConnectionFakeMap,
	delay network.Delay, wg *sync.WaitGroup, stopChan chan interface{}, filter network.Filter) {
	// create multi-hub-and-spoke network connections
	for _, e := range ConcatMediatorSlices(hubs, spokes) {
		for _, f := range hubs {
			id1 := e.GetConsensusId()
			id2 := f.GetConsensusId()
			if id1 != id2 {
				if !cfm.IsConnected(id1, id2) {
					logger.Info("connecting nodes %s and %s", e.GetConsensusId(), f.GetConsensusId())
					conn := network.FakeConnectWithFilter(e.GetHostForTest(), f.GetHostForTest(),
						wg, stopChan, delay, filter)
					cfm.AddConnection(id1, id2, conn)
				}
			}
		}
	}
}

type PalaNodeClusterConfig struct {
	ProposerIds     []ConsensusId
	VoterIds        []ConsensusId
	BootnodesITrust []ConsensusId // bootnodes I trust

	GenesisProposerIds []ConsensusId
	GenesisVoterIds    []ConsensusId

	Params                         consensus.PalaParams
	BlockDelayInMs                 uint64
	ElectionStopBlockSessionOffset uint64

	UseMetrics bool
}

type PalaNodeCluster struct {
	Proposers []*consensus.Mediator
	Voters    []*consensus.Mediator
	Bootnodes []*consensus.Mediator

	reconfigurers    map[ConsensusId]*consensus.ReconfigurerFake
	networkCallbacks map[blockchain.Session]PalaNodeClusterNetworkCallback

	writers           []metrics.MetricsWriter
	unnotarizedWindow *config.Int64HardforkConfig
}

type PalaNodeClusterNetworkCallback func(session blockchain.Session, id ConsensusId)

func BootnodeConfigForFake() consensus.BootnodeConfig {
	// For tests using the fake Network, `BootnodeListenPort` is only used by
	// NewMediatorXxx to detect that a node should be a bootnode.
	// The port number doesn't matter.
	return consensus.BootnodeConfig{
		ListenPort:       8888,
		OwnPublicAddress: "FAKE-NETWORK-bootnode-ADDRESS",
	}
}

func NewPalaNodeCluster(cfg PalaNodeClusterConfig) *PalaNodeCluster {
	k := int64(0)

	if cfg.Params.K != nil {
		k = cfg.Params.K.GetValueAtSession(0)
	}
	if k == 0 {
		cfg.Params = DefaultPalaParamsForTest
		cfg.Params.K = config.NewInt64HardforkConfig("", "")
		cfg.Params.K.SetTestValueAtSession(int64(DefaultMaxUnnotarizedProposals), 0)
	}

	if cfg.Params.VoterWaitingTimeBeforeClockMsg == 0 {
		cfg.Params.VoterWaitingTimeBeforeClockMsg = timeoutDelay
	}

	proposerList := blockchain.NewElectionResultFake(
		cfg.GenesisProposerIds, blockchain.Session(1), blockchain.Session(1))
	voterList := blockchain.NewElectionResultFake(
		cfg.GenesisVoterIds, blockchain.Session(1), blockchain.Session(1))

	// Create nodes
	proposers := make([]*consensus.Mediator, len(cfg.ProposerIds))
	voters := make([]*consensus.Mediator, len(cfg.VoterIds))
	bootnodes := make([]*consensus.Mediator, len(cfg.BootnodesITrust))

	var bootnodeAddresses []string
	for _, id := range cfg.BootnodesITrust {
		bootnodeAddresses = append(bootnodeAddresses, string(id))
	}

	var writers []metrics.MetricsWriter
	reconfigurers := make(map[ConsensusId]*consensus.ReconfigurerFake)

	create := func(ids []ConsensusId, isProposer bool, isVoter bool, isBootnode bool) {
		for i, e := range ids {
			var pm metrics.PalaMetrics
			var mw metrics.MetricsWriter
			if cfg.UseMetrics {
				pm, mw = metrics.NewPalaMetricsWithWriter(string(e) /*logId*/, false)
				writers = append(writers, mw)
			}
			r := consensus.NewReconfigurerFake(string(e) /*loggingId*/)
			reconfigurers[e] = r
			var bCfg consensus.BootnodeConfig
			if isBootnode {
				bCfg = BootnodeConfigForFake()
			}
			bCfg.TrustedAddresses = bootnodeAddresses
			mCfg := MediatorTestConfig{
				LoggingId:              string(e),
				ProposerList:           proposerList,
				VoterList:              voterList,
				BootnodeConfig:         bCfg,
				Params:                 cfg.Params,
				BlockDelayInMS:         cfg.BlockDelayInMs,
				Metrics:                pm,
				StopBlockSessionOffset: cfg.ElectionStopBlockSessionOffset,
				Reconfigurer:           r,
			}
			mCfg.MyId = e
			m, _ := NewMediatorForTest(mCfg)
			if isProposer {
				proposers[i] = m
			} else if isVoter {
				voters[i] = m
			} else if isBootnode {
				bootnodes[i] = m
			}
		}
	}
	create(cfg.ProposerIds, true, false, false)
	create(cfg.VoterIds, false, true, false)
	create(cfg.BootnodesITrust, false, false, true)

	cluster := &PalaNodeCluster{
		Proposers:         proposers,
		Voters:            voters,
		Bootnodes:         bootnodes,
		reconfigurers:     reconfigurers,
		networkCallbacks:  make(map[blockchain.Session]PalaNodeClusterNetworkCallback),
		writers:           writers,
		unnotarizedWindow: cfg.Params.K,
	}

	for id, r := range cluster.reconfigurers {
		setReconfigurerFakeNetworkCallback(cluster, id, r)
	}

	return cluster
}

// Use a new function to create the closure such that the closure accesses less variables.
func setReconfigurerFakeNetworkCallback(
	cluster *PalaNodeCluster, id ConsensusId, r *consensus.ReconfigurerFake) {
	r.SetNetworkReconfiguration(func(
		session blockchain.Session, bc blockchain.BlockChain, host *network.Host) error {
		if callback, ok := cluster.networkCallbacks[session]; ok {
			callback(session, id)
		} else {
			logger.Info("no network callback for session=%d, id=%s", session, id)
		}
		return nil
	})
}

func StartNodes(nodes []*consensus.Mediator) error {
	var err error
	for _, m := range nodes {
		logger.Info("starting %s", m.GetConsensusId())
		err = m.Start()
		if err != nil {
			return err
		}
	}
	return nil
}

func StopNodesAndWipeData(nodes []*consensus.Mediator) error {
	if err := StopNodes(nodes); err != nil {
		return err
	}

	e := blockchain.NewEpoch(1, 1)
	for i := 0; i < len(nodes); i++ {
		nodes[i].GetBlockChainForTest().(*blockchain.BlockChainImpl).ResetForTest()
		nodes[i].GetEpochManagerForTest().(*blockchain.EpochManagerFake).SetEpoch(e)
		nodes[i].GetActorForTest().ResetForTest(e)
	}
	return nil
}

func StopNodes(nodes []*consensus.Mediator) error {
	wg := sync.WaitGroup{}
	var stopfail uint32
	for _, m := range nodes {
		wg.Add(1)
		go func(med *consensus.Mediator) {
			logger.Info("stopping %s", med.GetConsensusId())
			defer wg.Done()
			err := med.Stop()
			if err != nil {
				atomic.AddUint32(&stopfail, 1)
				logger.Warn("failed to stop %s because %s", med.GetConsensusId(), err)
				return
			}
			med.Wait()
			logger.Info("stopped %s", med.GetConsensusId())
		}(m)
	}
	wg.Wait()
	if stopfail > 0 {
		return xerrors.Errorf("%d fail to stop", stopfail)
	}
	return nil
}

// WaitNodes Wait until every node stops
func WaitNodes(nodes []*consensus.Mediator) {
	wg := sync.WaitGroup{}

	for _, m := range nodes {
		wg.Add(1)
		go func(med *consensus.Mediator) {
			defer wg.Done()
			med.Wait()
		}(m)
	}
	wg.Wait()
}

func GetDifferenceSet(
	all []*consensus.Mediator, excluded []*consensus.Mediator) []*consensus.Mediator {
	var diff []*consensus.Mediator
	for _, m := range all {
		skip := false
		for _, e := range excluded {
			if e == m {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		diff = append(diff, m)
	}
	return diff
}

//------------------------------------------------------------------------------

func (pnc *PalaNodeCluster) StartAllNodes() error {
	return StartNodes(pnc.AllNodes())
}

func (pnc *PalaNodeCluster) Stop() error {
	err := StopNodes(pnc.AllNodes())
	for _, e := range pnc.writers {
		e.Close()
	}
	return err
}

func (pnc *PalaNodeCluster) Wait() {
	WaitNodes(pnc.AllNodes())
}

func (pnc *PalaNodeCluster) AllNodes() []*consensus.Mediator {
	return ConcatMediatorSlices(pnc.Proposers, pnc.Voters, pnc.Bootnodes)
}

func (pnc *PalaNodeCluster) GetUnnotarizedWindow() *config.Int64HardforkConfig {
	return pnc.unnotarizedWindow
}

// AddReconfiguration set the consensus nodes in `session`.
// For those sessions without a reconfiguration, use the same reconfiguration as the last session.
// Thus, the caller doesn't need to call AddReconfiguration() for all sessions.
func (pnc *PalaNodeCluster) AddReconfiguration(
	session blockchain.Session, proposerIds []ConsensusId, voterIds []ConsensusId, callback PalaNodeClusterNetworkCallback,
) error {
	for _, r := range pnc.reconfigurers {
		c := &consensus.ReconfigurationFake{
			ProposerList: blockchain.NewElectionResultFake(proposerIds, session, session),
			VoterList:    blockchain.NewElectionResultFake(voterIds, session, session),
		}
		if callback == nil {
			callback = func(session blockchain.Session, id ConsensusId) {}
		}
		pnc.networkCallbacks[session] = callback
		r.AddReconfiguration(session, c)
	}
	return nil
}

func CompileSol(contractName, sol string) (string, error) {
	tmpDir, err := ioutil.TempDir("", "sol")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)

	buf := bytes.NewBufferString(sol)
	// TODO(kevinfang): add london testing here
	cmd := exec.Command("solc", "--bin", "--evm-version", "byzantium", "-o", tmpDir, "-")
	cmd.Stdin = buf
	// var stderr bytes.Buffer
	// cmd.Stderr = &stderr
	err = cmd.Run()
	// fmt.Printf("stderr = %s\n", stderr.String())
	if err != nil {
		return "", err
	}

	outFile := fmt.Sprintf("%s.bin", contractName)
	outFile = path.Join(tmpDir, outFile)
	code, err := ioutil.ReadFile(outFile)
	if err != nil {
		return "", err
	}
	return string(code), nil
}

func SendTransaction(c *ethclient.Client, signer ethTypes.Signer,
	key *ecdsa.PrivateKey, nonce uint64, to *common.Address, value *big.Int,
	gasLimit uint64, gasPrice *big.Int, data []byte) (*ethTypes.Transaction, error) {
	ctx := context.Background()
	from := crypto.PubkeyToAddress(key.PublicKey)
	var err error

	if gasPrice.Cmp(big.NewInt(0)) == 0 {
		if gasPrice, err = c.SuggestGasPrice(ctx); err != nil {
			return nil, err
		}
	}

	if gasLimit == 0 {
		if gasLimit, err = c.EstimateGas(ctx,
			ethereum.CallMsg{
				From: from,
				To:   to,
				Data: data,
			}); err != nil {
			return nil, err
		}
	}

	if nonce == 0 {
		if nonce, err = c.NonceAt(ctx, from, nil); err != nil {
			return nil, err
		}
	}
	var tx *ethTypes.Transaction
	if to == nil {
		tx = ethTypes.NewContractCreation(nonce, value, gasLimit, gasPrice, data)
	} else {
		tx = ethTypes.NewTransaction(nonce, *to, value, gasLimit, gasPrice, data)
	}

	signedTx, err := ethTypes.SignTx(tx, signer, key)
	if err != nil {
		return nil, err
	}

	if err = c.SendTransaction(ctx, signedTx); err != nil {
		return signedTx, err
	}

	return signedTx, nil
}

func WaitForReceipt(c *ethclient.Client, txHash common.Hash, tick time.Duration, retry int) (*ethTypes.Receipt, error) {
	ticker := time.Tick(tick)
	i := 0
	for range ticker {
		if receipt, err := c.TransactionReceipt(context.Background(), txHash); err == nil {
			return receipt, nil
		}
		i += 1
		if i > retry {
			break
		}
	}
	return nil, xerrors.New("receipt not found")
}
