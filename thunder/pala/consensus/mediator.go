package consensus

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/bidder"
	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/consensus/chainsync"
	"github.com/ethereum/go-ethereum/thunder/pala/consensus/startstopwaiter"
	"github.com/ethereum/go-ethereum/thunder/pala/limiter"
	"github.com/ethereum/go-ethereum/thunder/pala/metrics"
	"github.com/ethereum/go-ethereum/thunder/pala/msggroup"
	"github.com/ethereum/go-ethereum/thunder/pala/network"
	"github.com/ethereum/go-ethereum/thunder/pala/txservice"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/commitsha1"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"golang.org/x/xerrors"
)

type PalaParams struct {
	// Number of outstanding (unnotarized) proposals allowed
	K *config.Int64HardforkConfig

	// Based on the Pala paper, the suggested value of this is >= 5*Δ
	// where Δ is maximum network delay during a period of synchrony (assume 200 ms in this case)
	DelayOfMakingFirstProposal time.Duration

	// Based on the Pala Paper, the suggested value for this is >= 6*mediator.go:delayOfMakingFirstProposal
	// or >=30*Δ where Δ is maximum network delay during a period of synchrony (assume 200 ms in this case)
	VoterWaitingTimeBeforeClockMsg time.Duration
}

type MediatorConfig struct {
	LoggingId               string
	Params                  PalaParams
	NetworkId               uint64
	ProposerHostPort        string
	BlockChain              blockchain.BlockChain
	Role                    RoleAssigner
	Verifier                blockchain.Verifier
	DataUnmarshaller        blockchain.DataUnmarshaller
	TxPool                  txservice.TxPool
	Reconfigurer            Reconfigurer
	EpochManager            blockchain.EpochManager
	ClockMessageTimer       Timer
	SyncDuration            time.Duration
	Selector                chainsync.Selector
	BootnodeConfig          BootnodeConfig
	ConnectingConfig        network.ConnectingConfig
	Metrics                 metrics.PalaMetrics
	ExtraServices           []startstopwaiter.StartStopWaiter
	TxRouter                txservice.TxRouter
	NetworkThrottlingConfig network.ThrottlingConfig
	MsgLimiterConfig        []limiter.MsgLimitConfig
	TxServiceLimitConfig    []limiter.MsgLimitConfig
	ClientPuzzleMgrCfg      *network.ClientPuzzleMgrCfg

	RpcMaxDelayBlock int64
	RpcSwitch        RpcSwitch
	RpcSuspendBuffer time.Duration

	Bidder *bidder.Bidder
}

// Note that BootnodeConfig is not part of consensus parameters,
// so there is no hardfork after changing it.
type BootnodeConfig struct {
	ListenPort       int64
	OwnPublicAddress string
	TrustedAddresses []string // bootnode addresses used for connect, i.e. <Addr>[:<Port>],
}

type ConnectionOpenEvent struct {
	Identity ConsensusId
}

type ConnectionClosedEvent struct {
	Identity ConsensusId
}

type metricsBlockInfo struct {
	blockSn  blockchain.BlockSn
	blockNum uint64
	// this is set to the time the block is observed and not the block timestamp
	blockTime time.Time
}

// Mediator uses Mediator Pattern. It is the center of all main objects.
// We can easily test Node using Mediator.
//
// About goroutine safety:
//   - Mediator waits data from BlockChain and Host in its worker goroutine.
//   - Node asks Mediator to forward data to Host in Node's worker goroutine.
//   - Mediator can do a blocking wait for operations of BlockChain/Node/ChainSyncer if needed,
//     but the reversed way is disallowed to avoid any potential deadlock.
//   - See the design document for more info
//     https://docs.google.com/presentation/d/1AY-GiujqkzRdfdleDSrj516d48-3w-z70w4DQiy_3HY/edit?usp=sharing
//
// Implements ActorClient, ChainSyncerClient, Authenticator, ConnectionObserver
// Implements thunder.RpcDelegate
type Mediator struct {
	startstopwaiter.StartStopWaiterImpl

	// Read-only / Assigned once
	loggingId                        string
	k                                *config.Int64HardforkConfig
	clock                            utils.Clock
	delayOfMakingFirstProposal       time.Duration
	voterWaitingPeriodBeforeClockMsg time.Duration
	maxRequestWaitingPeriod          time.Duration
	timeoutToRetryPeriod             time.Duration
	actorTimer                       Timer
	selector                         chainsync.Selector
	msgLimiter                       *limiter.MsgLimiter
	host                             *network.Host
	domainNameResolver               network.DomainNameResolver
	chain                            blockchain.BlockChain
	proposerHostPort                 string // when this is set and get elected as proposer, use this config to listen
	// Only use verifier for challenge-response authentication. Let Actor verify consensus data.
	verifier blockchain.Verifier
	// About epoch management:
	// * Mediator owns EpochManager and is responsible to update and save the epoch using EpochManager.
	// * To make Actor's decision be consistent in a work, update Actor's epoch asynchronously.
	//   Do not let Actor share EpochManager; otherwise, it's hard to prevent Actor from using
	//   different epochs while processing the same work.
	epochManager       blockchain.EpochManager
	palaMetrics        metrics.PalaMetrics
	role               RoleAssigner
	useFakeNetwork     bool
	connectingConfig   network.ConnectingConfig
	bootnodeConfig     BootnodeConfig
	networkMultiplexer *network.Multiplexer
	txDistributor      *txservice.TxDistributor
	extraServices      []startstopwaiter.StartStopWaiter

	rpcMaxDelayBlock int64
	rpcRunning       bool
	rpcSwitch        RpcSwitch
	rpcSuspendTimer  *time.Timer
	rpcSuspendBuffer time.Duration

	//
	// Only used in worker goroutine
	//
	selfChan                       chan interface{}
	messageChan                    chan *network.Message
	blockChan                      chan blockchain.BlockMadeEvent
	blockChainEventChan            <-chan interface{}
	actor                          *Actor
	syncer                         *chainsync.ChainSyncer
	unmarshaller                   blockchain.DataUnmarshaller
	reconfigurer                   Reconfigurer
	reconciliationWithAllBeginTime time.Time
	syncDuration                   time.Duration
	unnotarizedProposals           map[blockchain.BlockSn]blockchain.Proposal
	reconfiguringSession           *blockchain.Session
	reconfBeginTime                time.Time
	temporaryFetchedNotarizations  []blockchain.Notarization
	temporaryFetchedBlocks         []blockchain.Block
	isStopped                      bool
	// For debug and metrics
	lastBroadcastedProposal blockchain.BlockSn
	lastVotedProposal       blockchain.BlockSn
	lastFinalizedBlockInfo  metricsBlockInfo
	lastNotarizedBlockInfo  metricsBlockInfo

	//
	// Used in multiple goroutines
	//
	// eventChans is indirectly accessed by callers of Mediator.
	// Protect it by mutex is simpler.
	eventChansMutex utils.CheckedLock
	eventChans      []chan interface{}

	bidder *bidder.Bidder
}

type FreshestNotarizedChainExtendedEvent struct {
	Sn blockchain.BlockSn
}

type FinalizedChainExtendedEvent struct {
	Sn                            blockchain.BlockSn
	ReconfigurationBeginTriggered bool
	ReconfigurationEndTriggered   bool
}

type SessionReader interface {
	UpdateSession(blockchain.Session)
}

// Reconfigurer can update the context of objects when the proposer/voter reconfiguration
// happens. The implementation of Reconfigurer should know the implementation of those
// corresponding classes.
type Reconfigurer interface {
	// UpdateVerifier gets the new data (e.g., proposing/voting keys) from |bc|
	// and updates the new data to |verifier|.
	UpdateVerifier(bc blockchain.BlockChain, verifier blockchain.Verifier) error
	// UpdateRoleAssigner gets the new data (e.g., proposing/voting keys) from |bc|
	// and updates the new data to |role|.
	UpdateRoleAssigner(bc blockchain.BlockChain, role RoleAssigner) error
	// UpdateHost gets the new data (e.g., proposers' network IPs and ports) from |bc|
	// and updates the new data to |host|.
	UpdateHost(bc blockchain.BlockChain, host *network.Host, role RoleAssigner, listenAddr string) error
	// UpdateEpochManager confirms the reconfiguration happens in |bc|
	// and updates the new epoch to |em|.
	UpdateEpochManager(bc blockchain.BlockChain, em blockchain.EpochManager) error
	UpdateMetrics(bc blockchain.BlockChain, m metrics.PalaMetrics)

	// UpdateSession update session to any service that care session change
	UpdateSession(bc blockchain.BlockChain, reader SessionReader)
}

type DebugState struct {
	Identity             string
	Status               chainsync.Status
	SyncerState          chainsync.DebugState
	ConnectedIds         []ConsensusId
	ProposalInfo         string
	IsMakingBlock        bool
	LastBroadcastedBlock blockchain.BlockSn
}

type roleForChainSyncer struct {
	role     RoleAssigner
	verifier blockchain.Verifier
}

type RpcSwitch interface {
	ResumeRpc() error
	SuspendRpc()
}

// Types used with selfChan - Begin

type makeFirstProposalIfNeededEvent struct {
}

// Types used with selfChan - End

//--------------------------------------------------------------------

var DefaultPalaParams = PalaParams{
	K:                              nil,
	DelayOfMakingFirstProposal:     1000 * time.Millisecond,
	VoterWaitingTimeBeforeClockMsg: 6000 * time.Millisecond,
}

// nChainSyncExtendedBlocks affects the chain syncing speed for peers.
// The larger the number is, the higher network load the node has.
// TODO(thunder): [R3] adjust the value based on the node's network load.
// NOTE: this value related to msg rate limit setting of GetFresherHead and GetFresherHeadV2
var nChainSyncExtendedBlocks = 10

func IsBootnodeViaBootnodeConfig(c BootnodeConfig) bool {
	return c.ListenPort != 0
}

func bootnodeRelatedConfigIsValid(cfg MediatorConfig) error {
	bCfg := cfg.BootnodeConfig
	if IsBootnodeViaBootnodeConfig(bCfg) != cfg.Role.IsBootnode(UseMyId) {
		return xerrors.Errorf(`Consensus and network configs have different ideas of whether I'm a bootnode
IsBootnodeViaBootnodeConfig: %v, Role.IsBootNode(MyId): %v`,
			IsBootnodeViaBootnodeConfig(bCfg), cfg.Role.IsBootnode(UseMyId))
	}
	// if I'm accepting connections as a bootnode, I must know how to
	// avoid connecting to myself
	if (bCfg.ListenPort != 0) && (bCfg.OwnPublicAddress == "") {
		return xerrors.Errorf(`Configured to accept connections as a bootnode but don't know how to avoid connecting to myself
BootnodeListenPort: %d, BootnodePublicAddress: %q`,
			bCfg.ListenPort, bCfg.OwnPublicAddress)
	}
	return nil
}

//--------------------------------------------------------------------

func NewMediator(cfg MediatorConfig) *Mediator {
	if len(cfg.LoggingId) == 0 ||
		cfg.NetworkId == 0 ||
		cfg.Params.K == nil || cfg.Params.DelayOfMakingFirstProposal == 0 ||
		cfg.Params.VoterWaitingTimeBeforeClockMsg == 0 || cfg.BlockChain == nil ||
		cfg.Role == nil || cfg.Verifier == nil || cfg.DataUnmarshaller == nil ||
		cfg.Reconfigurer == nil || cfg.ClientPuzzleMgrCfg == nil ||
		cfg.ClockMessageTimer == nil ||
		cfg.SyncDuration == 0 || cfg.Selector == nil {
		logger.Error("NewMediator: must fill all fields in MediatorConfig %s", cfg)
		return nil
	}
	if err := bootnodeRelatedConfigIsValid(cfg); err != nil {
		msg := fmt.Sprintf("invalid bootnode config:\n%s", err)
		logger.Error(msg)
		debug.Bug(msg)
		return nil
	}
	empty := network.ConnectingConfig{}
	if cfg.ConnectingConfig == empty {
		cfg.ConnectingConfig = network.DefaultConnectingConfig
	} else if !utils.InTest() {
		logger.Warn("[%s] ConnectingConfig is changed: %s. "+
			"Suggest update network.DefaultConnectingConfig instead",
			cfg.LoggingId, cfg.ConnectingConfig)
	}

	nr := NetworkRole(cfg.EpochManager.GetEpoch().Session, cfg.Role)
	mul := network.NewMultiplexer()
	voterWaitingTimeBeforeClockMsg := cfg.Params.VoterWaitingTimeBeforeClockMsg
	clock := utils.NewClock()
	m := Mediator{
		loggingId:                        cfg.LoggingId,
		k:                                cfg.Params.K,
		clock:                            clock,
		delayOfMakingFirstProposal:       cfg.Params.DelayOfMakingFirstProposal,
		voterWaitingPeriodBeforeClockMsg: voterWaitingTimeBeforeClockMsg,
		maxRequestWaitingPeriod:          voterWaitingTimeBeforeClockMsg / 2,
		timeoutToRetryPeriod:             voterWaitingTimeBeforeClockMsg,
		proposerHostPort:                 cfg.ProposerHostPort,
		actorTimer:                       cfg.ClockMessageTimer,
		selector:                         cfg.Selector,
		palaMetrics:                      cfg.Metrics,
		role:                             cfg.Role,
		connectingConfig:                 cfg.ConnectingConfig,
		bootnodeConfig:                   cfg.BootnodeConfig,
		networkMultiplexer:               mul,
		syncDuration:                     cfg.SyncDuration,
		chain:                            cfg.BlockChain,
		verifier:                         cfg.Verifier,
		unmarshaller:                     cfg.DataUnmarshaller,
		reconfigurer:                     cfg.Reconfigurer,
		epochManager:                     cfg.EpochManager,
		rpcSwitch:                        cfg.RpcSwitch,
		rpcMaxDelayBlock:                 cfg.RpcMaxDelayBlock,
		rpcSuspendBuffer:                 cfg.RpcSuspendBuffer,
		rpcRunning:                       false,
		bidder:                           cfg.Bidder,
	}

	a := NewActor(ActorConfig{
		K:           cfg.Params.K,
		LoggingId:   cfg.LoggingId,
		Chain:       cfg.BlockChain,
		ActorClient: &m,
		Role:        cfg.Role,
		Verifier:    cfg.Verifier,
		Epoch:       blockchain.Epoch{}, // We'll set it in Start().
		Metrics:     cfg.Metrics,
	})
	m.actor = &a

	m.domainNameResolver = network.NewDomainNameResolver()
	h := network.NewHost(network.Config{
		LoggingId:          cfg.LoggingId,
		NetworkId:          cfg.NetworkId,
		Role:               nr,
		ConnectingConfig:   cfg.ConnectingConfig,
		ConnectionObserver: &m,
		Authenticator:      &m,
		Sink:               mul,
		Clock:              network.NewClock(),
		ThrottlingConfig:   cfg.NetworkThrottlingConfig,
		Metrics:            cfg.Metrics,
		ClientPuzzleMgrCfg: cfg.ClientPuzzleMgrCfg,
		DomainNameResolver: m.domainNameResolver,
	})
	m.host = h

	extraServices := make([]startstopwaiter.StartStopWaiter, len(cfg.ExtraServices))
	copy(extraServices, cfg.ExtraServices)
	if cfg.TxPool != nil {
		txChan := make(chan *network.Message, 1024)
		mul.Subscribe(msggroup.NetworkMsg, txChan)
		mul.Subscribe(msggroup.TxServiceMsg, txChan)
		m.txDistributor = txservice.NewTxDistributor(
			cfg.LoggingId, cfg.Role.GetMyId(), cfg.TxPool, h, cfg.TxRouter,
			cfg.EpochManager.GetEpoch().Session, txChan, cfg.TxServiceLimitConfig, clock)
		extraServices = append(extraServices, m.txDistributor)
	}
	m.extraServices = extraServices

	if len(cfg.MsgLimiterConfig) > 0 {
		m.msgLimiter = limiter.NewMsgLimiter(cfg.MsgLimiterConfig)
	} else if !utils.InTest() {
		logger.Warn("[%s] MsgLimiter is not set", m.loggingId)
	}

	return &m
}

// ActorClient - begin
//
// Called in handleEventLoop goroutine.
func (m *Mediator) Broadcast(msg blockchain.Message) {
	logger.Info("[%s] Broadcast %s", m.loggingId, msg.GetDebugString())
	m.broadcast(msg)
}

// Called in handleEventLoop goroutine.
func (m *Mediator) Reply(source *network.Message, msg blockchain.Message) {
	logger.Info("[%s] Reply %s %s",
		m.loggingId, msg.GetDebugString(), source.GetSourceDebugInfo())
	if err := source.Reply(consensusDataMessage{msg}.toNetworkMessage()); err == nil {
		if msg.GetType() == blockchain.TypeVote {
			m.lastVotedProposal = msg.GetBlockSn()
		}
	} else {
		// It's normal to have a network error.
		logger.Info("[%s] cannot reply %s (sn=%s) to %s; err=%s",
			m.loggingId, msg.GetType(), msg.GetBlockSn(), source.GetSourceDebugInfo(), err)
	}
}

// Called in handleEventLoop goroutine.
func (m *Mediator) CatchUp(source *network.Message, sn blockchain.BlockSn) {
	// ChainSyncer has its own schedule.
	// What we can do is to notify it, and let it decide what to do.
	m.syncer.DoSomethingIfNeeded()
}

// Called in handleEventLoop goroutine.
func (m *Mediator) UpdateEpoch(cNota blockchain.ClockMsgNota) {
	oldEpoch := m.epochManager.GetEpoch()
	if oldEpoch.Compare(cNota.GetEpoch()) > 0 {
		return
	}
	if err := m.epochManager.UpdateByClockMsgNota(cNota); err != nil {
		logger.Error("[%s] cannot update epoch to %d with a verified clock message notarization",
			m.loggingId, cNota.GetEpoch())
		return
	}
	newEpoch := m.epochManager.GetEpoch()
	if newEpoch == oldEpoch {
		// Not the first time. We just collect more clock message.
		return
	}
	logger.Note("[%s] update epoch from %s to %s due to clock message notarization",
		m.loggingId, oldEpoch, newEpoch)
	// The local epoch is advanced, so reset the timer to make the timer be consistent with
	// the others.
	m.actorTimer.Reset(m.voterWaitingPeriodBeforeClockMsg, m.epochManager.GetEpoch())

	m.stopCreatingNewBlocksIfNeeded()
	if err := m.actor.SetEpoch(newEpoch); err != nil {
		logger.Info("[%s] failed to set epoch %s; err=%s", m.loggingId, newEpoch, err)
	}
	m.syncer.SetMyEpoch(newEpoch)
	s := m.getStatus()
	// Our syncing model requires all nodes proactively broadcast their latest status.
	if _, err := m.host.Broadcast(statusMessage{s}.toNetworkMessage(), nil); err != nil {
		logger.Info("[%s] fails to broadcast status; err=%s", m.loggingId, err)
	}
	m.makeFirstProposalIfNeeded()
}

// ActorClient - end

// ChainSyncerClient - begin
//
// Called in handleEventLoop goroutine.
func (m *Mediator) RequestNotarizedBlocks(id ConsensusId) {
	logger.Debug("[%s] RequestNotarizedBlocks id=%s", m.loggingId, m.getShortName(id))

	head, ids, err := chainsync.NewRequest(m.chain)
	if err != nil {
		logger.Error("failed to create requests for chain syncing; id=%s, err=%s",
			m.getShortName(id), err)
		return
	}

	var msg *network.Message
	if m.host.IsCapable(id, network.CapabilityChainSyncV2) {
		request := getFresherHeadV2Message{}
		request.head = head
		request.blockIdentities = ids
		msg = request.toNetworkMessage()
	} else {
		request := getFresherHeadMessage{}
		request.head = head
		request.blockIdentities = ids
		msg = request.toNetworkMessage()
	}
	m.host.Send(id, msg)
}

// Called in handleEventLoop goroutine.
func (m *Mediator) RequestEpoch(id ConsensusId, session blockchain.Session) {
	epoch := m.epochManager.GetEpoch()
	m.host.Send(id, getEpochMessage{epoch}.toNetworkMessage())
}

// Called in handleEventLoop goroutine.
func (m *Mediator) SendUnnotarizedProposals(id ConsensusId) {
	if len(m.unnotarizedProposals) == 0 {
		return
	}

	// ChainSyncer doesn't know my voter id, so skip the request if `id` is me.
	if m.role.GetMyId() == id {
		return
	}

	var ps []blockchain.Message
	for _, p := range m.unnotarizedProposals {
		ps = append(ps, p)
	}
	sort.Sort(blockchain.ByBlockSn(ps))

	logger.Info("[%s] send unnotarized proposals %s..%s to %s",
		m.loggingId, ps[0].GetBlockSn(), ps[len(ps)-1].GetBlockSn(), m.getShortName(id))

	response := unnotarizedProposalsMessage{}
	response.proposals = make([]blockchain.Proposal, len(ps))
	for i, p := range ps {
		response.proposals[i] = p.(blockchain.Proposal)
	}

	m.host.Send(id, response.toNetworkMessage())
}

// ChainSyncerClient - end

// network.ConnectionObserver - Begin

// Called in a new goroutine. DO NOT access members which are not goroutine-safe.
//
// Since TxDistributor uses TxRouterImpl which uses RoleAssigner,
// we must make RoleAssigner ready before TxDistributor receives the open message.
func (m *Mediator) OnConnected(connectAddress string, connectId, verifiedId ConsensusId) {
	logger.Info("[%s] new connection to id:%q is ready", m.loggingId, verifiedId)
	// NOTE: We don't know bootnodes' consensus ids until the handshake is done.
	// If we are the initiator of the connection, we know that the peer is a bootnode
	// if it's not a proposer because we only connect to either a proposer or a bootnode.
	session := m.epochManager.GetEpoch().Session
	if connectAddress != "" && !m.role.IsProposer(verifiedId, session) {
		var shortName ConsensusId
		for i, addr := range m.bootnodeConfig.TrustedAddresses {
			if addr == connectAddress {
				shortName = ConsensusId(fmt.Sprintf("bootnode-%d", i))
				break
			}

			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				// TODO(thunder): when using the fake connection, the values of TrustedAddresses
				// don't include the port.
				logger.Info("[%s] invalid addr <%s>: %s", m.loggingId, addr, err)
				continue
			}

			ips, err := m.domainNameResolver.LookupHost(context.Background(), host)
			for j, ip := range ips {
				if ip+":"+port == connectAddress {
					shortName = ConsensusId(fmt.Sprintf("bootnode-%d-%d", i, j))
					break
				}
			}
		}
		if shortName == "" {
			logger.Error("[%s] connected to node with (addres= %q, connectId= %q), but the verifiedId %q is not a proposer, and the address is not in the trusted bootnode list"+
				"(session= %d, BootnodesITrust= %v); "+
				"drop the connection",
				m.loggingId, connectAddress, connectId, verifiedId,
				session, m.bootnodeConfig.TrustedAddresses)
			debug.Bug("cannot find the bootnode address")
		}
		m.role.AddBootnode(verifiedId, shortName)
	}
}

// Called in a new goroutine. DO NOT access members which are not goroutine-safe.
//
// Since TxDistributor uses TxRouterImpl which uses RoleAssigner,
// we must make RoleAssigner ready before TxDistributor receives the closed message.
func (m *Mediator) OnDisconnected(connectAddress string, connectId, verifiedId ConsensusId) {
	logger.Info("[%s] connection to id=%s is disconnected",
		m.loggingId, m.getShortName(verifiedId))
	m.role.RemoveBootnode(verifiedId)
}

// network.ConnectionObserver - End

// network.Authenticator - Begin

// Called in a new goroutine. Only access goroutine-safe members.
func (m *Mediator) Sign(input []byte) (ConsensusId, []byte, error) {
	if consensusId, signature, err := m.verifier.Sign(input); err == nil {
		return consensusId, signature, nil
	} else {
		return "", nil, err
	}
}

// Called in a new goroutine. Only access goroutine-safe members.
func (m *Mediator) Verify(
	remoteIsServer bool, connectId ConsensusId, signature []byte, expected []byte,
) (verifiedRemoteId ConsensusId, err error) {
	var signedId ConsensusId
	if signedId, _, err = m.verifier.VerifySignature(signature, expected); err != nil {
		logger.Info("[%s] verifier.VerifySignature(%q, %v, %v) (remoteIsServer=%t) failed: %s",
			m.loggingId, connectId, signature, expected, remoteIsServer, err)
		return
	}
	verifiedRemoteId = signedId

	session := m.epochManager.GetEpoch().Session
	role := m.role
	if remoteIsServer {
		if connectId != "" && role.IsProposer(connectId, session) {
			if signedId != connectId {
				verifiedRemoteId = ConsensusId("")
				err = xerrors.Errorf("signedId %s != connectId %s", signedId, connectId)
			}
		} else {
			// The clients trust bootnodes by network addresses. No extra check.
		}
		return
	}

	if role.IsProposer(UseMyId, session) && !role.IsBootnode(UseMyId) {
		if !role.IsProposer(signedId, session) && !role.IsVoter(signedId, session) {
			verifiedRemoteId = ConsensusId("")
			err = xerrors.Errorf("signedId %s is not a consensus node in session %s", signedId, session)
		}
	} else {
		// I am a bootnode. No extra check.
		// TODO(thunder): [R3] when there are too many connections, keep proposer/voter candidates
		// connected and drop low-priority connections.
	}
	return
}

// Called in a new goroutine. Only access goroutine-safe members.
func (m *Mediator) GetSigningId() ConsensusId {
	return m.role.GetMyId()
}

// network.Authenticator - End

// Deprecated. Remove it after Testnet upgrades to R2.
// Called in handleEventLoop goroutine.
// This method will run in a different goroutine from handleEventLoop, so must be goroutine safe.
func (m *Mediator) onGetFresherHead(request *getFresherHeadMessage, msg *network.Message) {
	if len(request.blockIdentities) == 0 {
		logger.Debug("[%s] received invalid request for fresher head; blockIdentities is empty",
			m.loggingId)
		return
	}

	r := &fresherHeadMetaMessage{}
	nbs, err := chainsync.FindNextBlocks(
		m.chain, request.head, request.blockIdentities, nChainSyncExtendedBlocks)
	if err != nil {
		logger.Info("failed to find next blocks: source=%s, err=%s",
			msg.GetSourceDebugInfo(), err)
		head := m.chain.GetFinalizedHead()
		r.finalizedHead.BlockIdentifier.Number = head.GetNumber()
		r.finalizedHead.BlockIdentifier.Hash = head.GetHash()
		r.finalizedHead.Sn = head.GetBlockSn()

		if err := msg.Reply(r.toNetworkMessage()); err != nil {
			logger.Info("[%s] %s", m.loggingId, err)
		}
		return
	}

	r.numNotarizedBlocks = uint16(len(nbs))
	if err := msg.Reply(r.toNetworkMessage()); err != nil {
		logger.Info("[%s] %s", m.loggingId, err)
		return
	}

	// To not exceed network.MaxMessageSize, separate blocks into different messages.
	for _, nb := range nbs {
		// Convert notarized block to v1 format
		block, err := m.chain.ToRawBlock(nb.Header, nb.BlockBody)
		if err != nil {
			logger.Error("[%s] %s", m.loggingId, err)
			return
		}
		buf := marshalToNotarizedBlock(block, nb.Nota)
		nm := network.NewMessage(uint8(MessageFresherHeadData), 0, buf)
		if err := msg.Reply(nm); err != nil {
			logger.Info("[%s] %s", m.loggingId, err)
			return
		}
	}
}

// This method will run in a different goroutine from handleEventLoop, so must be goroutine safe.
func (m *Mediator) onGetFresherHeadV2(request *getFresherHeadV2Message, msg *network.Message) {
	if len(request.blockIdentities) == 0 {
		logger.Debug("[%s] received invalid request for fresher head; blockIdentities is empty",
			m.loggingId)
		return
	}

	r := &fresherHeadMetaMessage{}
	nbs, err := chainsync.FindNextBlocks(
		m.chain, request.head, request.blockIdentities, nChainSyncExtendedBlocks)
	if err != nil {
		logger.Info("failed to find next blocks: source=%s, err=%s",
			msg.GetSourceDebugInfo(), err)
		head := m.chain.GetFinalizedHead()
		r.finalizedHead.BlockIdentifier.Number = head.GetNumber()
		r.finalizedHead.BlockIdentifier.Hash = head.GetHash()
		r.finalizedHead.Sn = head.GetBlockSn()

		if err := msg.Reply(r.toNetworkMessage()); err != nil {
			logger.Info("[%s] %s", m.loggingId, err)
		}
		return
	}

	r.numNotarizedBlocks = uint16(len(nbs))
	if err := msg.Reply(r.toNetworkMessage()); err != nil {
		logger.Info("[%s] %s", m.loggingId, err)
		return
	}

	// To not exceed network.MaxMessageSize, separate blocks into different messages.
	var buf []byte
	for _, nb := range nbs {
		// convert to network message format
		block, err := m.chain.ToRawBlock(nb.Header, nb.BlockBody)
		if err != nil {
			logger.Error("[%s] %s", m.loggingId, err)
			return
		}
		bs := marshalToNotarizedBlock(block, nb.Nota)
		// Aggregating messages into one message has some benefits:
		// * Reduce the network round trip time
		// * Simplify ChainSyncer's logic.
		//
		// Background about interaction between Mediator and ChainSyncer:
		//
		//   Assume we are far behind our peers and Mediator got a response of block 1 - 10.
		//   If Mediator processes block 1 and notifies ChainSyncer the head update immediately,
		//   ChainSyncer will make another request for block 2-11. In the best case, Mediator should
		//   process block 1-10 and notify ChainSyncer the head update in the end, so ChainSyncer will
		//   make a request for block 11-20.
		//
		// We have some different approaches to let ChainSyncer make the optimal decision.
		// Assume C is behind S and C makes a request to S.
		// 1. S tries his best to pack blocks into one message, so C's Mediator can process blocks
		//    in a batch easily. In the extrem cases, S may pack blocks into two or more messages.
		// 2. C temporarily collects blocks from S and process blocks in a batch when there are enough
		//    blocks. However, C needs to handle memory management carefully to avoid attacks.
		// 3. C asks its ChainSyncer pauses and resumes it after a while or the rest blocks are all
		//    processed. Whether C processes blocks in a batch or not doesn't matter.
		//
		// We chose 1 because it's simple and optimal usually.
		if len(buf)+len(bs) > network.MaxMessageBodySize {
			nm := network.NewMessage(uint8(MessageFresherHeadDataV2), 0, buf)
			if err := msg.Reply(nm); err != nil {
				logger.Info("[%s] %s", m.loggingId, err)
				return
			}
			buf = nil
		}
		buf = append(buf, bs...)
	}
	if len(buf) > 0 {
		nm := network.NewMessage(uint8(MessageFresherHeadDataV2), 0, buf)
		if err := msg.Reply(nm); err != nil {
			logger.Info("[%s] %s", m.loggingId, err)
		}
	}
}

// Called in handleEventLoop goroutine.
func (m *Mediator) onFresherHeadMeta(response *fresherHeadMetaMessage, msg *network.Message) {
	if response.numNotarizedBlocks > 0 {
		// To avoid unnecessary memory management, don't keep the meta data until we have such a need.
		return
	}

	id := msg.GetId()
	if id != "" {
		// Two possible cases:
		// 1. The peer has an inconsistent view.
		// 2. The peer has no new data for us. This is possible
		//    because we build the request from our chain and the chain my have
		//    newer status compared to ChainSyncer if there is some implementation error.
		b := m.chain.GetBlockByNumber(response.finalizedHead.Number)
		if b == nil || b.GetHash() != response.finalizedHead.Hash {
			// Either case cannot be resolved by the protocol automatically.
			// b == nil -> the peer is fresher than us but it cannot respond blocks.
			// hash mismatched -> inconsistent finalized heads.
			m.syncer.SetPeerIsInconsistent(id, response.finalizedHead)
		}
	}
}

// Deprecated. Remove it after Testnet upgrades to R2.
// Called in handleEventLoop goroutine.
func (m *Mediator) onFresherHeadData(response *fresherHeadDataMessage, msg *network.Message) {
	nb := response.notarizedBlock

	// NOTE: Instead of saving the notarized block temporarily and pass all of them to Actor,
	// pass the notarized block to Actor immedately. This approach has some advantages:
	// * This avoids attackers from occupying our memory temporarily and simplify the memory
	//   management.
	// * This may speed up the syncing process when EVM needs to take lots of time processing
	//   transactions.
	ns := []blockchain.Notarization{nb.Nota}
	bs := []blockchain.Block{nb.Block}
	if _, _, err := m.actor.AddNotarizedBlocks(ns, bs); err != nil {
		logger.Info("[%s] failed to add notarized blocks; err=%s", m.loggingId, err)
	}
}

// Called in handleEventLoop goroutine.
func (m *Mediator) onFresherHeadDataV2(response *fresherHeadDataV2Message, msg *network.Message) {
	if len(response.notarizedBlocks) == 0 {
		return
	}

	var ns []blockchain.Notarization
	var bs []blockchain.Block
	for _, nb := range response.notarizedBlocks {
		ns = append(ns, nb.Nota)
		bs = append(bs, nb.Block)
	}

	if ns, bs, err := m.actor.AddNotarizedBlocks(ns, bs); err != nil {
		temporary := utils.IsTemporaryError(err)
		if temporary {
			m.temporaryFetchedNotarizations = ns
			m.temporaryFetchedBlocks = bs
		}
		logger.Info("[%s] failed to add notarized blocks (temporary=%t); err=%s",
			m.loggingId, temporary, err)
	}
}

// Called in handleEventLoop goroutine for now.
func (m *Mediator) onUnnotarizedProposals(response *unnotarizedProposalsMessage, msg *network.Message) {
	logger.Info("[%s] receive unnotarized proposals %d", m.loggingId, len(response.proposals))
	for _, p := range response.proposals {
		if err := m.addProposal(p, msg); err != nil {
			logger.Info("[%s] failed to add a proposal (%s); err=%s",
				m.loggingId, p.GetBlockSn(), err)
		}
	}
}

// Called in handleEventLoop goroutine for now.
func (m *Mediator) addProposal(p blockchain.Proposal, msg *network.Message) error {
	return m.actor.AddProposal(p, msg, BlockCreatedByOther)
}

// Called in handleEventLoop goroutine for now.
func (m *Mediator) onGetEpoch(request *getEpochMessage, msg *network.Message) {
	clientSession := request.clientEpoch.Session
	response := epochMessage{session: clientSession}
	localSession := m.epochManager.GetEpoch().Session
	if localSession >= clientSession {
		// May be nil if there is no timeout in the designated session.
		response.cNota = m.epochManager.GetLatestClockMsgNota(clientSession)
		// existed and isLast were used by the old protocol. Abandoned because peers can lie
		response.existed = response.cNota != nil
		response.isLast = localSession > clientSession || m.shouldReconfigure()
	}

	if err := msg.Reply(response.toNetworkMessage()); err != nil {
		logger.Info("[%s] %s", m.loggingId, err)
	}
}

// Called in handleEventLoop goroutine for now.
func (m *Mediator) onEpoch(response *epochMessage, msg *network.Message) {
	if response.cNota == nil { // peer thinks session has no ClockMsgNota
		epoch := m.epochManager.GetEpoch()
		if epoch.E != 1 {
			id := m.getClientLoggingId(msg)
			logger.Warn("[%s] %s responds there is no ClockMsgNota, "+
				"but my local epoch.E is not 1 (%s)", m.loggingId, id, epoch)
			return
		}
		return
	}
	if err := m.actor.AddClockMsgNota(response.cNota); err != nil {
		logger.Info("[%s] failed to add a notarized clock msg (%s); err=%s",
			m.loggingId, response.cNota.GetEpoch(), err)
	}
}

func (m *Mediator) notifyEvent(e interface{}) {
	m.eventChansMutex.Lock()
	defer m.eventChansMutex.Unlock()
	for _, ch := range m.eventChans {
		select {
		case ch <- e:
		default:
		}
	}
}

func (m *Mediator) GetConsensusId() ConsensusId {
	return m.role.GetMyId()
}

// Called in handleEventLoop goroutine.
func (m *Mediator) getClientLoggingId(msg *network.Message) string {
	return fmt.Sprintf("%s:%s", msg.GetId(), msg.GetSourceAddress())
}

func (m *Mediator) setByzantineClient(c byzantineClient) {
	if m.IsRunning() {
		debug.Bug("unexpected call")
	}
	m.actor.setByzantineClient(c)
}

func (m *Mediator) Start() error {
	// NOTE: call reset() here to ensure states in memory matches states in storages.
	// ( i.e., the state in m.syncer matches m.chain and m.epochManager. )
	// Here is the scenario in tests:
	// 1. The test code starts Mediator.
	// 2. The test code stops Mediator.
	// 3. The test code resets Mediator's storage.
	// 4. The test code restarts Mediator.
	// If we only reset in stopEventLoop(), m.syncer's state is wrong.
	m.reset()
	stoppedChan := make(chan interface{})
	// We get stopChan from StartStopWaiterImpl and will use it to do the clean ups.
	action := func(stopChan chan interface{}) error {
		// Reset messageChan because there may be some messages in messageChan after Stop().
		m.messageChan = make(chan *network.Message, 1024)
		m.networkMultiplexer.Subscribe(msggroup.NetworkMsg, m.messageChan)
		m.networkMultiplexer.Subscribe(msggroup.ConsensusMsg, m.messageChan)
		m.networkMultiplexer.Subscribe(msggroup.ChainSyncMsg, m.messageChan)

		var err error
		if err = m.setupNetwork(); err != nil {
			return err
		}

		status := m.getStatus()
		logger.Note("[%s] init state: %s", m.loggingId, status)
		session := status.Epoch.Session
		m.checkRoles(session)
		m.logShortNameMapping()

		epoch := status.Epoch
		for _, s := range m.extraServices {
			if err = s.Start(); err != nil {
				logger.Error("[%s] Failed to start extra service(%s): %s", m.loggingId, reflect.TypeOf(s), err)
				return err
			}
		}
		if err := m.actor.SetEpoch(epoch); err != nil {
			logger.Info("[%s] failed to set epoch %s; err=%s", m.loggingId, epoch, err)
		}

		m.syncer.SetMyStatus(m.getStatus())
		m.selfChan <- makeFirstProposalIfNeededEvent{}
		go m.handleEventLoop(stopChan, stoppedChan)
		return nil
	}
	err := m.StartStopWaiterImpl.Start(action, stoppedChan)
	if err == nil {
		logger.Info("[%s] started", m.loggingId)
	}
	return err
}

// Called before Mediator's worker goroutine starts.
func (m *Mediator) setupNetwork() error {
	if m.useFakeNetwork {
		return nil
	}

	if m.host.GetRole() == network.RoleHub {
		addr := m.getMyAddress()
		logger.Info("[%s] the network role is hub with address:%s", m.loggingId, addr)
		if addr == "" {
			debug.Bug("%s is neither a proposer nor a bootnode at session=%d",
				m.loggingId, m.epochManager.GetEpoch().Session)
		}
		if err := m.host.StartAccepting(addr); err != nil {
			return err
		}
	} else {
		logger.Info("[%s] the network role is spoke", m.loggingId)
	}

	m.connect(nil)
	return nil
}

func (m *Mediator) getMyAddress() string {
	if m.useFakeNetwork {
		return ""
	}

	session := m.epochManager.GetEpoch().Session
	pid := m.role.GetMyId()
	addresses := m.chain.GetProposerAddresses(session)
	for id, addr := range addresses {
		if pid == id {
			if m.proposerHostPort != "" {
				return m.proposerHostPort
			}
			return addr
		}
	}

	if m.bootnodeConfig.ListenPort > 0 {
		return fmt.Sprintf("0.0.0.0:%d", m.bootnodeConfig.ListenPort)
	}

	return ""
}

func (m *Mediator) checkRoles(session blockchain.Session) {
	id := m.role.GetMyId()
	m.sanityCheck(id, session)
	var hasRole bool
	if m.role.IsProposer(UseMyId, session) {
		logger.Note("[%s] I am a proposer at session %s with id=%s", m.loggingId, session, id)
		hasRole = true
	}
	if m.role.IsVoter(UseMyId, session) {
		logger.Note("[%s] I am a voter at session %s with id=%s", m.loggingId, session, id)
		hasRole = true
	}
	if m.role.IsBootnode(UseMyId) {
		logger.Note("[%s] I am a bootnode at session %s with id=%s", m.loggingId, session, id)
		hasRole = true
		// Note that the sanity check is done in NewMediator() -> bootnodeRelatedConfigIsValid().
	}
	if !hasRole {
		logger.Note("[%s] I am a fullnode at session %s with id=%s", m.loggingId, session, id)
	}
}

func (m *Mediator) sanityCheck(id ConsensusId, session blockchain.Session) {
	if id == "" {
		debug.Bug("[%s] id cannot be empty", m.loggingId)
	}
	input := []byte("hello")
	aid, signature, err := m.verifier.Sign(input)
	if err != nil {
		debug.Bug("[%s] failed to sign: %s", m.loggingId, err)
	}
	if aid != id {
		debug.Bug("[%s] unexpected id: %s != %s", m.loggingId, id, aid)
	}
	if signedId, _, err := m.verifier.VerifySignature(signature, input); err != nil {
		debug.Bug("[%s] failed to verify: %s", m.loggingId, err)
	} else if signedId != id {
		debug.Bug("[%s] failed to verify: id mismatched", m.loggingId)
	}
}

// Called in handleEventLoop goroutine or before the start.
func (m *Mediator) reset() {
	m.selfChan = make(chan interface{}, 1024)
	if m.blockChainEventChan != nil {
		m.chain.RemoveNotificationChannel(m.blockChainEventChan)
	}
	m.blockChainEventChan = m.chain.NewNotificationChannel()
	m.syncer = chainsync.NewChainSyncer(chainsync.Config{
		LoggingId:               m.loggingId,
		Client:                  m,
		Selector:                m.selector,
		Clock:                   m.clock,
		Role:                    roleForChainSyncer{m.role, m.verifier},
		MaxRequestWaitingPeriod: m.maxRequestWaitingPeriod,
		TimeoutToRetryPeriod:    m.timeoutToRetryPeriod,
		RpcMaxDelayBlock:        m.rpcMaxDelayBlock,
	})
	m.syncer.SetMyStatus(m.getStatus())
	m.syncer.DoSomethingIfNeeded()

	if m.syncer.IsBlockChainBehind() {
		if m.rpcRunning {
			m.rpcSwitch.SuspendRpc()
		}
		if m.bidder != nil {
			m.bidder.StopBid()
		}
		m.rpcRunning = false
		logger.Warn("[%s] Block chain is behind.", m.loggingId)
	} else {
		m.rpcRunning = true

		if m.bidder != nil {
			m.bidder.StartBid()
		}
	}
}

func (m *Mediator) handleEventLoop(
	stopChan chan interface{}, stoppedChan chan interface{},
) {
	isReconfiguring := m.shouldReconfigure()

	logger.Note("[%s] start the main goroutine (isReconfiguring=%t)",
		m.loggingId, isReconfiguring)
	defer func() {
		logger.Note("[%s] end the main goroutine", m.loggingId)
	}()

	if isReconfiguring {
		m.beginReconfigureIfNeeded(m.chain.GetFinalizedHeadSn())
	}

	// Prepare timers for regular tasks.
	retryConnectingPeriod := m.connectingConfig.RetryTime
	logger.Note("[%s] keep reconnecting (period=%s)", m.loggingId, retryConnectingPeriod)
	retryConnectingTimer := time.NewTimer(retryConnectingPeriod)

	logger.Note("[%s] keep syncing (period=%s)", m.loggingId, m.syncDuration)
	syncTimer := time.NewTimer(m.syncDuration)

	heartbeatDuration := m.host.GetReadTimeout() / 2
	if heartbeatDuration < time.Second {
		heartbeatDuration = time.Second
	}
	logger.Note("[%s] keep sending status as heartbeat messages (period=%s)",
		m.loggingId, heartbeatDuration)
	heartbeatTimer := time.NewTimer(heartbeatDuration)

	logger.Note("[%s] keep tracking timeout(period=%s)", m.loggingId,
		m.voterWaitingPeriodBeforeClockMsg)
	m.actorTimer.Reset(m.voterWaitingPeriodBeforeClockMsg, m.epochManager.GetEpoch())

	for {
		// Do some action.
		select {
		case <-stopChan:
			m.stopEventLoop()
			close(stoppedChan)
			return
		case <-retryConnectingTimer.C:
			retryConnectingTimer.Reset(retryConnectingPeriod)
			m.connect(nil)
		case <-syncTimer.C:
			syncTimer.Reset(m.syncDuration)
			m.syncer.DoSomethingIfNeeded()
		case <-heartbeatTimer.C:
			heartbeatTimer.Reset(heartbeatDuration)
			m.syncer.DoSomethingIfNeeded()
			s := m.getStatus()
			if _, err := m.host.Broadcast(statusMessage{s}.toNetworkMessage(), nil); err != nil {
				logger.Info("[%s] fails to broadcast status; err=%s", m.loggingId, err)
			}
		case <-m.actorTimer.GetChannel():
			// Reset the timer, so voters will resend ClockMsg after timeout happens again.
			// Otherwise, when a proposer P connects to voters who have sent ClockMsg,
			// P will not receive ClockMsg.
			m.actorTimer.Reset(m.voterWaitingPeriodBeforeClockMsg, m.epochManager.GetEpoch())
			if err := m.actor.Timeout(); err != nil {
				logger.Info("[%s] %s", m.loggingId, err)
			}
		case bae := <-m.blockChan:
			logger.Debug("[%s] handleEventLoop: block %s\n", m.loggingId, bae.Block.GetBlockSn())
			// Only used by the primary proposer.
			if err := m.actor.AddBlock(bae.Block, BlockCreatedBySelf); err != nil {
				logger.Info("[%s] failed to add a block (%s); err=%s",
					m.loggingId, bae.Block.GetBlockSn(), err)
			}
		case msg := <-m.selfChan:
			m.handleSelfMessage(msg)
		case msg := <-m.messageChan:
			m.handleNetworkMessage(msg)
		}

		// Check whether there is any progress.
		//
		// We need to check the chain event right after the action to avoid making unnecessary
		// chain syncing requests. For example, a voter/proposer/voter receives the message
		// nota (1,1,2) and status update (1,1,2) from the primary proposer in order. Assume we just
		// processed nota (1,1,2) and created a chain extension event (1,1,2). If we catch that event
		// later, when processing the status update (1,1,2), we'll tell ChainSyncer that the primary
		// proposer's status is (1,1,2) and ChainSyncer will make a request because it thinks our head
		// is still (1,1,1).
		//
		// On the other hand, if we process the chain extension event (1,1,2) now, we'll tell
		// ChainSyncer our head is (1,1,2) and tell ChainSyncer the primary proposer's head is (1,1,2)
		// later. Then ChainSyncer will not make any request.
		m.handleBlockChainEvents()
	}
}

// Called in the handleEventLoop goroutine.
func (m *Mediator) stopNow() {
	m.stopEventLoop()

	// Make stopEventLoop() a NOP when Stop() calls it.
	m.isStopped = true
	defer func() {
		m.isStopped = false
	}()
	m.Stop()
}

// Called in the handleEventLoop goroutine.
func (m *Mediator) stopEventLoop() {
	if m.isStopped {
		return
	}

	logger.Note("[%s] try stopping", m.loggingId)
	// It's safe to call this even if the host doesn't start.
	if err := m.host.StopAccepting(); err != nil {
		logger.Warn("[%s] failed to stop accepting connections; err=%s", m.loggingId, err)
	}
	m.networkMultiplexer.Unsubscribe(msggroup.NetworkMsg, m.messageChan)
	m.networkMultiplexer.Unsubscribe(msggroup.ConsensusMsg, m.messageChan)
	m.networkMultiplexer.Unsubscribe(msggroup.ChainSyncMsg, m.messageChan)
	m.host.CloseAllConnections()
	// Wait the network closes all connections.
ForLoop:
	for {
		select {
		case <-m.messageChan:
		default:
			break ForLoop
		}
	}
	if n := m.host.GetNumConnections(); n > 0 {
		logger.Warn("[%s] there are %d connections after closing all connections", m.loggingId, n)
	}
	m.stopCreatingNewBlocksIfNeeded()
	for _, s := range m.extraServices {
		logger.Info("[%s] stopping service %v:", m.loggingId, reflect.TypeOf(s))
		if err := s.StopAndWait(); err != nil {
			logger.Warn("[%s] cannot stop extra service: %s", m.loggingId, err)
		}
	}

	m.reset()

	logger.Note("[%s] stopped", m.loggingId)
}

// Called in Mediator.handleEventLoop goroutine.
func (m *Mediator) connect(idToAddresses map[ConsensusId]string) {
	if m.useFakeNetwork {
		return
	}

	var connectIds []ConsensusId
	var addresses []string
	var groups []network.GroupConectedNess

	if idToAddresses != nil {
		for id, addr := range idToAddresses {
			connectIds = append(connectIds, id)
			addresses = append(addresses, addr)
			groups = append(groups, network.OneInGroup)
		}
	} else {
		// Connection rules:
		// * All nodes connect to designated bootnodes.
		// * Consensus nodes connect to proposers.
		session := m.epochManager.GetEpoch().Session
		if IsConsensusNode(m.role, UseMyId, session) {
			for id, addr := range m.chain.GetProposerAddresses(session) {
				if id == m.role.GetMyId() {
					continue
				}

				if m.role.IsProposer(UseMyId, session) && id < m.role.GetMyId() {
					continue
				}
				connectIds = append(connectIds, id)
				addresses = append(addresses, addr)
				groups = append(groups, network.OneInGroup)
			}
		}
		for _, addr := range m.bootnodeConfig.TrustedAddresses {
			if addr == m.bootnodeConfig.OwnPublicAddress {
				continue
			}
			// We don't know bootnode's id until the handshake is done.
			connectIds = append(connectIds, "")
			addresses = append(addresses, addr)
			if m.role.IsProposer(UseMyId, session) {
				groups = append(groups, network.AllInGroup)
			} else {
				groups = append(groups, network.OneInGroup)
			}
		}
	}

	for i := 0; i < len(connectIds); i++ {
		logger.Info("[%s] connect to id:%q, addr:%s, group:%s",
			m.loggingId, connectIds[i], addresses[i], groups[i])
		m.host.ConnectAsync(connectIds[i], addresses[i], groups[i])
	}
}

// Called in the handleEventLoop goroutine.
func (m *Mediator) handleBlockChainEvents() {
	var sn blockchain.BlockSn
	// Set a bound to avoid infinite loop when there is a bug.
	const maxTries = 10
	tries := 0
	for ; tries < maxTries; tries++ {
	Loop:
		for {
			select {
			case e := <-m.blockChainEventChan:
				switch v := e.(type) {
				case blockchain.FreshestNotarizedChainExtendedEvent:
					sn = v.Sn
					m.onReceivedFreshestNotarizedChainExtendedEvent(&v)
				case blockchain.FinalizedChainExtendedEvent:
					// Note that the primary proposer doesn't receive this event.
					// Instead, the event is received along with the new block from m.blockChan.
					m.onReceivedFinalizedChainExtendedEvent(&v)
				default:
					debug.Bug("unknown event %+v", e)
				}
			default:
				break Loop
			}
		}

		if len(m.temporaryFetchedNotarizations) > 0 {
			// We may advance the session and be able to process notarized blocks now.
			ns, bs := m.temporaryFetchedNotarizations, m.temporaryFetchedBlocks
			m.temporaryFetchedNotarizations, m.temporaryFetchedBlocks = nil, nil
			if ns, bs, err := m.actor.AddNotarizedBlocks(ns, bs); err != nil {
				temporary := utils.IsTemporaryError(err)
				if temporary && xerrors.Is(err, blockchain.ErrMissingElectionResult) {
					m.temporaryFetchedNotarizations = ns
					m.temporaryFetchedBlocks = bs
				}
				logger.Info("[%s] failed to add notarized blocks (temporary=%t); err=%s",
					m.loggingId, temporary, err)
			}
		} else {
			break
		}
	}
	if tries >= maxTries {
		logger.Warn("[%s] loop too many times; there might be something wrong", m.loggingId)
	}

	if sn.IsNil() {
		// No new progress.
		return
	}

	// Only notify ChainSyncer the last result to avoid duplicated requests.
	m.syncer.SetMyFreshestNotarizedHead(sn)

	// Check chain status to resume/suspend RPC.
	if m.syncer.IsBlockChainBehind() {
		// chain data delay before
		if m.rpcSuspendTimer != nil {
			select {
			case <-m.rpcSuspendTimer.C:
				logger.Warn("[%s] start to suspend RPC.", m.loggingId)
				m.rpcSwitch.SuspendRpc()
				logger.Warn("[%s] RPC suspended.", m.loggingId)
				m.rpcRunning = false
				if m.bidder != nil {
					m.bidder.StopBid()
				}
			default:
			}
		}

		// chain data delay after run a while.
		if m.rpcRunning && m.rpcSuspendTimer == nil {
			logger.Warn("[%s] RPC will be suspended after %s due to chain behind.", m.loggingId, m.rpcSuspendBuffer.String())
			m.rpcSuspendTimer = time.NewTimer(m.rpcSuspendBuffer)
		}
	} else {
		if m.rpcSuspendTimer != nil {
			logger.Info("[%s] RPC suspend timer is stopped.", m.loggingId)
			if !m.rpcSuspendTimer.Stop() {
				select {
				case <-m.rpcSuspendTimer.C:
					// try to drain the channel
				default:
				}
			}
			m.rpcSuspendTimer = nil
		}
		if !m.rpcRunning {
			if err := m.rpcSwitch.ResumeRpc(); err == nil {
				logger.Info("[%s] RPC resumed due to chain synced.", m.loggingId)
				m.rpcRunning = true
			} else {
				logger.Error("[%s] failed to resume rpc: %v", m.loggingId, err.Error())
			}
		}
		if m.bidder != nil {
			m.bidder.StartBid()
		}
	}

	// Our syncing model requires all nodes proactively broadcast their latest status.
	// The load is acceptable if the maximum peers are 1k.
	// TODO(thunder): [R3] ensure we have a limited number of peers
	s := m.getStatus()
	if _, err := m.host.Broadcast(statusMessage{s}.toNetworkMessage(), nil); err != nil {
		logger.Info("[%s] %s", m.loggingId, err)
	}
}

// Called in the handleEventLoop goroutine.
func (m *Mediator) onReceivedFreshestNotarizedChainExtendedEvent(
	e *blockchain.FreshestNotarizedChainExtendedEvent) {
	logger.Debug("[%s] onReceivedFreshestNotarizedChainExtendedEvent %s", m.loggingId, e.Sn)

	newLastNotarizedBlockInfo := metricsBlockInfo{
		e.Sn,
		m.chain.GetBlock(e.Sn).GetNumber(),
		time.Now(),
	}

	metrics.AddCounter(m.palaMetrics.NumNotarized,
		int64(newLastNotarizedBlockInfo.blockNum-m.lastNotarizedBlockInfo.blockNum))
	if !m.lastNotarizedBlockInfo.blockSn.IsNil() {
		metrics.ObserveHistogram(m.palaMetrics.NotarizationTime,
			newLastNotarizedBlockInfo.blockTime.Sub(m.lastNotarizedBlockInfo.blockTime).Seconds())
	}
	m.lastNotarizedBlockInfo = newLastNotarizedBlockInfo

	epoch := m.epochManager.GetEpoch()
	if e.Sn.Epoch.Compare(epoch) > 0 {
		debug.Bug("epoch is %s but the freshest notarized block is %s", epoch, e.Sn)
	} else if e.Sn.Epoch.Compare(epoch) == 0 {
		// There is progress, so reset the timer.
		m.actorTimer.Reset(m.voterWaitingPeriodBeforeClockMsg, m.epochManager.GetEpoch())
		// Force rotate proposer.
		if m.role.ExceedEpochMaxAllowedSeq(e.Sn.NextS(), m.chain.GetBlock(e.Sn).GetNumber()) {
			if err := m.actor.ForceTimeoutToRotateProposers(e.Sn); err != nil {
				logger.Error("[%s] rotate proposer failed: %s", m.loggingId, err)
			}
		}
	}
	m.actor.AddFreshestNotarizedChainExtendedEvent(*e)
	m.notifyEvent(FreshestNotarizedChainExtendedEvent{e.Sn})
}

// Called in the handleEventLoop goroutine.
func (m *Mediator) onReceivedFinalizedChainExtendedEvent(
	e *blockchain.FinalizedChainExtendedEvent) {
	logger.Debug("[%s] onReceivedFinalizedChainExtendedEvent %s", m.loggingId, e.Sn)
	m.actor.AddFinalizedChainExtendedEvent(*e)

	block := m.chain.GetBlock(e.Sn)
	// metrics
	newLastFinalizeBlockInfo := metricsBlockInfo{
		e.Sn,
		block.GetNumber(),
		time.Now(),
	}

	// Log metrics for num votes in notarization upon finalized chain extended because the finalized chain contains the
	// most canonical version of the notarization of the block in notarizes and should have the most votes in it.
	// Decoding notarizations takes work so do an explicit check here
	if m.palaMetrics.NumVotesInNotarizationInLastFinalizedBlock != nil {
		notas, _ := m.chain.DecodeBlock(block)
		for _, nota := range notas {
			metrics.ObserveHistogram(m.palaMetrics.NumVotesInNotarizationInLastFinalizedBlock, float64(nota.GetNVote()))
		}
	}

	metrics.AddCounter(m.palaMetrics.NumFinalized,
		int64(newLastFinalizeBlockInfo.blockNum-m.lastFinalizedBlockInfo.blockNum))
	if !m.lastFinalizedBlockInfo.blockSn.IsNil() {
		metrics.ObserveHistogram(m.palaMetrics.FinalizationTime,
			newLastFinalizeBlockInfo.blockTime.Sub(m.lastFinalizedBlockInfo.blockTime).Seconds())
	}
	m.lastFinalizedBlockInfo = newLastFinalizeBlockInfo

	event := FinalizedChainExtendedEvent{Sn: e.Sn}

	// When the first block and the stop block is finalized at the same time,
	// the reconfiguration of the last session ends and then the reconfiguration of the new session
	// begins. Thus, we must call endReconfigurationIfSessionAdvance() before beginReconfigureIfNeeded().
	event.ReconfigurationEndTriggered = m.endReconfigurationIfSessionAdvance(e.Sn)
	event.ReconfigurationBeginTriggered = m.beginReconfigureIfNeeded(e.Sn)

	m.notifyEvent(event)
}

func (m *Mediator) beginReconfigureIfNeeded(finalizedHeadSn blockchain.BlockSn) bool {
	if m.reconfiguringSession != nil {
		return false
	}

	if !m.shouldReconfigure() {
		return false
	}

	m.reconfiguringSession = &finalizedHeadSn.Epoch.Session
	logger.Note("[%s] reconfiguration begins at %s", m.loggingId, finalizedHeadSn)
	metrics.IncCounter(m.palaMetrics.Proposer_CommitteeRound)

	m.reconfBeginTime = time.Now()

	if err := m.reconfigurer.UpdateVerifier(m.chain, m.verifier); err != nil {
		logger.Error("failed to update Verifier during reconfiguration %s: %s", finalizedHeadSn, err)
	}
	if err := m.reconfigurer.UpdateRoleAssigner(m.chain, m.role); err != nil {
		logger.Error("failed to update RoleAssigner during reconfiguration %s: %s", finalizedHeadSn, err)
	}

	for _, extra := range m.extraServices {
		if reader, ok := extra.(SessionReader); ok {
			m.reconfigurer.UpdateSession(m.chain, reader)
		}
	}

	// In theory, updated objects should be independent from EpochManager, so the update order doesn't matter.
	// However, we still update EpochManager in the last to avoid any potential risk.
	oldEpoch := m.epochManager.GetEpoch()
	if oldEpoch.Session < *m.reconfiguringSession+1 {
		if err := m.reconfigurer.UpdateEpochManager(m.chain, m.epochManager); err == nil {
			newEpoch := m.epochManager.GetEpoch()
			if err := m.actor.SetEpoch(newEpoch); err != nil {
				logger.Info("[%s] failed to set epoch %s; err=%s", m.loggingId, newEpoch, err)
			}
			m.syncer.SetMyEpoch(newEpoch)
		} else {
			logger.Error("[%s] failed to update EpochManager during reconfiguration %s: %s",
				m.loggingId, finalizedHeadSn, err)
		}
	} else {
		logger.Warn("[%s] current epoch %s >= target epoch %s. Skip updating epoch by reconfiguration. "+
			"This is possible when we restart during the reconfiguration "+
			"and have received ClockMsgNota in the new session", m.loggingId, oldEpoch, *m.reconfiguringSession+1)
	}

	m.reconfigurer.UpdateMetrics(m.chain, m.palaMetrics)

	s := m.epochManager.GetEpoch().Session
	addr := m.getMyAddress()
	if err := m.reconfigurer.UpdateHost(m.chain, m.host, m.role, addr); err != nil {
		logger.Error("failed to update Host during reconfiguration %s: %s", finalizedHeadSn, err)
	}

	m.checkRoles(s)
	m.logShortNameMapping()

	// NOTE: the management of the worker goroutine of blockchain:
	// * BlockChain stops the worker automatically before sending the finalized event.
	// * Mediator is responsible to start the worker when needed.
	if m.chain.IsCreatingBlock() {
		// Expect this won't happen.
		logger.Error("[%s] the chain is creating block "+
			"after the reconfiguration happened", m.loggingId)
	}
	m.stopCreatingNewBlocksIfNeeded()
	newEpoch := m.epochManager.GetEpoch()
	logger.Note("[%s] update epoch from %s to %s due to the reconfiguration",
		m.loggingId, oldEpoch, newEpoch)
	// The local epoch is advanced, so reset the timer to make the timer be consistent with
	// the others.
	m.actorTimer.Reset(m.voterWaitingPeriodBeforeClockMsg, m.epochManager.GetEpoch())

	numVoter := 0
	for id, _ := range m.syncer.GetPeersStatus() {
		if m.role.IsVoter(id, newEpoch.Session) {
			numVoter++
		}
	}
	metrics.SetGauge(m.palaMetrics.Proposer_ActiveCommittees, int64(numVoter))

	if m.role.IsVoter(UseMyId, newEpoch.Session) {
		metrics.IncCounter(m.palaMetrics.Voter_ActiveCommRounds)
	}
	m.makeFirstProposalIfNeeded()

	return true
}

func (m *Mediator) logShortNameMapping() {
	nameMapping := m.role.GetShortNameMapping()
	var names []string
	for n := range nameMapping {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		logger.Note("[%s] name/id mapping: %s -> %s", m.loggingId, name, nameMapping[name])
	}
}

func (m *Mediator) endReconfigurationIfSessionAdvance(finalizedHeadSn blockchain.BlockSn) bool {
	if m.reconfiguringSession == nil {
		return false
	}

	if finalizedHeadSn.Epoch.Session <= *m.reconfiguringSession {
		logger.Note("Reconfigure not end. finalized %s expect %d", finalizedHeadSn, *m.reconfiguringSession)
		return false
	}

	if finalizedHeadSn.S != 1 {
		debug.Bug("Expected first finalized block of a session to be S=1 but get %s", finalizedHeadSn)
	}

	logger.Note("[%s] reconfiguration ends at %s", m.loggingId, finalizedHeadSn)
	// After the reconfiguration, the new proposers and voters have liveness now.
	// It's safe to reset the state and drop connections to old proposers and voters.
	m.reconfiguringSession = nil
	d := time.Now().Sub(m.reconfBeginTime)
	logger.Note("[%s] took %s to finish the reconfiguration (current epoch=%s)",
		m.loggingId, d, finalizedHeadSn.Epoch)
	m.reconfBeginTime = time.Time{}

	if !m.role.IsBootnode(UseMyId) {
		m.host.CloseConnections(func(id ConsensusId) bool {
			session := m.epochManager.GetEpoch().Session
			// TODO(thunder): when bootnode can come from ElectionResult's maybe
			// close connections to them here
			return !IsConsensusNode(m.role, id, session) && !m.role.IsBootnode(id)
		})
	}

	return true
}

// Called in the handleEventLoop goroutine.
func (m *Mediator) handleSelfMessage(msg interface{}) {
	switch v := msg.(type) {
	case rpcRequest:
		m.handleRpcRequest(v)
	case chan DebugState:
		v <- m.getDebugState()
	case makeFirstProposalIfNeededEvent:
		m.makeFirstProposalIfNeeded()
	default:
		logger.Warn("[%s] received unknown self message %v", m.loggingId, msg)
	}
}

// Called in the handleEventLoop goroutine.
func (m *Mediator) broadcast(msg blockchain.Message) {
	// Only the primary proposer broadcasts a proposal or a notarization.
	if msg.GetType() == blockchain.TypeProposal {
		p := msg.(blockchain.Proposal)
		m.lastBroadcastedProposal = p.GetBlockSn()
		m.unnotarizedProposals[p.GetBlockSn()] = p
	} else if msg.GetType() == blockchain.TypeNotarization {
		n := msg.(blockchain.Notarization)
		delete(m.unnotarizedProposals, n.GetBlockSn())
	}

	nm := consensusDataMessage{msg}.toNetworkMessage()
	sn := msg.GetBlockSn()
	if msg.GetType() == blockchain.TypeClockMsg {
		// When the voter creates a clock message, it means the primary proposer is offline.
		// Send the clock message to all proposers and hope one of the proposer is online.
		m.host.Broadcast(nm, func(id ConsensusId) bool {
			return m.role.IsProposer(id, m.epochManager.GetEpoch().Session)
		})
		return
	}

	if n, err := m.host.Broadcast(nm, nil); err != nil {
		logger.Info("[%s] cannot broadcast %s (sn=%s); err=%s",
			m.loggingId, msg.GetType(), sn, err)
	} else if n != 0 {
		if msg.GetType() == blockchain.TypeProposal {
			metrics.AddCounter(m.palaMetrics.Proposer_ProposalsSent, int64(n))
		} else if msg.GetType() == blockchain.TypeNotarization {
			metrics.AddCounter(m.palaMetrics.Proposer_NotarizationsSent, int64(n))
		}
	}

}

// Called in the handleEventLoop goroutine.
func (m *Mediator) makeFirstProposalIfNeeded() {
	epoch := m.epochManager.GetEpoch()
	if !m.role.IsPrimaryProposer(UseMyId, epoch) ||
		epoch.Compare(m.chain.GetFreshestNotarizedHeadSn().Epoch) <= 0 {
		logger.Info("[%s] makeFirstProposalIfNeeded epoch=%s: skipped", m.loggingId, epoch)
		return
	}

	m.syncer.SetIAmPrimaryProposer(true)

	now := m.clock.Now()
	var zero time.Time
	if m.reconciliationWithAllBeginTime == zero {
		m.reconciliationWithAllBeginTime = now
		m.unnotarizedProposals = make(map[blockchain.BlockSn]blockchain.Proposal)
	}

	// If we'll create the first block of a new session, start creating the block as long as
	// we're ready because we want to end the reconfiguration immediately and there is little chance that the parent
	// block is mismatched with voters.
	ready := m.syncer.IsReadyToPropose()
	if m.chain.GetFreshestNotarizedHeadSn().Epoch.Session < epoch.Session && ready {
		logger.Note("[%s] we're ready to make the first block (epoch=%s)", m.loggingId, epoch)
		m.startCreatingNewBlocks()
		return
	}

	// We need to wait a while before making the first block. Here are the reasons:
	// * We have the chance to collect more notarized blocks.
	// * It's possible that voters extend their freshest notarized head right after the new primary
	//   proposer synced the status with them. This is possible because the last primary proposer
	//   may be still collecting votes and broadcast a new notarization. In this case, the new
	//   primary proposer will make a proposal rejected by those voters. Waiting one second can
	//   reduces the chance of having such a race condition error.
	d := now.Sub(m.reconciliationWithAllBeginTime)
	if d < m.delayOfMakingFirstProposal {
		go func(ch chan interface{}) {
			d = m.delayOfMakingFirstProposal - d
			time.Sleep(d)
			ch <- makeFirstProposalIfNeededEvent{}
		}(m.selfChan)
		return
	}

	if ready {
		logger.Note("[%s] we're ready to make the first block (epoch=%s)", m.loggingId, epoch)
		m.startCreatingNewBlocks()
		return
	}

	// We're not ready to make the first block because our status is behind voters.
	// Wait a while if possible.
	hardLimit := m.voterWaitingPeriodBeforeClockMsg * 2
	if d < hardLimit {
		go func(ch chan interface{}) {
			d = hardLimit - d
			time.Sleep(d)
			ch <- makeFirstProposalIfNeededEvent{}
		}(m.selfChan)
		return
	}

	// It doesn't matter whether we're ready. We must make a proposal now;
	// otherwise, we're not have enough time to collect votes and make the notarization.
	sn := m.chain.GetFreshestNotarizedHeadSn()
	if m.syncer.IsReadyToPropose() {
		logger.Note("[%s] we're ready to make the first block (epoch=%s, head=%s)",
			m.loggingId, epoch, sn)
	} else {
		logger.Note("[%s] we're not ready to make the first block "+
			" (epoch=%s, head=%s), but we have to make anyway", m.loggingId, epoch, sn)
	}
	m.startCreatingNewBlocks()
}

// Called in the handleEventLoop goroutine.
func (m *Mediator) startCreatingNewBlocks() {
	if m.blockChan != nil {
		return
	}
	epoch := m.epochManager.GetEpoch()
	cNota := m.epochManager.GetLatestClockMsgNota(epoch.Session)
	var err error
	if m.blockChan, err = m.chain.StartCreatingNewBlocks(epoch, cNota); err != nil {
		logger.Error("[%s] cannot start creating new blocks; err=%s", m.loggingId, err)
	} else {
		fncSn := m.chain.GetFreshestNotarizedHeadSn()
		logger.Note("[%s] start creating new blocks from %s (epoch=%s)",
			m.loggingId, fncSn, epoch)
	}
}

func (m *Mediator) stopCreatingNewBlocksIfNeeded() {
	if m.chain.IsCreatingBlock() {
		if err := m.chain.StopCreatingNewBlocks(blockchain.WaitingPeriodForStopingNewBlocks); err != nil {
			logger.Warn("[%s] cannot stop creating new blocks: %s", m.loggingId, err)
		} else {
			logger.Note("[%s] stopped creating new blocks", m.loggingId)
		}
	}
	m.blockChan = nil
	m.reconciliationWithAllBeginTime = time.Time{}
	m.unnotarizedProposals = nil
	m.syncer.SetIAmPrimaryProposer(false)
}

// Called in the handleEventLoop goroutine.
func (m *Mediator) handleNetworkMessage(msg *network.Message) {
	attr := msg.GetAttribute()
	if attr&network.AttrOpen > 0 {
		m.onConnectionIsReady(msg)
		return
	}

	if attr&network.AttrClosed > 0 {
		m.onConnectionIsClosed(msg)
		return
	}

	if attr&network.AttrHandshakeError > 0 || attr&network.AttrUnverifiedConnection > 0 {
		logger.Info("[%s] unexpectd message with attribute %d", m.loggingId, attr)
		return
	}

	// Rate limit by msg type, drop the msg if exceed limit.
	if m.msgLimiter != nil {
		msgid := limiter.MsgId(MessageId(msg.GetType()).String())
		id := limiter.Id(msg.GetId())
		if !m.msgLimiter.Allow(msgid, id, 1) {
			logger.Info("[%s] over rate limit, drop msg (id=%s) msg type=(%d)",
				m.loggingId, msg.GetId(), msg.GetType())
			return
		}
	}

	handler, err := m.decodeNetworkMessage(msg)
	if err != nil {
		logger.Info("[%s] decode error: %s", m.loggingId, err)
		msg.CloseConnection()
		return
	}
	if handler != nil {
		handler()
		return
	}

	metrics.IncCounter(m.palaMetrics.BadMessageCode)
	logger.Info("[%s] received a network message with an unknown type %d", m.loggingId, msg.GetType())
}

// Called in Mediator.handleEventLoop goroutine.
func (m *Mediator) decodeNetworkMessage(msg *network.Message) (func(), error) {
	typ := MessageId(msg.GetType())
	logger.Debug("[%s] handleEventLoop receives type=%s %s",
		m.loggingId, typ, msg.GetSourceDebugInfo())

	// ChainsyncMessage
	switch typ {
	case MessageStatus:
		response, err := newStatusMessage(msg)
		if err != nil {
			return nil, err
		}
		return func() {
			id := msg.GetId()
			if id != "" {
				m.syncer.SetPeerStatus(id, response.status)
			}
		}, nil
	case MessageGetFresherHead:
		request, err := newGetFresherHeadMessage(msg)
		if err != nil {
			return nil, err
		}
		return func() {
			go m.onGetFresherHead(request, msg)
		}, nil
	case MessageGetFresherHeadV2:
		request, err := newGetFresherHeadV2Message(msg)
		if err != nil {
			return nil, err
		}
		return func() {
			go m.onGetFresherHeadV2(request, msg)
		}, nil
	case MessageFresherHeadMeta:
		response, err := newFresherHeadMetaMessage(msg)
		if err != nil {
			return nil, err
		}
		return func() {
			m.onFresherHeadMeta(response, msg)
		}, nil
	case MessageFresherHeadData:
		response, err := newFresherHeadDataMessage(m.unmarshaller, msg)
		if err != nil {
			return nil, err
		}
		return func() {
			m.onFresherHeadData(response, msg)
		}, nil
	case MessageFresherHeadDataV2:
		response, err := newFresherHeadDataV2Message(m.unmarshaller, msg)
		if err != nil {
			return nil, err
		}
		return func() {
			m.onFresherHeadDataV2(response, msg)
		}, nil
	case MessageUnnotarizedProposals:
		response, err := newUnnotarizedProposalsMessage(m.unmarshaller, msg)
		if err != nil {
			return nil, err
		}
		return func() {
			m.onUnnotarizedProposals(response, msg)
		}, nil
	case MessageGetEpoch:
		request, err := newGetEpochMessage(msg)
		if err != nil {
			return nil, err
		}
		return func() {
			m.onGetEpoch(request, msg)
		}, nil
	case MessageEpoch:
		response, err := newEpochMessage(m.unmarshaller, msg)
		if err != nil {
			return nil, err
		}
		return func() {
			m.onEpoch(response, msg)
		}, nil
	}

	// BlockChainMessage
	switch typ {
	case MessageBlock:
		// We should only take notarized blocks or proposals; otherwise, attackers can
		// send lots of invalid blocks to cause a deny of service.
		logger.Warn("[%s] handleEventLoop receives a block directly. Skip it", m.loggingId)
	case MessageProposal:
		p, _, err := m.unmarshaller.UnmarshalProposal(msg.GetBlob())
		if err != nil {
			logger.Warn("[%s] handleEventLoop receives invalid proposal; err=%s", m.loggingId, err)
			return nil, err
		}

		return func() {
			if err := m.addProposal(p, msg); err != nil {
				logger.Info("[%s] failed to add a proposal (%s); err=%s",
					m.loggingId, p.GetBlockSn(), err)
			}
		}, nil
	case MessageVote:
		v, _, err := m.unmarshaller.UnmarshalVote(msg.GetBlob())
		if err != nil {
			metrics.IncCounter(m.palaMetrics.Proposer_VoteDecodeBad)
			logger.Warn("[%s] handleEventLoop receives invalid vote; err=%s", m.loggingId, err)
			return nil, err
		}
		return func() {
			if err := m.actor.AddVote(v); err != nil {
				logger.Info("[%s] failed to add a vote (%s); err=%s", m.loggingId, v.GetBlockSn(), err)
			}
		}, nil
	case MessageNotarization:
		n, _, err := m.unmarshaller.UnmarshalNotarization(msg.GetBlob())
		if err != nil {
			logger.Warn("[%s] handleEventLoop receives invalid notarization; err=%s", m.loggingId, err)
			return nil, err
		}
		return func() {
			if err := m.actor.AddNotarization(n); err != nil {
				logger.Info("[%s] failed to add a notarization (%s); err=%s", m.loggingId, n.GetBlockSn(), err)
			}
		}, nil
	case MessageClockMsg:
		c, _, err := m.unmarshaller.UnmarshalClockMsg(msg.GetBlob())
		if err != nil {
			logger.Warn("[%s] handleEventLoop receives invalid clock message; err=%s", m.loggingId, err)
			return nil, err
		}
		return func() {
			if err := m.actor.AddClockMsg(c); err != nil {
				logger.Info("[%s] failed to add a clock msg (%s); err=%s", m.loggingId, c.GetEpoch(), err)
			}
		}, nil
	case MessageClockMsgNota:
		cNota, _, err := m.unmarshaller.UnmarshalClockMsgNota(msg.GetBlob())
		if err != nil {
			logger.Warn("[%s] handleEventLoop receives invalid clock message notarization; err=%s", m.loggingId, err)
			return nil, err
		}
		return func() {
			if err := m.actor.AddClockMsgNota(cNota); err != nil {
				logger.Info("[%s] failed to add a clock msg nota (%s); err=%s",
					m.loggingId, cNota.GetEpoch(), err)
			}
		}, nil
	}

	return nil, nil
}

// Called in Mediator.handleEventLoop goroutine.
func (m *Mediator) onConnectionIsReady(msg *network.Message) {
	id := msg.GetId()
	m.notifyEvent(ConnectionOpenEvent{id})
	logger.Info("[%s] connection ready (id=%s)", m.loggingId, id)
	m.syncer.SetHostAddress(id, msg.GetSourceAddress())
	// Our syncing model requires notifying the new peer our latest status.
	s := m.getStatus()
	if err := m.host.Send(id, statusMessage{s}.toNetworkMessage()); err != nil {
		logger.Warn("[%s] host.Send: err: %s", m.loggingId, err)
	}

	if m.role.IsVoter(id, m.epochManager.GetEpoch().Session) {
		metrics.IncGauge(m.palaMetrics.Proposer_ActiveCommittees)
	}
}

// Called in Mediator.handleEventLoop goroutine.
func (m *Mediator) onConnectionIsClosed(msg *network.Message) {
	logger.Info("[%s] the connection to id=%s is disconnected",
		m.loggingId, m.getShortName(msg.GetId()))
	id := msg.GetId()
	m.syncer.SetPeerOffline(id)
	m.notifyEvent(ConnectionClosedEvent{id})
	if m.role.IsVoter(id, m.epochManager.GetEpoch().Session) {
		metrics.AddGauge(m.palaMetrics.Proposer_ActiveCommittees, -1)
	}
}

func (m *Mediator) NewNotificationChannel() <-chan interface{} {
	m.eventChansMutex.Lock()
	defer m.eventChansMutex.Unlock()
	ch := make(chan interface{}, 1024)
	m.eventChans = append(m.eventChans, ch)
	return ch
}

func (m *Mediator) RemoveNotificationChannel(target <-chan interface{}) {
	m.eventChansMutex.Lock()
	defer m.eventChansMutex.Unlock()
	for i, ch := range m.eventChans {
		if ch == target {
			m.eventChans = append(m.eventChans[:i], m.eventChans[i+1:]...)
			break
		}
	}
}

func (m *Mediator) UseFakeNetworkForTest() {
	m.useFakeNetwork = true
}

func (m *Mediator) ConnectForTest(addresses map[ConsensusId]string) {
	utils.EnsureRunningInTestCode()
	m.connect(addresses)
}

func (m *Mediator) StartSyncerForTest() {
	utils.EnsureRunningInTestCode()
	m.syncer.Start()
}
func (m *Mediator) StopSyncerForTest() {
	utils.EnsureRunningInTestCode()
	m.syncer.Stop()
}

func (m *Mediator) GetHostForTest() *network.Host {
	utils.EnsureRunningInTestCode()
	return m.host
}

func (m *Mediator) GetActorForTest() *Actor {
	utils.EnsureRunningInTestCode()
	return m.actor
}

func (m *Mediator) GetBlockChainForTest() blockchain.BlockChain {
	utils.EnsureRunningInTestCode()
	return m.chain
}

func (m *Mediator) GetEpochManagerForTest() blockchain.EpochManager {
	utils.EnsureRunningInTestCode()
	return m.epochManager
}

func (m *Mediator) GetDebugState() <-chan DebugState {
	ch := make(chan DebugState, 1)
	m.selfChan <- ch
	return ch
}

// Called in the handleEventLoop goroutine.
func (m *Mediator) getStatus() chainsync.Status {
	info := m.chain.GetFreshestNotarizedHeadInfo()

	nodeVersion := commitsha1.CommitSha1
	if commitsha1.CommitTag != "" {
		nodeVersion += "-" + commitsha1.CommitTag
	}

	return chainsync.Status{
		FncBlockSn:  info.Sn,
		Epoch:       m.epochManager.GetEpoch(),
		BlockHeight: info.Number,
		NodeVersion: nodeVersion,
	}
}

// Reconfiguration:
// * Begin when the stop block is finalized.
// * End when the first block of the next session is finalized.
func (m *Mediator) shouldReconfigure() bool {
	// When there is no pala block, we don't have the stop block yet.
	sb := m.chain.GetLatestFinalizedStopBlock()
	if sb == nil {
		return false
	}
	sb_session := sb.GetBlockSn().Epoch.Session
	fh_session := m.chain.GetFinalizedHeadSn().Epoch.Session
	return sb_session > 0 && sb_session == fh_session
}

// Called in the handleEventLoop goroutine.
func (m *Mediator) getDebugState() DebugState {
	var ps []blockchain.Message
	for _, p := range m.unnotarizedProposals {
		ps = append(ps, p)
	}
	sort.Sort(blockchain.ByBlockSn(ps))

	var sb strings.Builder
	_, _ = sb.WriteString("[")
	first := true
	for _, p := range ps {
		b := p.(blockchain.Proposal).GetBlock()
		if !first {
			_, _ = sb.WriteString(" ")
		}
		_, _ = sb.WriteString(fmt.Sprintf("%s<-%s", b.GetParentBlockSn(), b.GetBlockSn()))
		first = false
	}
	_, _ = sb.WriteString("]")

	var ids []ConsensusId
	for id, _ := range m.syncer.GetPeersStatus() {
		ids = append(ids, id)
	}
	ConsensusIds(ids).Sort()
	return DebugState{
		Identity:             m.loggingId,
		Status:               m.getStatus(),
		SyncerState:          m.syncer.GetDebugState(),
		ConnectedIds:         ids,
		ProposalInfo:         sb.String(),
		IsMakingBlock:        m.blockChan != nil,
		LastBroadcastedBlock: m.lastBroadcastedProposal,
	}
}

// Only used for logging.
func (m *Mediator) getShortName(id ConsensusId) string {
	return m.role.GetShortName(id)
}

func (m *Mediator) GetRpcStatusForTest() bool {
	utils.EnsureRunningInTestCode()
	return m.rpcRunning
}

//--------------------------------------------------------------------

func NetworkRole(s blockchain.Session, r RoleAssigner) network.Role {
	if r.IsProposer(UseMyId, s) || r.IsBootnode(UseMyId) {
		return network.RoleHub
	}
	return network.RoleSpoke
}

func (r roleForChainSyncer) IsVoter(id ConsensusId, session blockchain.Session) bool {
	return r.role.IsVoter(id, session)
}

func (r roleForChainSyncer) IsReadyToPropose(ids []ConsensusId, session blockchain.Session) bool {
	if r.role.IsVoter(UseMyId, session) {
		vid := r.role.GetMyId()
		missed := true
		for _, id := range ids {
			if vid == id {
				missed = false
				break
			}
		}
		if missed {
			ids = append(ids, vid)
		}
	}
	return r.verifier.IsReadyToPropose(ids, session)
}

func (r roleForChainSyncer) GetShortName(id ConsensusId) string {
	return r.role.GetShortName(id)
}
