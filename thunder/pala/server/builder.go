package server

import (
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/ethconfig"

	"github.com/ethereum/go-ethereum/thunder/pala/bidder"
	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/consensus"
	"github.com/ethereum/go-ethereum/thunder/pala/consensus/chainsync"
	"github.com/ethereum/go-ethereum/thunder/pala/consensus/startstopwaiter"
	"github.com/ethereum/go-ethereum/thunder/pala/limiter"
	"github.com/ethereum/go-ethereum/thunder/pala/metrics"
	"github.com/ethereum/go-ethereum/thunder/pala/network"
	"github.com/ethereum/go-ethereum/thunder/pala/rmonitor"
	"github.com/ethereum/go-ethereum/thunder/pala/server/internal/configreader"
	"github.com/ethereum/go-ethereum/thunder/pala/types"

	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chainconfig"
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/consensus/thunder"
	"github.com/ethereum/go-ethereum/thunder/thunderella/keymanager"
	oldMetrics "github.com/ethereum/go-ethereum/thunder/thunderella/libs/analytics/metrics"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"golang.org/x/xerrors"
)

type ConsensusId = types.ConsensusId

var MakeConsensusIds = types.MakeConsensusIds

var logger = lgr.NewLgr("/server")

type Config struct {
	LoggingId string

	// Geth/Block parameters
	LogDir       string
	GcMode       string
	TimePerBlock time.Duration

	// Genesis Block
	GenesisCommInfo *committee.CommInfo
	PalaFromGenesis bool

	AlterCommInfo map[string]*committee.CommInfo

	// Metrics parameters
	MetricsAddr string

	// Proposer parameters
	ProposerHostPort string

	// Profile parameters
	ResourceMonitorEnable   bool
	ResourceMonitorInterval time.Duration

	// Key management parameters
	KeyConfig KeyConfig

	// Role parameters.
	IsFullNode         bool
	BootnodeListenPort int64 // port number on which to start the Thunder wire protocol for the bootnode,
	// BootnodeListenPort is both a role and a network parameter
	IsVoter    bool
	IsProposer bool

	// Network parameters
	AddressesOfBootnodesITrust []string // addresses of bootnodes I trust
	BootnodesOwnPublicAddress  string   // a bootnode would avoid connecting to this address to avoid connecting to itself

	// TxRouting
	IdsOfTxRouting []string

	// Pala consensus parameters.
	K                              *config.Int64HardforkConfig
	DelayOfMakingFirstProposal     time.Duration
	VoterWaitingTimeBeforeClockMsg time.Duration

	BidderConfig bidder.BidderCfg

	ElectionStopBlockSessionOffset *config.Int64HardforkConfig

	ServiceConfig ServiceConfig

	NetworkThrottlingConfig network.ThrottlingConfig
	ChainSyncLimitConfig    []limiter.MsgLimitConfig
	TxServiceLimitConfig    []limiter.MsgLimitConfig

	TracerCacheSize  int64
	RpcMaxDelayBlock int64
	RpcSuspendBuffer time.Duration
}

type KeyConfig struct {
	KeyManager *keymanager.KeyManager
	// Used to retrieve the proposing/voting key from KeyManager
	// All are optional.
	ProposingKeyId string
	VotingKeyId    string
	StakeInKeyId   string
}

type TxPoolConfig struct {
	RunServer    bool
	RunClient    bool
	ServerIpPort string // Must set this if RunServer/RunClient is true.
}

type NodeConfig struct {
	Version string
	DataDir string

	// RPC parameters
	RpcListenHostname string
	RpcListenPort     int64
	RpcCorsDomains    []string
	RpcVirtualHosts   []string
	RpcModules        []string
	WsListenHostname  string
	WsListenPort      int64
	WsOrigins         []string
	WsRpcModules      []string
}

type EthConfig struct {
	NoPruning   bool
	GenesisPath string

	HardforkCfg *blockchain.HardforkCfg

	TxPool  core.TxPoolConfig
	ChainId int64

	CacheInMb        int64
	DbCachePercent   int64
	TrieCachePercent int64
	FdLimit          int64
	SnapshotCache    int64
	HistoryOrderList []string

	MaxRpcLogsBlockRange int64
	TxLookupLimit        int64
}

type ServiceConfig struct {
	EthChain  *core.BlockChain
	EthDb     ethdb.Database
	TxPool    *core.TxPool
	RpcSwitch consensus.RpcSwitch
}

const (
	clientIdentifier = "thunder"
)

func validWebSocketUrlOrEmpty(url string) error {
	if url == "" {
		return nil
	}
	if !strings.HasPrefix(url, "ws://") && !strings.HasPrefix(url, "wss://") {
		return xerrors.Errorf("%q is not a valid WebSocket URL. Must start with \"ws://\" or \"wss://\"", url)
	}
	return nil
}

func newBlockChain(cfg *Config, me metrics.PalaMetrics) (blockchain.BlockChain, error) {
	bCfg := blockchain.Config{
		ChainDb:           cfg.ServiceConfig.EthDb,
		EthChain:          cfg.ServiceConfig.EthChain,
		Txpool:            cfg.ServiceConfig.TxPool,
		UnnotarizedWindow: cfg.K,
		TimePerBlock:      cfg.TimePerBlock,
		CommInfo:          cfg.GenesisCommInfo,
		AlterCommInfo:     cfg.AlterCommInfo,
		PalaFromGenesis:   cfg.PalaFromGenesis,
		Metrics:           me,
		TracerCacheSize:   cfg.TracerCacheSize,
	}

	bc, err := blockchain.NewBlockChain(bCfg)
	if err != nil {
		return nil, err
	}
	return bc, nil
}

func NewMediatorAndDependency(cfg *Config) (*consensus.Mediator, *bidder.Bidder, error) {
	if cfg.IsProposer || cfg.IsVoter {
		if cfg.GcMode != "archive" {
			return nil, nil, xerrors.Errorf("consensus Nodes can only run in archive mode not %q", cfg.GcMode)
		}
	}
	if err := validWebSocketUrlOrEmpty(cfg.BidderConfig.Url); err != nil {
		return nil, nil, err
	}

	ethChain, chainDb, txPool := cfg.ServiceConfig.EthChain, cfg.ServiceConfig.EthDb, cfg.ServiceConfig.TxPool

	palaParams := &consensus.PalaParams{
		K:                              cfg.K,
		DelayOfMakingFirstProposal:     cfg.DelayOfMakingFirstProposal,
		VoterWaitingTimeBeforeClockMsg: cfg.VoterWaitingTimeBeforeClockMsg,
	}

	me := metrics.NewPalaMetrics("", !utils.InTest())
	bc, err := newBlockChain(cfg, me)
	if err != nil {
		return nil, nil, err
	}

	// Prepare and start TxPool server.
	var extraServices []startstopwaiter.StartStopWaiter

	// Prepare BlockChain.
	marshaller := &blockchain.DataUnmarshallerImpl{Config: ethChain.Config().Thunder}

	if cfg.ResourceMonitorEnable {
		resourceMonitor, err := rmonitor.NewResourceMonitor(
			cfg.ResourceMonitorInterval,
			cfg.LogDir,
			bc,
			txPool,
		)
		if err == nil {
			extraServices = append(extraServices, resourceMonitor)
		} else {
			debug.Bug("new resource monitor failed: %v", err)
		}
	}

	// During reconfiguration, new consensus nodes can connect to old consensus nodes and sync,
	// this reduces bootnode's loading on block distribution. The session we choose to use here
	// determines the chance of the above situation to happen if new consensus nodes crash
	// "during reconfiguration":
	// - EpochManager: The epoch is advanced right after reconfiguration begins. So the node only
	//   connects to new consensus nodes after restarted.
	// - NotarizedHead: The node has the chance to connect to old consensus nodes if it crashes
	//   after reconfiguration-begun and before the first block of the new session was notarized.
	// - FinalizedHead: Similar to NotarizedHead, but finalized.
	s := bc.GetFreshestNotarizedHeadSn().Epoch.Session
	if s < 1 {
		s = 1
	}
	commInfo := bc.(*blockchain.BlockChainImpl).GetCommInfo(s)
	if commInfo == nil {
		return nil, nil, xerrors.New("Failed to get CommInfo")
	}
	consensus.UpdateElectionResultMetrics(commInfo, me)

	// Prepare RoleAssigner and Verifier.
	// Prepare Mediator
	bootnodeCfg := consensus.BootnodeConfig{
		ListenPort:       cfg.BootnodeListenPort,
		TrustedAddresses: cfg.AddressesOfBootnodesITrust,
		OwnPublicAddress: cfg.BootnodesOwnPublicAddress,
	}

	electionResult := blockchain.NewElectionResultImpl(commInfo, s)
	roleAssignerCfg := &consensus.RoleAssignerImplCfg{
		K:                              cfg.K,
		IsBootnode:                     consensus.IsBootnodeViaBootnodeConfig(bootnodeCfg),
		LoggingId:                      cfg.LoggingId,
		ElectionStopBlockSessionOffset: cfg.ElectionStopBlockSessionOffset,
	}

	verifierCfg := &blockchain.VerifierImplCfg{ElectionResult: electionResult, LoggingId: cfg.LoggingId}
	var bid *bidder.Bidder
	if cfg.IsVoter {
		privVoteKey, err := cfg.KeyConfig.KeyManager.GetCommPrivateVoteKey(
			cfg.KeyConfig.VotingKeyId, "")

		if err != nil {
			return nil, nil, xerrors.Errorf("Failed to get committee private voting key: %v", err)
		}
		voterId := consensus.Id(privVoteKey.GetPublicKey())
		roleAssignerCfg.MyId = voterId
		verifierCfg.Signer = privVoteKey

		stakeKey, err := cfg.KeyConfig.KeyManager.GetAccountKey(
			cfg.KeyConfig.StakeInKeyId, "", "Enter password for committee stake-in account: ", false)
		if err != nil {
			return nil, nil, xerrors.Errorf("Failed to load committee account key: %s", err)
		}
		bidderCfg := cfg.BidderConfig
		bidderCfg.VoteKeySigner = privVoteKey
		bidderCfg.StakeinKey = stakeKey
		bid, err = bidder.NewBidder(&bidderCfg)
		if err != nil {
			return nil, nil, err
		}
		extraServices = append(extraServices, bid)
	}

	if cfg.IsProposer {
		privPropKey, err := cfg.KeyConfig.KeyManager.GetCommPrivateVoteKey(
			cfg.KeyConfig.ProposingKeyId, "")
		if err != nil {
			return nil, nil, xerrors.Errorf("Cannot get the Accel proposing key, err=%v", err)
		}

		proposerId := consensus.Id(privPropKey.GetPublicKey())
		if cfg.IsVoter {
			if proposerId != roleAssignerCfg.MyId {
				debug.Bug("configuration error: a node can only have one id; proposerId=%s != voterId=%s",
					proposerId, roleAssignerCfg.MyId)
			}
		}
		roleAssignerCfg.MyId = proposerId
		verifierCfg.Signer = privPropKey
	}

	if roleAssignerCfg.MyId == "" {
		// A nonconsensus node generates its identity on the fly.
		// We don't need to save it in a permanent store. It's only used to prevent attackers
		// from dropping our connections by using our identity.
		signer, err := bls.NewSigningKey()
		if err != nil {
			debug.Bug("failed to generate bls key: %s", err)
		}
		verifierCfg.Signer = signer
		roleAssignerCfg.MyId = consensus.Id(signer.GetPublicKey())
	}

	roleAssigner := consensus.NewRoleAssignerImpl(roleAssignerCfg)
	roleAssigner.(*consensus.RoleAssignerImpl).AddElectionResult(electionResult)
	verifier := blockchain.NewVerifierImpl(verifierCfg)

	// Prepare Reconfigurer
	reconfigurerCfg := &consensus.ReconfigurerImplCfg{LoggingId: cfg.LoggingId}
	reconfigurer := consensus.NewReconfigurerImpl(reconfigurerCfg)

	// Prepare EpochManager
	epocher := blockchain.NewEpochManager(chainDb, marshaller)

	var routingConfig *consensus.TxRoutingConfig
	if len(cfg.IdsOfTxRouting) > 0 {
		logger.Info("NewMediatorAndDependency: Using custom tx routing. %v", cfg.IdsOfTxRouting)
		routingConfig = &consensus.TxRoutingConfig{
			Ids: MakeConsensusIds(cfg.IdsOfTxRouting...),
		}
	}

	txRouter := consensus.NewTxRouter(roleAssigner, routingConfig)

	mc := consensus.MediatorConfig{
		LoggingId:               cfg.LoggingId,
		Params:                  *palaParams,
		ProposerHostPort:        cfg.ProposerHostPort,
		NetworkId:               params.ThunderChainConfig().ChainID.Uint64(),
		BlockChain:              bc,
		Role:                    roleAssigner,
		ExtraServices:           extraServices,
		Verifier:                verifier,
		DataUnmarshaller:        marshaller,
		EpochManager:            epocher,
		ClockMessageTimer:       consensus.NewTimer(blockchain.Epoch{}),
		SyncDuration:            cfg.TimePerBlock,
		BootnodeConfig:          bootnodeCfg,
		TxPool:                  txPool,
		Reconfigurer:            reconfigurer,
		Selector:                chainsync.NewRandomSelector(),
		NetworkThrottlingConfig: cfg.NetworkThrottlingConfig,
		MsgLimiterConfig:        cfg.ChainSyncLimitConfig,
		TxServiceLimitConfig:    cfg.TxServiceLimitConfig,
		Metrics:                 me,
		TxRouter:                txRouter,
		RpcSwitch:               cfg.ServiceConfig.RpcSwitch,
		RpcMaxDelayBlock:        cfg.RpcMaxDelayBlock,
		RpcSuspendBuffer:        cfg.RpcSuspendBuffer,
		ClientPuzzleMgrCfg: &network.ClientPuzzleMgrCfg{
			Preference: []string{network.Keccak256CPUReversePuzzleName},
			Difficulty: 80000,
		},
		Bidder: bid,
	}

	m := consensus.NewMediator(mc)
	// Bind Mediator to our consensus.Engine Thunder, so Thunder can answer customized RPCs.
	ethChain.Engine().(*thunder.Thunder).SetRPCDelegate(m)
	serveMetrics(cfg.MetricsAddr, roleAssigner, epocher, me)

	return m, bid, nil
}

func DefaultAllowedConfig() (HttpCors []string, HttpVirtualHosts []string, WsOrigins []string) {
	HttpCors = []string{"*"}
	HttpVirtualHosts = []string{"*"}
	WsOrigins = []string{"*"}
	return
}

func publicRpcModules() []string {
	m0 := node.DefaultConfig.HTTPModules
	modules := make([]string, len(m0))
	copy(modules, m0)
	modules = append(modules, "eth")     // Thunder doesn't use the "shh" (whisper) protocol
	modules = append(modules, "thunder") // Be backward compatible with Thunder 0.5
	return modules
}

func NewNodeConfig(cfg NodeConfig) *node.Config {
	// setup ethereum node config.
	nodeCfg := node.DefaultConfig // intentionally do a shallow copy
	nodeCfg.Name = clientIdentifier
	nodeCfg.Version = cfg.Version
	nodeCfg.IPCPath = "thunder2.ipc"
	// disable USB hardware wallet support
	nodeCfg.NoUSB = true
	nodeCfg.DataDir = cfg.DataDir

	defaultHttpCors, defaultHttpVirtualHosts, defaultWsOrigins := DefaultAllowedConfig()
	// Add RPC HTTP config
	nodeCfg.HTTPHost = cfg.RpcListenHostname
	nodeCfg.HTTPPort = int(cfg.RpcListenPort)
	var t []string
	if len(cfg.RpcCorsDomains) == 0 {
		t = defaultHttpCors
	} else {
		t = cfg.RpcCorsDomains
	}
	nodeCfg.HTTPCors = t
	if len(cfg.RpcVirtualHosts) == 0 {
		t = defaultHttpVirtualHosts
	} else {
		t = cfg.RpcVirtualHosts
	}
	nodeCfg.HTTPVirtualHosts = t
	if len(cfg.RpcModules) == 0 {
		nodeCfg.HTTPModules = publicRpcModules()
	} else {
		nodeCfg.HTTPModules = cfg.RpcModules
	}

	// Add RPC WS config
	nodeCfg.WSHost = cfg.WsListenHostname
	nodeCfg.WSPort = int(cfg.WsListenPort)
	if len(cfg.WsOrigins) == 0 {
		t = defaultWsOrigins
	} else {
		t = cfg.WsOrigins
	}
	nodeCfg.WSOrigins = t
	if len(cfg.WsRpcModules) == 0 {
		nodeCfg.WSModules = publicRpcModules()
	} else {
		nodeCfg.WSModules = cfg.WsRpcModules
	}

	// disable p2p
	nodeCfg.P2P.ListenAddr = ""
	nodeCfg.P2P.NoDial = true

	return &nodeCfg
}

func GetBlockChainAndDb(dataDir string) (*core.BlockChain, ethdb.Database, error) {
	ethCfg := NewEthConfig(*readEthConfig())

	dbPath := filepath.Join(dataDir, "thunder", "chaindata")
	db, err := rawdb.NewLevelDBDatabase(dbPath, ethCfg.DatabaseCache, ethCfg.DatabaseHandles, "", false)
	if err != nil {
		return nil, nil, err
	}
	chainCfg, _, err := core.SetupGenesisBlockWithOverride(db, ethCfg.Genesis, nil)
	if err != nil {
		return nil, nil, err
	}

	engine := thunder.New(ethCfg.Genesis.Config.Thunder)

	chain, err := core.NewBlockChain(db, &core.CacheConfig{TrieDirtyDisabled: true}, chainCfg, engine, vm.Config{}, nil, nil)
	if err != nil {
		return nil, nil, err
	}

	return chain, db, err
}

func StartNode(nConfig *NodeConfig, eConfig *EthConfig) (*eth.Ethereum, error) {
	// NOTE: must call SetChainId before `NewEthConfig` and all other callers of
	// `ThunderChainConfig().ChainID`
	// See TODO in `chainconfig/config.go`
	if eConfig.ChainId == 0 {
		eConfig.ChainId = chainconfig.TestnetChainID
	}
	chainconfig.SetChainId(eConfig.ChainId)

	// Prepare and start Ethereum backend.
	nodeConfig := NewNodeConfig(*nConfig)
	ethConfig := NewEthConfig(*eConfig)

	n, err := node.New(nodeConfig)
	if err != nil {
		debug.Fatal("Failed to create the protocol stack: %v", err)
	}
	ethConfig.Upgrader = blockchain.Upgrade

	ethBackend, err := eth.New(n, ethConfig)
	if err != nil {
		errstr := fmt.Sprintf("Failed to make ethereum node: %s", err)
		logger.Error(errstr)
		return nil, err
	}

	logger.Info("StartNode: RpcModules: %#v, WsRpcModules: %#v",
		nodeConfig.HTTPModules, nodeConfig.WSModules)
	if err = n.Start(); err != nil {
		return nil, xerrors.Errorf("Node.Start(): %w", err)
	}

	return ethBackend, nil
}

type PalaNode struct {
	nodeConfig *node.Config
	ethConfig  *eth.Config
	config     *Config

	mutex           sync.Mutex
	stopped         bool
	node            *node.Node
	ethWithMediator *EthWithMediator
	sig             chan os.Signal
}

func (pala *PalaNode) Start() error {
	pala.mutex.Lock()
	defer pala.mutex.Unlock()

	// Prepare and start Ethereum backend.
	logger.Info("NewNode: RpcModules: %#v, WsRpcModules: %#v",
		pala.nodeConfig.HTTPModules, pala.nodeConfig.WSModules)

	n, err := node.New(pala.nodeConfig)
	if err != nil {
		debug.Fatal("Failed to create the protocol stack: %v", err)
	}

	ethBackend, err := eth.New(n, pala.ethConfig)
	if err != nil {
		errstr := fmt.Sprintf("Failed to make ethereum node: %s", err)
		logger.Error(errstr)
		return err
	}

	em, err := WithPalaMediator(ethBackend, n, pala.config)
	if err != nil {
		return err
	}
	n.RegisterLifecycle(em)

	logger.Info("StartNode: HTTPEndpoint: %s, IPCEndpoint: %s, WSEndpoint: %s",
		n.HTTPEndpoint(), n.IPCEndpoint(), n.WSEndpoint())
	if err := n.Start(); err != nil {
		return err
	}

	pala.node = n
	pala.ethWithMediator = em
	pala.sig = consensus.RegisterSignalHandlers(
		consensus.NewDumpDebugStateHandler(pala),
		consensus.NewStopHandler(pala),
	)
	pala.stopped = false

	return nil
}

func (pala *PalaNode) Stop() error {
	pala.mutex.Lock()
	defer pala.mutex.Unlock()

	if pala.stopped {
		return nil
	}

	if err := pala.node.Close(); err != nil {
		return err
	}
	pala.node.Wait()

	pala.ethWithMediator = nil
	pala.node = nil
	pala.stopped = true

	return nil
}

func (pala *PalaNode) Signal() chan os.Signal {
	return pala.sig
}

func (pala *PalaNode) Backend() *EthWithMediator {
	if pala.ethWithMediator == nil {
		debug.Fatal("pala node is not running")
	}
	return pala.ethWithMediator
}

func (pala *PalaNode) Wait() {
	pala.Mediator().Wait()
}

func (pala *PalaNode) Node() *node.Node {
	return pala.node
}

func (pala *PalaNode) Mediator() *consensus.Mediator {
	return pala.Backend().mediator
}

func (pala *PalaNode) Bidder() *bidder.Bidder {
	return pala.Backend().bidder
}

func (pala *PalaNode) GetDebugState() <-chan consensus.DebugState {
	return pala.Backend().mediator.GetDebugState()
}

// EthWithMediator implements `Node.Service` interface
type EthWithMediator struct {
	mediator   *consensus.Mediator
	bidder     *bidder.Bidder
	ethBackend *eth.Ethereum
	node       *node.Node
}

func (em *EthWithMediator) Protocols() []p2p.Protocol {
	return em.ethBackend.Protocols()
}

func (em *EthWithMediator) APIs() []rpc.API {
	// TODO (thunder): move rpcDelegate out here
	return em.ethBackend.APIs()
}

func (em *EthWithMediator) Start() error {
	if err := em.ethBackend.Start(); err != nil {
		return err
	}
	return em.mediator.Start()
}

func (em *EthWithMediator) Stop() error {
	if err := em.mediator.StopAndWait(); err != nil {
		return err
	}

	return nil
}

// WithPalaMediator
func WithPalaMediator(e *eth.Ethereum, node consensus.RpcSwitch, config *Config) (*EthWithMediator, error) {
	config.ServiceConfig = ServiceConfig{
		EthChain:  e.BlockChain(),
		EthDb:     e.ChainDb(),
		TxPool:    e.TxPool(),
		RpcSwitch: node,
	}
	m, b, err := NewMediatorAndDependency(config)
	if err != nil {
		return nil, err
	}
	return &EthWithMediator{
		mediator:   m,
		bidder:     b,
		ethBackend: e,
	}, nil
}

func NewPalaNode(nConfig *NodeConfig, eConfig *EthConfig, config *Config) *PalaNode {
	// NOTE: must call SetChainId before `NewEthConfig` and all other callers of
	// `ThunderChainConfig().ChainID`
	// See TODO in `chainconfig/config.go`
	if eConfig.ChainId == 0 {
		eConfig.ChainId = chainconfig.TestnetChainID
	}
	chainconfig.SetChainId(eConfig.ChainId)
	ethConfig := NewEthConfig(*eConfig)
	ethConfig.Upgrader = blockchain.Upgrade

	return &PalaNode{
		nodeConfig: NewNodeConfig(*nConfig),
		ethConfig:  ethConfig,
		config:     config,
	}
}

// setEthConfig applies eth-related command line flags to the config.
func NewEthConfig(cfg EthConfig) *eth.Config {
	ethCfg := &ethconfig.Defaults
	// COPY from common.go
	cacheInMb := cfg.CacheInMb
	dbCachePercent := cfg.DbCachePercent
	trieCachePercent := cfg.TrieCachePercent
	fdLimit := cfg.FdLimit

	// setEtherbase
	ethCfg.Miner.Etherbase = common.Address{}

	ethCfg.DatabaseCache = int(cacheInMb*dbCachePercent) / 100
	ethCfg.DatabaseHandles = int(fdLimit)
	ethCfg.NoPruning = cfg.NoPruning

	ethCfg.TrieCleanCache = int(cacheInMb*trieCachePercent) / 100
	ethCfg.TrieDirtyCache = int(cacheInMb*trieCachePercent) / 100
	ethCfg.NoPrefetch = true
	ethCfg.SnapshotCache = int(cfg.SnapshotCache)
	ethCfg.DatabaseHistory = cfg.HistoryOrderList

	// Override any default configs for hard coded networks.
	ethCfg.NetworkId = params.ThunderChainConfig().ChainID.Uint64()
	if len(cfg.GenesisPath) > 0 {
		ethCfg.Genesis = core.GetGenesisFromConfig(cfg.GenesisPath)
	} else {
		ethCfg.Genesis = core.DefaultThunderGenesisBlock()
	}
	ethCfg.Genesis.Config.Thunder = blockchain.NewThunderConfig(cfg.HardforkCfg)

	ethCfg.TxPool = cfg.TxPool

	ethCfg.SyncMode = downloader.FullSync
	ethCfg.RPCTxFeeCap = 0

	ethCfg.MaxRpcLogsBlockRange = cfg.MaxRpcLogsBlockRange
	ethCfg.TxLookupLimit = uint64(cfg.TxLookupLimit)

	return ethCfg
}

func serveMetrics(addr string, roleAssigner consensus.RoleAssigner, e blockchain.EpochManager, pm metrics.PalaMetrics) {
	// Create a new HTTP multiplexer
	if len(addr) == 0 {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		roles := consensus.GetRoles(roleAssigner, e)
		filter := pm.GetInvMetricsFilter(roles)
		res, err := oldMetrics.GetPrometheusMetricsAsTextWithFilter(filter)
		if err != nil {
			// Return error itself as the result.
			res = fmt.Sprint(err)
		}
		fmt.Fprint(w, res)
	})
	go func() {
		err := http.ListenAndServe(addr, mux)
		if err != nil {
			debug.Fatal(fmt.Sprintf("Error when starting metrics server: %v", err))
		}
	}()
}

func ScientificBigIntParse(s string) *big.Int {
	v, err := configreader.SimpleScientificBigIntParse(s)
	if err != nil {
		debug.Fatal("%s", err)
	}
	return v
}
