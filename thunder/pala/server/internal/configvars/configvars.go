package configvars

import (
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/server/internal/configreader"
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chainconfig"

	"github.com/ethereum/go-ethereum/node"
)

type Config = configreader.Config

var r = configreader.New()
var Reader = r

var (
	DataDirFromConfig = r.NewString(Config{
		Key:         "dataDir",
		Description: "Data dir",
	})

	MasterCertPath = r.NewString(Config{
		Key:         "key.masterCert",
		Description: "Master certifcate path",
	})

	KeyStorePath = r.NewString(Config{
		Key:         "key.KeyStorePath",
		Description: "Key store path when using fs type",
	})

	LogFile = r.NewString(Config{
		Key:         "logFile",
		Description: "Log file(s) path",
		Default:     "thunder.log",
	})

	VerboseLogFile = r.NewString(Config{
		Key:         "verboseLogFile",
		Description: "Log verbose file(s) path",
		Default:     "thunder.verbose.log",
	})

	EthLogFile = r.NewString(Config{
		Key:         "eth.logFile",
		Description: "eth log file",
		Default:     "thunder.eth.log",
	})

	EthLogFilter = r.NewString(Config{
		Key:         "eth.logFilter",
		Description: "enable logging eth metrics. (trie=4,core=2)",
		Default:     "",
	})

	LoggingId = r.NewString(Config{
		Key:         "loggingId",
		Description: "Logging id",
		Default:     "unknown",
	})

	IsFullNode = r.NewBool(Config{
		Key:         "pala.isFullNode",
		Description: "Fullnodes respond to external JSON-RPC requests.",
	})

	IsVoter = r.NewBool(Config{
		Key:         "pala.isVoter",
		Description: "Voters have votekey to vote for accepted proposals and stakingkey to bid for next round",
	})

	IsProposer = r.NewBool(Config{
		Key:         "pala.isProposer",
		Description: "Proposer have propkey to gen a proposals and a notarizations",
	})

	AddressesOfBootnodesITrust = r.NewStringSlice(Config{
		Key:         "pala.bootnode.trusted",
		Description: "Addresses of bootnodes trusted by this node",
	})

	IdsOfTxRouting = r.NewStringSlice(Config{
		Key:         "pala.txservice.routing",
		Description: "Addresses of ids (Can be bootnode addresses or Consensus Id)",
	})

	BootnodeListenPort = r.NewInt(Config{
		Key:         "pala.bootnode.port",
		Description: "Port number on which to start the Thunder wire protocol for the bootnode",
	})
	BootnodesOwnPublicAddress = r.NewString(Config{
		Key:         "pala.bootnode.ownPublicAddress",
		Description: "The public address of this bootnode. Used by the bootnode to avoid connecting to itself",
	})

	RpcMaxDelayBlock = r.NewInt(Config{
		Key:         "rpc.maxDelayBlock",
		Description: "Max tolerance of block delay",
		Default:     60,
	})

	RpcSuspendBuffer = r.NewDuration(Config{
		Key:         "rpc.suspendBuffer",
		Description: "Buffer Ns before suspend node rpc",
		Default:     30 * time.Second,
	})

	RpcListenHostname = r.NewString(Config{
		Key:         "rpc.http.hostname",
		Description: "Host interface on which to start the HTTP RPC server",
		Default:     node.DefaultHTTPHost,
	})

	RpcListenPort = r.NewInt(Config{
		Key:         "rpc.http.port",
		Description: "Port number on which to start the HTTP RPC server",
		Default:     node.DefaultHTTPPort,
	})

	RpcCorsDomains = r.NewStringSlice(Config{
		Key:         "rpc.http.cors",
		Description: "Cross-Origin Resource Sharing header to send to requesting clients",
	})

	RpcVirtualHosts = r.NewStringSlice(Config{
		Key:         "rpc.http.virtualHosts",
		Description: "List of virtual hostnames which are allowed on incoming requests",
	})

	RpcModules = r.NewStringSlice(Config{
		Key:         "rpc.http.modules",
		Description: "List of API modules to expose via the HTTP RPC interface. An empty list would cause all public APIs to be exposed",
	})

	WsListenHostname = r.NewString(Config{
		Key:         "rpc.ws.hostname",
		Description: "Host interface on which to start the websocket RPC server",
		Default:     node.DefaultWSHost,
	})

	WsListenPort = r.NewInt(Config{
		Key:         "rpc.ws.port",
		Description: "Port number on which to start the websocket RPC server",
		Default:     node.DefaultWSPort,
	})

	WsOrigins = r.NewStringSlice(Config{
		Key:         "rpc.ws.origins",
		Description: "List of domains to accept websocket requests from",
	})

	WsRpcModules = r.NewStringSlice(Config{
		Key:         "rpc.ws.modules",
		Description: "List of API modules to expose via the websocket RPC interface. An empty list would cause all public APIs to be exposed",
	})

	MetricsAddr = r.NewString(Config{
		Key:         "metrics.address",
		Description: "ip:port to expose Prometheus metrics",
		Default:     "0.0.0.0:9201",
	})

	EnableProfiling = r.NewBool(Config{
		Key:         "profiling.enable",
		Description: "enable net/http/pprof",
		Default:     true,
	})

	ProfilingPort = r.NewInt(Config{
		Key:         "profiling.port",
		Description: "port number for net/http/pprof",
		Default:     9999,
	})

	ResourceMonitorEnable = r.NewBool(Config{
		Key:         "resourceMonitor.enable",
		Description: "enable runtime resource monitor",
	})

	ResourceMonitorInterval = r.NewDuration(Config{
		Key:         "resourceMonitor.interval",
		Description: "set runtime resource monitor interval",
		Default:     10 * time.Second,
	})

	TimePerBlock = r.NewDuration(Config{
		Key:         "accel.blockmaker.TimePerBlock",
		Description: "min/target time per block",
		Default:     time.Second,
	})

	/* we only support "archive" mode for now
	GcMode = r.NewString(Config{
		Key:         "triecache.gcMode",
		Description: "gcmode suggest: archive",
		Default:     "archive",
	}) */
	DelayOfMakingFirstProposal = r.NewDuration(Config{
		Key:         "pala.delayOfMakingFirstProposal",
		Description: "The delay in millisecond we wait for reconfiguration done.",
		Default:     1000 * time.Millisecond,
	})

	VoterWaitingTimeBeforeClockMsg = r.NewDuration(Config{
		Key:         "pala.voterWaitingTimeBeforeClockMsg",
		Description: "Voter consider timeout after this much of time.",
		Default:     6000 * time.Millisecond,
	})

	GenesisCommPath = r.NewString(Config{
		Key:         "key.GenesisCommPath",
		Description: "path for genesis comm info",
	})

	AlterCommInfo = r.NewString(Config{
		Key:         "key.AlterCommPath",
		Description: "path for after comm info",
	})

	KeyStoreType = r.NewString(Config{
		Key:         "key.StoreType",
		Description: "Type of key store: either `aws` or `fs` (default)",
		Default:     "fs",
	})

	ProposingKeyId = r.NewString(Config{
		Key:         "key.ProposingKeyId",
		Description: "proposing key id (when using AWS keystore)",
	})

	VotingKeyId = r.NewString(Config{
		Key:         "key.VotingKeyId",
		Description: "voting key id (when using AWS keystore)",
	})

	StakeInKeyId = r.NewString(Config{
		Key:         "key.StakeInKeyId",
		Description: "stake-in key id (when using AWS keystore)",
	})

	AwsRegion = r.NewString(Config{
		Key:         "key.awsRegion",
		Description: "AWS region (when using AWS keystore)",
		Default:     "us-west-2",
	})

	PalaFromGenesis = r.NewBool(Config{
		Key:         "pala.fromGenesis",
		Description: "run pala from genesis",
	})

	GenesisPath = r.NewString(Config{
		Key:         "chain.genesis",
		Description: "genesis config file path",
	})

	ChainId = r.NewInt(Config{
		Key:         "chain.chainID",
		Description: "the Ethereum chainId to use, i.e. what the `net_version` RPC-call would return",
	})

	CacheInMb = r.NewInt(Config{
		Key:         "chain.cacheInMb",
		Description: "megabytes of memory allocated to internal caching. (default: 1024)",
		Default:     1024,
	})

	DbCachePercent = r.NewInt(Config{
		Key:         "chain.dbCachePercent",
		Description: "percentage of cache memory allowance to use for database io. (default: 75)",
		Default:     75,
	})

	TrieCachePercent = r.NewInt(Config{
		Key:         "chain.trieCachePercent",
		Description: "percentage of cache memory allowance to use for trie pruning. (default: 25)",
		Default:     25,
	})

	FdLimit = r.NewInt(Config{
		Key:         "chain.fdLimit",
		Description: "open fd limitation. (default: 4096)",
		Default:     4096,
	})

	SnapshotCache = r.NewInt(Config{
		Key:         "chain.snapshotCache",
		Description: "state snapshot cache size. (disable: 0, ethereum: 128)",
		Default:     0,
	})

	HistoryOrderList = r.NewStringSlice(Config{
		Key:         "dataDirHistory",
		Description: "Data directory order list for history stores and path must be full path. (example: /datadir-oldest1)",
	})

	ProposerIpPort = r.NewString(Config{
		Key:         "proposer.bindingIPPort", // nolint:golint
		Description: "address:port on which to start the Thunder wire protocol for the Proposer",
		Default:     ":0",
	})

	ProposerGasPrice = r.NewBigInt(Config{
		Key:         "proposer.gasPrice",
		Description: "proposer gas price",
	})

	BidAddress = r.NewAddress(Config{
		Key:         "bidder.bidaddress",
		Description: "address to send bid to",
		Default:     chainconfig.CommElectionTPCAddress,
	})

	BidAmount = r.NewBigInt(Config{
		Key:         "bidder.amount",
		Description: "amount to stake in",
		Default:     big.NewInt(-1),
	})

	GasBidPrice = r.NewBigInt(Config{
		Key:         "bidder.gasbidprice",
		Description: "gas price to bid",
		Default:     big.NewInt(-1),
	})

	RewardAddress = r.NewAddress(Config{
		Key:         "bidder.rewardaddress",
		Description: "committee member reward address",
	})

	BidTxGasPrice = r.NewBigInt(Config{
		Key:         "bidder.bidtxgasprice",
		Description: "gas price of bid tx; use the price only if the price is larger than \"the clearing price * BidTxPriceBump\"",
	})

	BidTxPriceBump = r.NewInt(Config{
		Key:         "bidder.bidtxpricebump",
		Description: "the multiple of the tx gas clearing price",
	})

	BidTxPriceMax = r.NewBigInt(Config{
		Key:         "bidder.bidtxpricemax",
		Description: "The maximum gas price of bid tx",
	})

	RetryInterval = r.NewDuration(Config{
		Key:         "bidder.retryinterval",
		Description: "time to wait between retrying failed txs",
		Default:     time.Second * 2,
	})

	BidderRpcUrl = r.NewString(Config{
		Key:         "bidder.rpcUrl",
		Description: "eth JSON-RPC over Websocket URL used by bidder",
	})

	BidderDynamicBidAmount = r.NewBool(Config{
		Key:         "bidder.dynamicbidamount",
		Description: "enable dynamic bid amount, and load bid amount from pre-compiled vault contract",
	})

	// Please be mindful about changing these configurations.
	// Reducing these numbers may cause transactions to be dropped.
	// Default values match geth TxPoolConfig defaults and are not appropriate for thunder.
	AccountSlots = r.NewInt(Config{
		Key:         "accel.txpool.AccountSlots",
		Description: "max pending transactions / account when too many txs",
		Default:     1000,
	})

	// FIXME: "accel.txpool." -> "txpool."
	GlobalSlots = r.NewInt(Config{
		Key:         "accel.txpool.GlobalSlots",
		Description: "max pending transactions",
		Default:     10000,
	})

	AccountQueue = r.NewInt(Config{
		Key:         "accel.txpool.AccountQueue",
		Description: "max queued transactions / account",
		Default:     100,
	})

	GlobalQueue = r.NewInt(Config{
		Key:         "accel.txpool.GlobalQueue",
		Description: "max queued transactions",
		Default:     1000,
	})

	QueueLifetime = r.NewDuration(Config{
		Key:         "accel.txpool.Lifetime",
		Description: "max time queued transaction will stay in pool with no heartbeat",
		Default:     time.Hour * 3,
	})

	PriceLimit = r.NewInt(Config{
		Key:         "accel.txpool.PriceLimit",
		Description: "minimum tx price to be accepted in tx pool (wei)",
		Default:     1,
	})

	EvictionInterval = r.NewDuration(Config{
		Key:         "accel.txpool.EvictionInterval",
		Description: "the interval of tx eviction",
		Default:     12 * time.Second,
	})

	// In a normal usage, there are at most 100 tx distribution messages. The number of the rest
	// of messages is lower than 100. Thus, 200 is large enough.
	//
	// 0 means no limitation.
	NetworkMessageCountLimitPerSecond = r.NewInt(Config{
		Key:         "throttling.NetworkMessageCount",
		Description: "maximum number of messages per peer in a second",
		Default:     200,
	})

	// When the total reading bytes exceeds this value, use NetworkMessageSizeLimitPerSecond
	// to limit the traffic per connection.
	//
	// If the value < NetworkMessageSizeLimitPerSecond, use NetworkMessageSizeLimitPerSecond instead.
	NetworkMessageTotalSizeLimitPerSecond = r.NewInt(Config{
		Key:         "throttling.NetworkMessageTotalSize",
		Description: "maximum sum of message payload sizes among all peers in a second",
		Default:     0,
	})

	// Given a 10 Gbps network. Assume there are at most 100 peers, 10 MB/s is a reasonable bound.
	//
	// 0 means no limitation.
	NetworkMessageSizeLimitPerSecond = r.NewInt(Config{
		Key:         "throttling.NetworkMessageSize",
		Description: "maximum sum of message payload sizes per peer in a second",
		Default:     1e7,
	})

	// Set a large limit for now. We need to take tps and our capabilty of processing tx in to consideration.
	TxDistributionMessageLimitPerSecond = r.NewInt(Config{
		Key:         "throttling.TxDistributionMsgCount",
		Description: "maximum number of tx distribution messages per peer in a second",
		Default:     105,
	})

	// Current FindNextBlocks returns nChainSyncExtendedBlocks blocks, which is 10 now.
	// , peer can fetch 10 * limit = 10 * 10 = 100 blocks per second.
	// If we increase the limit here, peers can fetch block faster, but we also need to consider
	// our capability of serving the request, which is related to connected peers num and average
	// block size. We also need to consider the block processing time on peer side. If peers need
	// 10ms to process a block, they can only process 10 block per second, so we probably don't
	// need to allow limit higher than that.
	ChainSyncRequestLimitPerSecond = r.NewInt(Config{
		Key:         "throttling.ChainSyncRequestCount",
		Description: "maximum number of chain sync requests per peer in a second",
		Default:     10,
	})

	LogRpcRequests = r.NewBool(Config{
		Key:         "rpc.logRequests",
		Description: "Log rpc requests",
		Default:     false,
	})

	TracerCacheSize = r.NewInt(Config{
		Key:         "collectors.cacheSize",
		Description: "No matter the tracer is collected in storage or runtime tracer, we cached the maximum traces in storage",
		Default:     512,
	})

	MaxRpcLogsBlockRange = r.NewInt(Config{
		Key:         "rpc.logs.BlockRange",
		Description: "Maximum block range for eth_getLogs RPC",
		Default:     -1,
	})

	TxLookupLimit = r.NewInt(Config{
		Key:         "eth.txLookupLimit",
		Description: "Maximum block number to keep indexing transaction",
		Default:     0,
	})

	InitialSupply = r.NewBigInt(Config{
		Key:         "chain.initialSupply",
		Description: "Set initial supply for rpc query",
		Default:     big.NewInt(0),
	})
)
