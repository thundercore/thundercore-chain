package server

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/bidder"
	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/consensus"
	"github.com/ethereum/go-ethereum/thunder/pala/limiter"
	"github.com/ethereum/go-ethereum/thunder/pala/metrics"
	"github.com/ethereum/go-ethereum/thunder/pala/network"
	"github.com/ethereum/go-ethereum/thunder/pala/server/internal/configreader"
	c "github.com/ethereum/go-ethereum/thunder/pala/server/internal/configvars"
	"github.com/ethereum/go-ethereum/thunder/pala/txservice"

	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/keymanager"
	"github.com/ethereum/go-ethereum/thunder/thunderella/thundervm"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"golang.org/x/xerrors"
)

var (
	electionStopBlockSessionOffset = config.NewInt64HardforkConfig(
		"election.stopBlockSessionOffset",
		"The number of blocks that include transactions in one session.",
	)

	palaHardfork = config.NewBoolHardforkConfig(
		"pala.hardfork",
		"The number of block we start run with pala protocol.",
	)

	proposerList = config.NewStringHardforkConfig(
		"committee.proposerList",
		"The name of proposer list we choose to use",
	)

	maxCodeSize = config.NewInt64HardforkConfig(
		"protocol.maxCodeSize",
		"Maximum code size of a contract.",
	)

	gasTable = config.NewStringHardforkConfig(
		"protocol.gasTable",
		"The gas table we choose to use",
	)

	rewardScheme = config.NewStringHardforkConfig(
		"committee.rewardScheme",
		"The scheme of reward dispatch hardfork.",
	)

	vaultGasUnlimited = config.NewBoolHardforkConfig(
		"committee.vaultGasUnlimited",
		"True if we don't limit the gas when vault calling other contract.",
	)

	evmHardforkVersion = config.NewStringHardforkConfig(
		"evm.version",
		"EVM hardfork version.",
	)

	isConsensusInfoInHeader = config.NewBoolHardforkConfig(
		"consensus.infoInHeader",
		"True if we store consensus info in Extra field of block header.",
	)

	rngVersion = config.NewStringHardforkConfig(
		"trustedRNG.version",
		"True if we use more unpredictable RNG",
	)

	protocolBaseFee = config.NewBigIntHardforkConfig(
		"protocol.baseFee", "protocol basefee",
	)

	protocalInflation = config.NewBigIntHardforkConfig(
		"protocol.inflation", "protocal token inflation",
	)

	committeeRewardRatio = config.NewInt64HardforkConfig(
		"committee.rewardRatio", "ratio of committee reward share",
	)

	tpcRevertDelegateCall = config.NewBoolHardforkConfig(
		"precompiled.revertDelegateCall",
		"revert delegatecall when calling precompiled contract",
	)
)

func newKeyManager(keyStoreType, keyStorePath, awsRegion string) *keymanager.KeyManager {
	if strings.ToLower(keyStoreType) == "aws" {
		awsCfg := keymanager.AWSKeystoreConfig{
			Config: keymanager.Config{},
		}
		return keymanager.NewKeyManager(
			awsCfg.Config, keymanager.NewAWSKeystore(awsCfg, awsRegion))
	}

	fsCfg := keymanager.FsKeystoreConfig{
		Config: keymanager.Config{
			MustEncryptPrivateKeys: false,
		},
		DirPath: keyStorePath,
	}
	return keymanager.NewKeyManager(fsCfg.Config, keymanager.NewFsKeystore(fsCfg))
}

func ReadConfigFiles(configPath string) (configreader.AllKeysGetStringer, error) {
	// TODO: must remove it in the future
	// dirty solution
	bidder.ConfigPath = configPath
	return c.Reader.Read(configPath)
}

func SetupRotatingLogging() error {
	if err := SetupEthLogging(c.EthLogFile.Get(), c.EthLogFilter.Get()); err != nil {
		return err
	}
	return SetupLogging(RotatingLogOutputMode, c.LogFile.Get(), c.VerboseLogFile.Get())
}

func bootnodeAddressesConvert(idToAddr map[string]string) map[ConsensusId]string {
	out := make(map[ConsensusId]string)
	for id, addr := range idToAddr {
		out[ConsensusId(id)] = addr
	}
	return out
}

func StartPprofServer() {
	if !c.EnableProfiling.Get() {
		return
	}
	// this is to enable pprof/block, we need this get Goroutine
	// blocking info, the golang default setup is to disable it */
	runtime.SetBlockProfileRate(1)
	runtime.SetMutexProfileFraction(1)

	go func() {
		pprofAddr := fmt.Sprintf(":%d", c.ProfilingPort.Get())
		log.Fatal(http.ListenAndServe(pprofAddr, nil))
	}()
}

func DataDirFromConfig() string {
	return c.DataDirFromConfig.Get()
}

func genesisCommInfo(keyManager *keymanager.KeyManager) (*committee.CommInfo, error) {
	genesisCommInfo, err := blockchain.NewGenesisCommInfo(blockchain.GenesisConfig{
		GenesisCommPath: c.GenesisCommPath.Get(),
	})
	return genesisCommInfo, err
}

func alterCommInfo() (map[string]*committee.CommInfo, error) {
	path := c.AlterCommInfo.Get()
	var cInfos []*committee.CommInfo
	ret := make(map[string]*committee.CommInfo)

	if len(path) == 0 {
		log.Printf("key.AlterCommPath not provided, skipping")
		return ret, nil
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, xerrors.Errorf("failed to read JSON file %q: %w", path, err)
	}

	if err := json.Unmarshal(data, &cInfos); err != nil {
		return nil, xerrors.Errorf("json.Unmarshal failed: %w", err)
	}

	for _, cInfo := range cInfos {
		ret[cInfo.Name] = cInfo
	}

	return ret, nil
}

func ReadConfig() (*Config, error) {
	keyManager := newKeyManager(c.KeyStoreType.Get(), c.KeyStorePath.Get(), c.AwsRegion.Get())
	genesisCommInfo, err := genesisCommInfo(keyManager)
	if err != nil {
		return nil, err
	}

	alterInfo, err := alterCommInfo()
	if err != nil {
		return nil, err
	}

	hardforkCfg := &blockchain.HardforkCfg{
		PalaBlock:               new(big.Int).SetUint64(uint64(palaHardfork.GetEnabledBlockNum())),
		VerifyBidSession:        blockchain.Session(thundervm.VerifyBid.GetEnabledSession()),
		ElectionStopBlockOffset: electionStopBlockSessionOffset,
		ProposerListName:        proposerList,
		MaxCodeSize:             maxCodeSize,
		GasTable:                gasTable,
		EVMHardforkVersion:      evmHardforkVersion,
	}
	cfg := &Config{
		LoggingId:    c.LoggingId.Get(),
		LogDir:       path.Dir(c.LogFile.Get()),
		GcMode:       "archive",
		TimePerBlock: c.TimePerBlock.Get(),
		KeyConfig: KeyConfig{
			KeyManager:     keyManager,
			ProposingKeyId: c.ProposingKeyId.Get(),
			VotingKeyId:    c.VotingKeyId.Get(),
			StakeInKeyId:   c.StakeInKeyId.Get(),
		},
		IsFullNode:                     c.IsFullNode.Get(),
		IsVoter:                        c.IsVoter.Get(),
		IsProposer:                     c.IsProposer.Get(),
		ProposerHostPort:               c.ProposerIpPort.Get(),
		BootnodeListenPort:             c.BootnodeListenPort.Get(),
		BootnodesOwnPublicAddress:      c.BootnodesOwnPublicAddress.Get(),
		AddressesOfBootnodesITrust:     c.AddressesOfBootnodesITrust.Get(),
		IdsOfTxRouting:                 c.IdsOfTxRouting.Get(),
		MetricsAddr:                    c.MetricsAddr.Get(),
		ResourceMonitorEnable:          c.ResourceMonitorEnable.Get(),
		ResourceMonitorInterval:        c.ResourceMonitorInterval.Get(),
		K:                              params.MaxUnnotarizedProposals,
		DelayOfMakingFirstProposal:     c.DelayOfMakingFirstProposal.Get(),
		VoterWaitingTimeBeforeClockMsg: c.VoterWaitingTimeBeforeClockMsg.Get(),
		GenesisCommInfo:                genesisCommInfo,
		AlterCommInfo:                  alterInfo,
		PalaFromGenesis:                c.PalaFromGenesis.Get(),
		TracerCacheSize:                c.TracerCacheSize.Get(),
		BidderConfig: bidder.BidderCfg{
			LoggingId:              c.LoggingId.Get(),
			Url:                    c.BidderRpcUrl.Get(),
			PrepareClientFunc:      bidder.PrepareClientFunc,
			ThunderConfig:          blockchain.NewThunderConfig(hardforkCfg),
			Stake:                  c.BidAmount.Get(),
			RewardAddress:          c.RewardAddress.Get(),
			GasBidPrice:            c.GasBidPrice.Get(),
			BidTxGasPrice:          c.BidTxGasPrice.Get(),
			BidTxPriceBump:         c.BidTxPriceBump.Get(),
			BidTxPriceMax:          c.BidTxPriceMax.Get(),
			BidAddress:             c.BidAddress.Get(),
			RetryInterval:          c.RetryInterval.Get(),
			BlockInterval:          c.TimePerBlock.Get(),
			EnableDynamicBidAmount: c.BidderDynamicBidAmount.Get(),
			EnableBiddingByDefault: false,
		},

		ElectionStopBlockSessionOffset: electionStopBlockSessionOffset,

		RpcMaxDelayBlock: c.RpcMaxDelayBlock.Get(),
		RpcSuspendBuffer: c.RpcSuspendBuffer.Get(),

		// Throttling
		NetworkThrottlingConfig: network.ThrottlingConfig{
			TotalReadBytesThresholdPerSecond: uint(c.NetworkMessageTotalSizeLimitPerSecond.Get()),
			ReadBytesPerSecond:               uint(c.NetworkMessageSizeLimitPerSecond.Get()),
			MessageCountPerSecond:            uint(c.NetworkMessageCountLimitPerSecond.Get()),
		},
		ChainSyncLimitConfig: []limiter.MsgLimitConfig{
			limiter.MsgLimitConfig{
				MsgId:  limiter.MsgId(consensus.MessageGetFresherHead.String()),
				Limit:  c.ChainSyncRequestLimitPerSecond.Get(),
				Window: time.Second,
			},
			limiter.MsgLimitConfig{
				MsgId:  limiter.MsgId(consensus.MessageGetFresherHeadV2.String()),
				Limit:  c.ChainSyncRequestLimitPerSecond.Get(),
				Window: time.Second,
			},
		},
		TxServiceLimitConfig: []limiter.MsgLimitConfig{
			limiter.MsgLimitConfig{
				MsgId:  limiter.MsgId(strconv.Itoa(int(txservice.MessageTxDistribute))),
				Limit:  c.TxDistributionMessageLimitPerSecond.Get(),
				Window: time.Second,
			},
			// Debug messages are not used frequently. A number slightly larger than the number of proposers is enough.
			limiter.MsgLimitConfig{
				MsgId:  limiter.MsgId(strconv.Itoa(int(txservice.MessageTxTraceRoutes))),
				Limit:  50,
				Window: time.Second,
			},
			// Debug messages are not used frequently. A number slightly larger than the number of proposers is enough.
			limiter.MsgLimitConfig{
				MsgId:  limiter.MsgId(strconv.Itoa(int(txservice.MessageTxTraceRoutesReply))),
				Limit:  50,
				Window: time.Second,
			},
		},
	}

	return cfg, nil
}

func readEthConfig() *EthConfig {
	hardforkCfg := &blockchain.HardforkCfg{
		PalaBlock:               new(big.Int).SetUint64(uint64(palaHardfork.GetEnabledBlockNum())),
		VerifyBidSession:        blockchain.Session(thundervm.VerifyBid.GetEnabledSession()),
		ElectionStopBlockOffset: electionStopBlockSessionOffset,
		ProposerListName:        proposerList,
		MaxCodeSize:             maxCodeSize,
		GasTable:                gasTable,
		RewardScheme:            rewardScheme,
		VaultGasUnlimited:       vaultGasUnlimited,
		EVMHardforkVersion:      evmHardforkVersion,
		IsConsensusInfoInHeader: isConsensusInfoInHeader,
		RNGVersion:              rngVersion,
		BaseFee:                 protocolBaseFee,
		TokenInflation:          protocalInflation,
		CommitteeRewardRatio:    committeeRewardRatio,
		TPCRevertDelegateCall:   tpcRevertDelegateCall,
	}

	return &EthConfig{
		NoPruning:   true, // GcMode == "archive"
		GenesisPath: c.GenesisPath.Get(),
		HardforkCfg: hardforkCfg,

		TxPool: core.TxPoolConfig{
			NoLocals: true,
			//Journal:   "transactions.rlp",
			// This is not used when NoLocals is true, but TxPool requires a non-zero value.
			Rejournal: 365 * 24 * time.Hour,

			PriceLimit:       uint64(c.PriceLimit.Get()),
			PriceBump:        10,
			AccountSlots:     uint64(c.AccountSlots.Get()),
			GlobalSlots:      uint64(c.GlobalSlots.Get()),
			AccountQueue:     uint64(c.AccountQueue.Get()),
			GlobalQueue:      uint64(c.GlobalQueue.Get()),
			Lifetime:         c.QueueLifetime.Get(),
			EvictionInterval: c.EvictionInterval.Get(),
		},
		ChainId:              c.ChainId.Get(),
		CacheInMb:            c.CacheInMb.Get(),
		DbCachePercent:       c.DbCachePercent.Get(),
		TrieCachePercent:     c.TrieCachePercent.Get(),
		FdLimit:              c.FdLimit.Get(),
		SnapshotCache:        c.SnapshotCache.Get(),
		HistoryOrderList:     c.HistoryOrderList.Get(),
		MaxRpcLogsBlockRange: c.MaxRpcLogsBlockRange.Get(),
		TxLookupLimit:        c.TxLookupLimit.Get(),
	}
}

func readNodeConfig(version, dataDir string) *NodeConfig {
	if c.LogRpcRequests.Get() {
		rpc.ThunderLogRequest = true
	}
	blockchain.InitialSupply = c.InitialSupply.Get()

	return &NodeConfig{
		Version:           version,
		DataDir:           dataDir,
		RpcListenHostname: c.RpcListenHostname.Get(),
		RpcListenPort:     c.RpcListenPort.Get(),
		RpcCorsDomains:    c.RpcCorsDomains.Get(),
		RpcVirtualHosts:   c.RpcVirtualHosts.Get(),
		RpcModules:        c.RpcModules.Get(),
		WsListenHostname:  c.WsListenHostname.Get(),
		WsListenPort:      c.WsListenPort.Get(),
		WsOrigins:         c.WsOrigins.Get(),
		WsRpcModules:      c.WsRpcModules.Get(),
	}
}

func NewPalaNodeFromConfig(version, dataDir string) (*PalaNode, error) {
	nodeConfig := readNodeConfig(version, dataDir)
	ethConfig := readEthConfig()

	cfg, err := ReadConfig()
	if err != nil {
		return nil, err
	}

	return NewPalaNode(nodeConfig, ethConfig, cfg), nil
}

func NewPalaChainFromConfig(version, dataDir string) (blockchain.BlockChain, *eth.Ethereum, error) {
	nodeConfig := readNodeConfig(version, dataDir)
	ethConfig := readEthConfig()

	ethBackend, err := StartNode(nodeConfig, ethConfig)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		// Stop eth backend if any error happened
		if err != nil {
			ethBackend.Stop()
		}
	}()

	cfg, err := ReadConfig()
	if err != nil {
		return nil, nil, err
	}

	cfg.ServiceConfig = ServiceConfig{
		EthChain: ethBackend.BlockChain(),
		EthDb:    ethBackend.ChainDb(),
		TxPool:   ethBackend.TxPool(),
	}

	me := metrics.NewPalaMetrics("", !utils.InTest())
	bc, err := newBlockChain(cfg, me)
	if err != nil {
		return nil, nil, err
	}

	return bc, ethBackend, nil
}
