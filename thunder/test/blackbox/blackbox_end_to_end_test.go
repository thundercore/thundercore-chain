//go:build !skipe2etest
// +build !skipe2etest

package blackbox

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chain"
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chainconfig"
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/election"
	"github.com/ethereum/go-ethereum/thunder/thunderella/keymanager"
	oTestutils "github.com/ethereum/go-ethereum/thunder/thunderella/testutils"
	"github.com/ethereum/go-ethereum/thunder/thunderella/thundervm"

	"github.com/ethereum/go-ethereum/thunder/pala/bidder"
	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/consensus"
	"github.com/ethereum/go-ethereum/thunder/pala/server"
	"github.com/ethereum/go-ethereum/thunder/pala/testutils"
	"github.com/ethereum/go-ethereum/thunder/test"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/require"
)

const STOP_BLOCK_OFFSET = 7
const UNNOTARIZED_WINDOW = 1
const GAS_TABLE_HARDFORK_SEESSION = 2

// copied from go-ethereum/internal/ethapi/api.go
type ExecutionResult struct {
	Gas         uint64 `json:"gas"`
	Failed      bool   `json:"failed"`
	ReturnValue string `json:"returnValue"`
}

// NOTE: propsers are also voters.
func newKeyManagerAndGenesisCommInfo(req *require.Assertions, proposers, voters int, proposerPorts []int,
) (*keymanager.KeyManager, map[string][]string, *committee.CommInfo, error) {
	// Prepare key IDs
	testKeys, err := blockchain.SetupKeys(voters, proposers)
	req.NoError(err)
	for i, _ := range testKeys.ElectionResult.CommInfo.AccelInfo {
		proposerInfo := &testKeys.ElectionResult.CommInfo.AccelInfo[i]
		proposerInfo.HostPort = fmt.Sprintf("0.0.0.0:%d", proposerPorts[i])
	}

	return testKeys.KeyMgr, testKeys.KeyIds, &testKeys.ElectionResult.CommInfo, nil
}

type IMediatorBuilder interface {
	SetLoggingId(loggingId string) IMediatorBuilder
	SetKeyCfg(keyCfg server.KeyConfig) IMediatorBuilder
	SetDataDir(dataDir string) IMediatorBuilder
	IsFullNode(isFullNode bool) IMediatorBuilder
	IsVoter(isVoter bool) IMediatorBuilder
	IsProposer(isProposer bool) IMediatorBuilder
	SetWsPort(wsPort int) IMediatorBuilder
	SetFullnodeWsPort(fullnodeWsPort int) IMediatorBuilder
	SetBootnodeListenPort(bootnodeListenPort int64) IMediatorBuilder
	SetBootnodesOwnPublicAddress(bootnodesOwnPublicAddress string) IMediatorBuilder
	SetGenesisPath(genesisPath string) IMediatorBuilder
	SetGenesisCommInfo(genesisCommInfo *committee.CommInfo) IMediatorBuilder
	SetAddressesOfBootnodesITrust(addressesOfBootnodesITrust []string) IMediatorBuilder
	SetHardForkCfg(hardforkCfg *blockchain.HardforkCfg) IMediatorBuilder
	SetTimePerBlock(timePerBlock time.Duration) IMediatorBuilder

	// bidder setting
	SetUseDirectBid(useDirectBid bool) IMediatorBuilder
	SetBidAmount(bidAmount *big.Int) IMediatorBuilder
	SetBidRewardAddress(bidRewardAddress common.Address) IMediatorBuilder
	EnableDynamicBidAmount(enableDynamicBidAmount bool) IMediatorBuilder
	Build() *server.PalaNode
}
type mediatorBuilder struct {
	addressesOfBootnodesITrust []string
	genesisCommInfo            *committee.CommInfo
	loggingId                  string
	keyCfg                     server.KeyConfig
	dataDir                    string
	bootnodeListenPort         int64
	bootnodesOwnPublicAddress  string
	isFullNode                 bool
	isVoter                    bool
	isProposer                 bool
	wsPort                     int
	fullnodeWsPort             int
	genesisPath                string
	hardforkCfg                *blockchain.HardforkCfg
	bidAmount                  *big.Int
	bidRewardAddress           common.Address
	useDirectBid               bool
	timePerBlock               time.Duration
	enableDynamicBidAmount     bool
}

func NewMediatorBuilder() *mediatorBuilder {
	return &mediatorBuilder{
		bidAmount:        big.NewInt(-1),
		timePerBlock:     100 * time.Millisecond,
		bidRewardAddress: common.HexToAddress("0x0"),
	}
}

func (mb *mediatorBuilder) SetLoggingId(loggingId string) IMediatorBuilder {
	mb.loggingId = loggingId
	return mb
}

func (mb *mediatorBuilder) SetKeyCfg(keyCfg server.KeyConfig) IMediatorBuilder {
	mb.keyCfg = keyCfg
	return mb
}
func (mb *mediatorBuilder) SetDataDir(dataDir string) IMediatorBuilder {
	mb.dataDir = dataDir
	return mb
}
func (mb *mediatorBuilder) IsFullNode(isFullNode bool) IMediatorBuilder {
	mb.isFullNode = isFullNode
	return mb
}
func (mb *mediatorBuilder) IsVoter(isVoter bool) IMediatorBuilder {
	mb.isVoter = isVoter
	return mb
}
func (mb *mediatorBuilder) IsProposer(isProposer bool) IMediatorBuilder {
	mb.isProposer = isProposer
	return mb
}
func (mb *mediatorBuilder) SetWsPort(wsPort int) IMediatorBuilder {
	mb.wsPort = wsPort
	return mb
}
func (mb *mediatorBuilder) SetFullnodeWsPort(fullnodeWsPort int) IMediatorBuilder {
	mb.fullnodeWsPort = fullnodeWsPort
	return mb
}
func (mb *mediatorBuilder) SetBootnodeListenPort(bootnodeListenPort int64) IMediatorBuilder {
	mb.bootnodeListenPort = bootnodeListenPort
	return mb
}
func (mb *mediatorBuilder) SetBootnodesOwnPublicAddress(bootnodesOwnPublicAddress string) IMediatorBuilder {
	mb.bootnodesOwnPublicAddress = bootnodesOwnPublicAddress
	return mb
}
func (mb *mediatorBuilder) SetGenesisPath(genesisPath string) IMediatorBuilder {
	mb.genesisPath = genesisPath
	return mb
}
func (mb *mediatorBuilder) SetGenesisCommInfo(genesisCommInfo *committee.CommInfo) IMediatorBuilder {
	mb.genesisCommInfo = genesisCommInfo
	return mb
}
func (mb *mediatorBuilder) SetAddressesOfBootnodesITrust(addressesOfBootnodesITrust []string) IMediatorBuilder {
	mb.addressesOfBootnodesITrust = addressesOfBootnodesITrust
	return mb
}
func (mb *mediatorBuilder) SetHardForkCfg(hardforkCfg *blockchain.HardforkCfg) IMediatorBuilder {
	mb.hardforkCfg = hardforkCfg
	return mb
}

func (mb *mediatorBuilder) SetBidAmount(bidAmount *big.Int) IMediatorBuilder {
	mb.bidAmount = bidAmount
	return mb
}
func (mb *mediatorBuilder) SetBidRewardAddress(bidRewardAddress common.Address) IMediatorBuilder {
	mb.bidRewardAddress = bidRewardAddress
	return mb
}

func (mb *mediatorBuilder) SetUseDirectBid(useDirectBid bool) IMediatorBuilder {
	mb.useDirectBid = useDirectBid
	return mb
}

func (mb *mediatorBuilder) SetTimePerBlock(timePerBlock time.Duration) IMediatorBuilder {
	mb.timePerBlock = timePerBlock
	return mb
}

func (mb *mediatorBuilder) EnableDynamicBidAmount(enableDynamicBidAmount bool) IMediatorBuilder {
	mb.enableDynamicBidAmount = enableDynamicBidAmount
	return mb
}

func (mb *mediatorBuilder) Build() *server.PalaNode {
	var bidAddress common.Address
	if mb.useDirectBid {
		bidAddress = chainconfig.CommElectionTPCAddress
	} else {
		bidAddress = chainconfig.VaultTPCAddress
	}

	nConfig := &server.NodeConfig{
		Version: "integration-test-version",
		DataDir: mb.dataDir,

		// Turn off RPC.
		RpcListenHostname: "",
		RpcListenPort:     0,
		RpcCorsDomains:    nil,
		RpcVirtualHosts:   nil,
		WsListenHostname:  "0.0.0.0",
		WsListenPort:      int64(mb.wsPort),
		WsOrigins:         nil,
		WsRpcModules:      append(node.DefaultConfig.WSModules, []string{"eth", "thunder", "debug"}...),
	}
	eConfig := &server.EthConfig{
		NoPruning:   true,
		GenesisPath: mb.genesisPath,
		HardforkCfg: mb.hardforkCfg,
		TxPool: core.TxPoolConfig{
			NoLocals:         false,
			PriceLimit:       1,
			PriceBump:        10,
			AccountSlots:     1000,
			GlobalSlots:      10000,
			AccountQueue:     100,
			GlobalQueue:      1000,
			Lifetime:         time.Hour * 3,
			EvictionInterval: time.Second * 12,
		},
	}
	cfg := &server.Config{
		LoggingId:    mb.loggingId,
		GcMode:       "archive",
		TimePerBlock: mb.timePerBlock,
		KeyConfig:    mb.keyCfg,

		IsFullNode:                 mb.isFullNode,
		BootnodeListenPort:         mb.bootnodeListenPort,
		IsVoter:                    mb.isVoter,
		IsProposer:                 mb.isProposer,
		AddressesOfBootnodesITrust: mb.addressesOfBootnodesITrust,
		BootnodesOwnPublicAddress:  mb.bootnodesOwnPublicAddress,

		K:                              mb.hardforkCfg.K,
		DelayOfMakingFirstProposal:     mb.timePerBlock,
		VoterWaitingTimeBeforeClockMsg: 6 * mb.timePerBlock,
		GenesisCommInfo:                mb.genesisCommInfo,
		PalaFromGenesis:                true,

		BidderConfig: bidder.BidderCfg{
			LoggingId:              mb.loggingId,
			Url:                    fmt.Sprintf("ws://127.0.0.1:%d", mb.fullnodeWsPort),
			PrepareClientFunc:      bidder.PrepareClientFunc,
			ThunderConfig:          blockchain.NewThunderConfig(mb.hardforkCfg),
			BidAddress:             bidAddress,
			Stake:                  mb.bidAmount,
			GasBidPrice:            big.NewInt(-1),
			RewardAddress:          mb.bidRewardAddress,
			BidTxGasPrice:          big.NewInt(-1),
			BidTxPriceMax:          big.NewInt(-1),
			RetryInterval:          2 * mb.timePerBlock,
			BlockInterval:          mb.timePerBlock,
			EnableDynamicBidAmount: mb.enableDynamicBidAmount,
			EnableBiddingByDefault: true,
		},

		// speedup test
		ElectionStopBlockSessionOffset: mb.hardforkCfg.ElectionStopBlockOffset,
	}

	return server.NewPalaNode(nConfig, eConfig, cfg)
}

func writeGenesis(req *require.Assertions, genesis *core.Genesis) string {
	file, err := ioutil.TempFile("", "")
	req.NoError(err)
	path := file.Name()

	b, err := json.MarshalIndent(genesis, "", "\t")
	req.NoError(err)

	err = ioutil.WriteFile(path, b, 0644)
	req.NoError(err)
	return path
}

func getMediators(ps []*server.PalaNode) []*consensus.Mediator {
	ms := []*consensus.Mediator{}
	for _, p := range ps {
		ms = append(ms, p.Mediator())
	}
	return ms
}

func getDefaultHardforkCfg() *blockchain.HardforkCfg {
	// Note: We need K + 2 block to finalized new session. So don't be too small.
	offset := config.NewInt64HardforkConfig("consensus.unused.value", "")
	offset.SetTestValueAt(STOP_BLOCK_OFFSET, chain.Seq(0))
	offset.SetTestValueAtSession(STOP_BLOCK_OFFSET, 0)
	commInfoName := config.NewStringHardforkConfig("consensus.unused.value2", "")
	commInfoName.SetTestValueAtSession("", 0)
	maxCodeSize := config.NewInt64HardforkConfig("consensus.unused.value3", "")
	maxCodeSize.SetTestValueAtSession(40960, 0)
	gasTable := config.NewStringHardforkConfig("consensus.unused.value4", "")
	gasTable.SetTestValueAtSession("", 0)
	gasTable.SetTestValueAtSession("pala-r2.1", GAS_TABLE_HARDFORK_SEESSION)
	rewardScheme := config.NewStringHardforkConfig("consensus.unused.value5", "")
	rewardScheme.SetTestValueAtSession("thunderella", 0)
	vaultGasUnlimitedForTest := config.NewBoolHardforkConfig("consensus.unused.value6", "")
	vaultGasUnlimitedForTest.SetTestValueAtSession(true, 0)
	evmHardforkVersion := config.NewStringHardforkConfig("consensus.unused.value7", "")
	evmHardforkVersion.SetTestValueAtSession("", 0)
	isConsensusInHeaderForTest := config.NewBoolHardforkConfig("consensus.unused.value8", "")
	isConsensusInHeaderForTest.SetTestValueAtSession(false, 0)
	RNGVersionForTest := config.NewStringHardforkConfig("consensus.unused.value9", "")
	RNGVersionForTest.SetTestValueAtSession("v1", 0)
	baseFee := config.NewBigIntHardforkConfig("protocol.basefee.value0", "")
	baseFee.SetTestValueAtSession(common.Big0, 0)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(UNNOTARIZED_WINDOW), 0)

	thundervm.VaultVersion.SetTestValueAtSession("", 0)
	thundervm.VaultVersion.SetTestValueAtSession("r3", 0)

	return &blockchain.HardforkCfg{
		PalaBlock:               common.Big1,
		VerifyBidSession:        1,
		ElectionStopBlockOffset: offset,
		ProposerListName:        commInfoName,
		MaxCodeSize:             maxCodeSize,
		GasTable:                gasTable,
		RewardScheme:            rewardScheme,
		VaultGasUnlimited:       vaultGasUnlimitedForTest,
		EVMHardforkVersion:      evmHardforkVersion,
		IsConsensusInfoInHeader: isConsensusInHeaderForTest,
		RNGVersion:              RNGVersionForTest,
		BaseFee:                 baseFee,
		K:                       hardforkK,
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func setupChain(chainDataDeployer *testutils.ChainDataDeployer, setting nodeSetting) error {
	if setting.IsChainSetuped {
		// run the setup only once in subtests
		return nil
	}
	setting.IsChainSetuped = true
	if !setting.UseGenesis {
		if setting.UseDirectBid {
			return chainDataDeployer.SetupDirectBid()
		} else {
			return chainDataDeployer.SetupVault()
		}
	}
	return nil
}

func makeIds(prefix string, n int) []string {
	var ids []string
	for i := 0; i < n; i++ {
		ids = append(ids, fmt.Sprintf("%s%d", prefix, i))
	}
	return ids
}

type voterSetting struct {
	BidAmount              *big.Int
	RewardAddress          common.Address
	EnableDynamicBidAmount bool
}
type nodeSetting struct {
	IsChainSetuped         bool
	NumProposers           int
	NumVoters              int
	NumBootnodes           int
	NumFullnodes           int
	NumAdditionalVoters    int
	DateDir                string
	UseDirectBid           bool
	UseGenesis             bool
	TimePerBlock           time.Duration
	ChainDataConifg        *testutils.ChainDataConfig
	VoterSetting           []voterSetting
	AdditionalVoterSetting []voterSetting
}

func prepareDefaultNodes(req *require.Assertions, setting nodeSetting) (
	[]*server.PalaNode, []*server.PalaNode, []*server.PalaNode, *testutils.ChainDataDeployer, int) {
	getPorts := func(n int) []int {
		ports := make([]int, n)
		for i := 0; i < n; i++ {
			ports[i] = testutils.NextTestingPort(testutils.TestGroupConsensus)
		}
		return ports
	}
	fullnodeWsPorts := getPorts(setting.NumFullnodes)
	bootnodePorts := getPorts(setting.NumBootnodes)
	proposerPorts := getPorts(setting.NumProposers)
	bootnodeLoggingIds := makeIds("b", setting.NumBootnodes)
	bootnodesITrust := make([]string, 0, setting.NumBootnodes)
	for _, port := range bootnodePorts {
		addr := fmt.Sprintf("localhost:%d", port)
		bootnodesITrust = append(bootnodesITrust, addr)
	}

	for i := len(setting.VoterSetting); i < setting.NumVoters; i++ {
		setting.VoterSetting = append(setting.VoterSetting, voterSetting{
			BidAmount:              big.NewInt(-1),
			RewardAddress:          common.HexToAddress("0x0"),
			EnableDynamicBidAmount: false,
		})
	}
	for i := len(setting.AdditionalVoterSetting); i < setting.NumAdditionalVoters; i++ {
		setting.AdditionalVoterSetting = append(setting.AdditionalVoterSetting, voterSetting{
			BidAmount:              big.NewInt(-1),
			RewardAddress:          common.HexToAddress("0x0"),
			EnableDynamicBidAmount: false,
		})
	}

	keymgr, keyIds, genesisCommInfo, err := newKeyManagerAndGenesisCommInfo(req, setting.NumProposers, setting.NumVoters, proposerPorts)
	req.NoError(err)
	// using nVoters+1 since testingKeys are cached by number of voters
	additionalVoterKeys, err := blockchain.SetupKeys(max(setting.NumVoters, setting.NumAdditionalVoters)+1, 1)
	req.NoError(err)
	chainDataDeployer, err := testutils.NewChainDataDeployer(
		setting.ChainDataConifg, setting.NumVoters, keymgr, keyIds, fmt.Sprintf("localhost:%d", fullnodeWsPorts[0]), setting.TimePerBlock)
	req.NoError(err)
	err = chainDataDeployer.AddAdditionalStakeins(additionalVoterKeys.KeyMgr, additionalVoterKeys.KeyIds, setting.NumAdditionalVoters)
	req.NoError(err)

	genesisPath := ""
	if setting.UseGenesis {
		var genesis *core.Genesis
		if setting.UseDirectBid {
			genesis, err = chainDataDeployer.SetupDirectBidGenesis()
		} else {
			genesis, err = chainDataDeployer.SetupVaultGenesis()
		}
		req.NoError(err)
		genesisPath = writeGenesis(req, genesis)
		defer os.Remove(genesisPath)
	}

	var ps []*server.PalaNode
	var psGrp1 []*server.PalaNode
	var psGrp2 []*server.PalaNode

	// Prepare the proposer.
	keyCfg := server.KeyConfig{
		KeyManager:     keymgr,
		ProposingKeyId: keyIds["proposingKeyIds"][0],
		VotingKeyId:    keyIds["votingKeyIds"][0],
		StakeInKeyId:   keyIds["accountKeyIds"][0],
	}
	hardforkCfg := getDefaultHardforkCfg()
	proposerId := "p0"
	p := NewMediatorBuilder().
		SetAddressesOfBootnodesITrust(bootnodesITrust).
		SetGenesisCommInfo(genesisCommInfo).
		SetGenesisPath(genesisPath).
		SetLoggingId(proposerId).
		SetKeyCfg(keyCfg).
		SetHardForkCfg(hardforkCfg).
		SetDataDir(filepath.Join(setting.DateDir, proposerId)).
		IsVoter(true).
		SetBidAmount(setting.VoterSetting[0].BidAmount).
		SetBidRewardAddress(setting.VoterSetting[0].RewardAddress).
		EnableDynamicBidAmount(setting.VoterSetting[0].EnableDynamicBidAmount).
		SetUseDirectBid(setting.UseDirectBid).
		IsProposer(true).
		SetWsPort(testutils.NextTestingPort(testutils.TestGroupConsensus)).
		SetFullnodeWsPort(fullnodeWsPorts[0]).
		Build()
	ps = append(ps, p)
	psGrp1 = append(psGrp1, p)

	// Prepare the voters.
	voterIds := makeIds("v1-", setting.NumVoters)
	for i := 1; i < setting.NumVoters; i++ {
		keyCfg = server.KeyConfig{
			KeyManager:   keymgr,
			VotingKeyId:  keyIds["votingKeyIds"][i],
			StakeInKeyId: keyIds["accountKeyIds"][i],
		}
		p := NewMediatorBuilder().
			SetAddressesOfBootnodesITrust(bootnodesITrust).
			SetGenesisCommInfo(genesisCommInfo).
			SetGenesisPath(genesisPath).
			SetLoggingId(voterIds[i]).
			SetKeyCfg(keyCfg).
			SetHardForkCfg(hardforkCfg).
			SetDataDir(filepath.Join(setting.DateDir, voterIds[i])).
			IsVoter(true).
			SetBidAmount(setting.VoterSetting[i].BidAmount).
			SetBidRewardAddress(setting.VoterSetting[i].RewardAddress).
			EnableDynamicBidAmount(setting.VoterSetting[i].EnableDynamicBidAmount).
			SetUseDirectBid(setting.UseDirectBid).
			SetWsPort(testutils.NextTestingPort(testutils.TestGroupConsensus)).
			SetFullnodeWsPort(fullnodeWsPorts[0]).
			Build()
		ps = append(ps, p)
		psGrp1 = append(psGrp1, p)
	}

	// Prepare second group of voters.
	voterIds = makeIds("v2-", setting.NumAdditionalVoters)
	for i := 0; i < setting.NumAdditionalVoters; i++ {
		keyCfg = server.KeyConfig{
			KeyManager:   additionalVoterKeys.KeyMgr,
			VotingKeyId:  additionalVoterKeys.KeyIds["votingKeyIds"][i],
			StakeInKeyId: additionalVoterKeys.KeyIds["accountKeyIds"][i],
		}
		b := NewMediatorBuilder().
			SetGenesisCommInfo(genesisCommInfo).
			SetGenesisPath(genesisPath).
			SetLoggingId(voterIds[i]).
			SetKeyCfg(keyCfg).
			SetHardForkCfg(hardforkCfg).
			SetDataDir(filepath.Join(setting.DateDir, voterIds[i])).
			IsVoter(true).
			SetBidAmount(setting.AdditionalVoterSetting[i].BidAmount).
			SetBidRewardAddress(setting.AdditionalVoterSetting[i].RewardAddress).
			EnableDynamicBidAmount(setting.AdditionalVoterSetting[i].EnableDynamicBidAmount).
			SetUseDirectBid(setting.UseDirectBid).
			SetWsPort(testutils.NextTestingPort(testutils.TestGroupConsensus)).
			SetAddressesOfBootnodesITrust(bootnodesITrust).
			SetFullnodeWsPort(fullnodeWsPorts[0])
		p := b.Build()
		ps = append(ps, p)
		psGrp2 = append(psGrp2, p)
	}

	// Prepare the bootnode.
	for i := 0; i < setting.NumBootnodes; i++ {
		p := NewMediatorBuilder().
			SetAddressesOfBootnodesITrust(bootnodesITrust).
			SetGenesisCommInfo(genesisCommInfo).
			SetGenesisPath(genesisPath).
			SetHardForkCfg(hardforkCfg).
			SetLoggingId(bootnodeLoggingIds[i]).
			SetDataDir(filepath.Join(setting.DateDir, bootnodeLoggingIds[i])).
			SetBootnodeListenPort(int64(bootnodePorts[i])).
			SetBootnodesOwnPublicAddress(bootnodesITrust[i]).
			SetWsPort(testutils.NextTestingPort(testutils.TestGroupConsensus)).
			SetFullnodeWsPort(fullnodeWsPorts[0]).
			Build()
		ps = append(ps, p)
	}

	fullnodeIds := makeIds("f", setting.NumFullnodes)
	for i := 0; i < setting.NumFullnodes; i++ {
		p := NewMediatorBuilder().
			SetAddressesOfBootnodesITrust(bootnodesITrust).
			SetGenesisCommInfo(genesisCommInfo).
			SetGenesisPath(genesisPath).
			SetHardForkCfg(hardforkCfg).
			SetLoggingId(fullnodeIds[i]).
			SetDataDir(filepath.Join(setting.DateDir, fullnodeIds[i])).
			IsFullNode(true).
			SetWsPort(fullnodeWsPorts[i]).
			SetFullnodeWsPort(fullnodeWsPorts[i]).
			Build()
		ps = append(ps, p)
	}

	// debug log option
	// server.SetupLogging(server.StdoutLogOutputMode, "", "")
	// lgr.SetLogLevel("/", lgr.LvlDebug)

	return ps, psGrp1, psGrp2, chainDataDeployer, fullnodeWsPorts[0]
}

func reCreateTempDir(tempDir string) {
	os.RemoveAll(tempDir)
	os.MkdirAll(tempDir, os.ModePerm)
}

func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow tests in short mode")
	}
	timePerBlock := 100 * time.Millisecond
	if oTestutils.RaceEnabled {
		timePerBlock = 400 * time.Millisecond
	}

	// TODO(thunder): fix the goroutine leak and open the detection.
	/*
		detector := detector.NewBundleDetector()
		detector.SetTrace()
		defer detector.Verify(t)
	*/

	req := require.New(t)

	tempDir, err := ioutil.TempDir("", "end-to-end-test")
	req.NoError(err)

	// NOTE: Use at least one bootnode and one fullnode to cover the scenario that a fullnode catches up from the genesis.
	setting := nodeSetting{
		IsChainSetuped:      false,
		NumProposers:        1,
		NumVoters:           2,
		NumBootnodes:        1,
		NumFullnodes:        1,
		NumAdditionalVoters: 1,
		DateDir:             tempDir,
		UseDirectBid:        true,
		UseGenesis:          true,
		TimePerBlock:        timePerBlock,
		ChainDataConifg:     testutils.GetDefaultChainDataConfig(),
	}

	ps, psGrp1, psGrp2, chainDataDeployer, _ := prepareDefaultNodes(
		req, setting)
	// TODO(thunder): Test more actions in this case:
	// * Transfer the balance and
	defer reCreateTempDir(tempDir)

	t.Run("normal case", func(t *testing.T) {
		req := require.New(t)

		for _, p := range ps {
			err := p.Start()
			req.NoError(err)
		}
		for _, p := range psGrp1 {
			p.Bidder().SetStopSessionForTest(1)
		}
		err = setupChain(chainDataDeployer, setting)
		req.NoError(err)
		defer chainDataDeployer.Close()

		testutils.ExpectProgress(req, 15*time.Second, getMediators(ps), blockchain.NewBlockSn(1, 1, 3))
		for _, p := range ps {
			err := p.Stop()
			req.NoError(err)
		}
	})

	t.Run("normal case again", func(t *testing.T) {
		req := require.New(t)

		for _, p := range ps {
			err := p.Start()
			req.NoError(err)
		}
		for _, p := range psGrp1 {
			p.Bidder().SetStopSessionForTest(1)
		}
		err = setupChain(chainDataDeployer, setting)
		req.NoError(err)
		defer chainDataDeployer.Close()

		testutils.ExpectProgress(req, 15*time.Second, getMediators(ps), blockchain.NewBlockSn(1, 2, 3))
		for _, p := range ps {
			err := p.Stop()
			req.NoError(err)
		}
	})

	t.Run("reconfiguration case", func(t *testing.T) {
		// Reset the chain data.
		reCreateTempDir(tempDir)

		req := require.New(t)
		if !setting.UseDirectBid {
			t.Skip("Vault not supported yet")
		}

		for _, p := range ps {
			err := p.Start()
			req.NoError(err)
		}
		for _, p := range psGrp2 {
			p.Bidder().SetStopSessionForTest(1)
		}
		err = setupChain(chainDataDeployer, setting)
		req.NoError(err)
		defer chainDataDeployer.Close()

		sortedVotingKeys := chainDataDeployer.GetOriginalVotingKeys()
		sort.Slice(sortedVotingKeys, func(i, j int) bool {
			return bytes.Compare(sortedVotingKeys[i][:], sortedVotingKeys[j][:]) < 0
		})
		testutils.ExpectReconfiguration(
			req, 25*time.Second, getMediators(ps), testutils.CheckVoters(sortedVotingKeys))

		expected := blockchain.NewBlockSn(2, 1, 1)
		for _, p := range ps {
			actual := p.Mediator().GetBlockChainForTest().GetFinalizedHeadSn()
			req.True(actual.Compare(expected) >= 0, actual)
			err := p.Stop()
			req.NoError(err)
		}
	})

	t.Run("shrink voters", func(t *testing.T) {
		req := require.New(t)
		if !setting.UseDirectBid {
			t.Skip("Vault not supported yet")
		}

		stake := election.MinBidderStake.GetValueAt(0)
		stake.Mul(stake, big.NewInt(2))

		for _, p := range ps {
			err := p.Start()
			req.NoError(err)
		}
		for _, p := range psGrp1 {
			p.Bidder().SetStopSessionForTest(1)
		}
		err := setupChain(chainDataDeployer, setting)
		req.NoError(err)
		defer chainDataDeployer.Close()

		// Voters in psGrp2 may not ready to bid, so we check the result in the next session.
		checkNothing := func(req *require.Assertions, tries int, commInfo *committee.CommInfo) bool {
			return true
		}
		testutils.ExpectReconfiguration(req, 35*time.Second, getMediators(ps), checkNothing)

		sortedVotingKeys := chainDataDeployer.GetAdditionalVotingKeys()
		sort.Slice(sortedVotingKeys, func(i, j int) bool {
			return bytes.Compare(sortedVotingKeys[i][:], sortedVotingKeys[j][:]) < 0
		})
		testutils.ExpectReconfiguration(
			req, 35*time.Second, getMediators(ps), testutils.CheckVoters(sortedVotingKeys))

		expected := blockchain.NewBlockSn(3, 1, 1)
		for _, p := range ps {
			actual := p.Mediator().GetBlockChainForTest().GetFinalizedHeadSn()
			req.True(actual.Compare(expected) >= 0, actual)
			err := p.Stop()
			req.NoError(err)
		}
	})

	t.Run("append two history db case", func(t *testing.T) {
		req := require.New(t)

		for _, p := range ps {
			err := p.Start()
			req.NoError(err)
		}

		err = setupChain(chainDataDeployer, setting)
		req.NoError(err)
		defer chainDataDeployer.Close()

		testutils.ExpectProgress(req, 15*time.Second, getMediators(ps), blockchain.NewBlockSn(3, 1, 1))
		for _, p := range ps {
			err := p.Stop()
			req.NoError(err)
		}

		// move proposer v0's chaindata to chaindata.1 as history data dir 1
		// data will be:
		//  chaindata.1 -> chaindata
		os.Rename(filepath.Join(tempDir, "/v0/thunder/chaindata"), filepath.Join(tempDir, "/v0/thunder/chaindata.1"))
		// chain start again
		for _, p := range ps {
			err := p.Start()
			req.NoError(err)
		}

		for _, p := range ps {
			actual := p.Mediator().GetBlockChainForTest().GetFinalizedHeadSn()
			req.True(actual.Compare(blockchain.NewBlockSn(3, 1, 1)) >= 0, actual)
		}

		err = setupChain(chainDataDeployer, setting)
		req.NoError(err)
		defer chainDataDeployer.Close()

		testutils.ExpectProgress(req, 15*time.Second, getMediators(ps), blockchain.NewBlockSn(6, 1, 1))
		for _, p := range ps {
			err := p.Stop()
			req.NoError(err)
		}

		// move chaindata.1 to chaindata.2 as history data dir 2
		// move proposer v0's chaindata to chaindata.1 as history data dir 1
		// data will be:
		//  chaindata.2 -> chaindata.1 -> chaindata
		os.Rename(filepath.Join(tempDir, "/v0/thunder/chaindata.1"), filepath.Join(tempDir, "/v0/thunder/chaindata.2"))
		os.Rename(filepath.Join(tempDir, "/v0/thunder/chaindata"), filepath.Join(tempDir, "/v0/thunder/chaindata.1"))
		// chain start again
		for _, p := range ps {
			err := p.Start()
			req.NoError(err)
		}

		for _, p := range ps {
			actual := p.Mediator().GetBlockChainForTest().GetFinalizedHeadSn()
			req.True(actual.Compare(blockchain.NewBlockSn(6, 1, 1)) >= 0, actual)
		}

		err = setupChain(chainDataDeployer, setting)
		req.NoError(err)
		defer chainDataDeployer.Close()

		testutils.ExpectProgress(req, 15*time.Second, getMediators(ps), blockchain.NewBlockSn(9, 1, 1))
		for _, p := range ps {
			actual := p.Mediator().GetBlockChainForTest().GetFinalizedHeadSn()
			req.True(actual.Compare(blockchain.NewBlockSn(9, 1, 1)) >= 0, actual)
			// make sure each block can be retrieved
			blockHeight := p.Mediator().GetBlockChainForTest().GetFreshestNotarizedHead().GetNumber()
			for blockNumber := uint64(1); blockNumber < blockHeight; blockNumber++ {
				block := p.Mediator().GetBlockChainForTest().GetBlockByNumber(blockNumber)
				req.NotNil(block)
			}
			err := p.Stop()
			req.NoError(err)
		}
	})
}

func TestEndToEnd_R2_5_GasTableChange(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow tests in short mode")
	}
	timePerBlock := 100 * time.Millisecond
	if oTestutils.RaceEnabled {
		timePerBlock = 400 * time.Millisecond
	}

	// TODO(thunder): fix the goroutine leak and open the detection.
	/*
		detector := detector.NewBundleDetector()
		detector.SetTrace()
		defer detector.Verify(t)
	*/

	req := require.New(t)

	tempDir, err := ioutil.TempDir("", "R2_5-gas-change")
	req.NoError(err)

	// NOTE: Use at least one bootnode and one fullnode to cover the scenario that a fullnode catches up from the genesis.
	setting := nodeSetting{
		IsChainSetuped:      false,
		NumProposers:        1,
		NumVoters:           2,
		NumBootnodes:        1,
		NumFullnodes:        1,
		NumAdditionalVoters: 1,
		DateDir:             tempDir,
		UseDirectBid:        true,
		UseGenesis:          true,
		TimePerBlock:        timePerBlock,
		ChainDataConifg:     testutils.GetDefaultChainDataConfig(),
	}

	ps, psGrp1, _, chainDataDeployer, fullnodeWsPort := prepareDefaultNodes(
		req, setting)
	// TODO(thunder): Test more actions in this case:
	// * Transfer the balance and
	defer reCreateTempDir(tempDir)

	t.Run("R2.5 gas table change", func(t *testing.T) {
		// contract call: num += 1
		// sload + sstore(unchanged)
		sendIncTx := func(client *ethclient.Client, signer types.Signer, key *ecdsa.PrivateKey, contractAddr common.Address) (*types.Receipt, error) {
			data := crypto.Keccak256([]byte("inc()"))[:4]
			tx, err := testutils.SendTransaction(client, signer, key, 0, &contractAddr, common.Big0, 0, common.Big0, data)
			if err != nil {
				return nil, err
			}
			return testutils.WaitForReceipt(client, tx.Hash(), timePerBlock, 20)
		}

		// contract call:LibThunderRNG.rand()
		// call + rng
		sendRngTx := func(client *ethclient.Client, signer types.Signer, key *ecdsa.PrivateKey, contractAddr common.Address) (*types.Receipt, error) {
			data := crypto.Keccak256([]byte("rng()"))[:4]
			tx, err := testutils.SendTransaction(client, signer, key, 0, &contractAddr, common.Big0, 0, common.Big0, data)
			if err != nil {
				return nil, err
			}
			return testutils.WaitForReceipt(client, tx.Hash(), timePerBlock, 20)
		}

		req := require.New(t)

		for _, p := range ps {
			err := p.Start()
			req.NoError(err)
		}
		for _, p := range psGrp1 {
			p.Bidder().SetStopSessionForTest(1)
		}
		err = setupChain(chainDataDeployer, setting)
		req.NoError(err)
		defer chainDataDeployer.Close()

		rpc.ThunderLogRequest = true
		signer := types.NewEIP155Signer(big.NewInt(19))
		testingKey := oTestutils.TestingKey
		// enable rng earlier for faster test
		thundervm.IsRNGActive.SetTestValueAt(true, 0)
		hardforkCfg := getDefaultHardforkCfg()
		chainConfig := params.ThunderChainConfig()
		chainConfig.Thunder = blockchain.NewThunderConfig(hardforkCfg)
		client, err := ethclient.Dial(fmt.Sprintf("ws://127.0.0.1:%d", fullnodeWsPort))
		req.NoError(err)
		defer client.Close()
		_, contractAddr := deployTestingContract(req, client, signer, timePerBlock)

		r, err := sendIncTx(client, signer, testingKey, contractAddr)
		req.NoError(err)
		req.Equal(types.ReceiptStatusSuccessful, r.Status)
		txHashOfIncBeforeHF := r.TxHash
		gasUsageOfIncBeforeHF := r.GasUsed
		r, err = sendRngTx(client, signer, testingKey, contractAddr)
		req.NoError(err)
		req.Equal(types.ReceiptStatusSuccessful, r.Status)
		txHashOfRngBeforeHF := r.TxHash
		gasUsageOfRngBeforeHF := r.GasUsed

		// gas table hardforked
		testutils.ExpectProgress(req, 15*time.Second, getMediators(ps), blockchain.NewBlockSn(GAS_TABLE_HARDFORK_SEESSION, 1, 1))

		r, err = sendIncTx(client, signer, testingKey, contractAddr)
		req.NoError(err)
		req.Equal(types.ReceiptStatusSuccessful, r.Status)
		gasUsageOfIncAfterHF := r.GasUsed
		r, err = sendRngTx(client, signer, testingKey, contractAddr)
		req.NoError(err)
		req.Equal(types.ReceiptStatusSuccessful, r.Status)
		gasUsageOfRngAfterHF := r.GasUsed

		// 16000 - 200 = 15800
		gasDiffSLoad := params.Pala2P5SLoad - params.SloadGasEIP150
		req.Equal(gasDiffSLoad, gasUsageOfIncAfterHF-gasUsageOfIncBeforeHF)

		gasDiffCall := params.Pala2P5Calls - params.CallGasEIP150
		// thundervm.random.RequiredGas() - thundervm.random2P5.RequiredGas()
		gasDiffRng := params.Pala2P5SLoad - params.SloadGas
		req.Equal(gasDiffCall+gasDiffRng, gasUsageOfRngAfterHF-gasUsageOfRngBeforeHF)

		c, err := rpc.DialContext(context.Background(), fmt.Sprintf("ws://127.0.0.1:%d", fullnodeWsPort))
		req.NoError(err)
		defer c.Close()
		checkTracedTransactionGasUsage := func(txHash common.Hash, expectedGasUsage uint64) {
			var result ExecutionResult
			err = c.CallContext(context.Background(), &result, "debug_traceTransaction", txHash)
			req.NoError(err)
			req.Equal(expectedGasUsage, result.Gas)
		}
		checkTracedTransactionGasUsage(txHashOfIncBeforeHF, gasUsageOfIncBeforeHF)
		checkTracedTransactionGasUsage(txHashOfRngBeforeHF, gasUsageOfRngBeforeHF)

		for _, p := range ps {
			err := p.Stop()
			req.NoError(err)
		}
	})
}

func deployTestingContract(req *require.Assertions, client *ethclient.Client, signer types.Signer, timePerBlock time.Duration) (*types.Transaction, common.Address) {
	deployKey := oTestutils.TestingKey
	sol := `
contract C {
	uint256 num;
	constructor() public {num = 1;}
	function inc() public {num += 1;}
	function rng() public {LibThunderRNG.rand();}
}
library LibThunderRNG {
	function rand() internal returns (uint256) {
		uint256[1] memory m;
		assembly {if iszero(call(not(0),0x8cC9C2e145d3AA946502964B1B69CE3cD066A9C7,0,0,0x0,m,0x20)){revert(0,0)}}
		return m[0];
	}
}
`
	code, err := testutils.CompileSol("C", sol)
	req.NoError(err)
	code = strings.TrimPrefix(code, "0x")
	data, err := hex.DecodeString(code)
	req.NoError(err)
	tx, err := testutils.SendTransaction(client, signer, deployKey, 0, nil, common.Big0, 0, common.Big0, data)
	req.NoError(err)
	receipt, err := testutils.WaitForReceipt(client, tx.Hash(), timePerBlock, 20)
	req.NoError(err)
	req.Equal(types.ReceiptStatusSuccessful, receipt.Status)
	return tx, receipt.ContractAddress
}

func TestEndToEnd_VoterBehavior_DirectBid(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow tests in short mode")
	}
	timePerBlock := 100 * time.Millisecond
	if oTestutils.RaceEnabled {
		timePerBlock = 400 * time.Millisecond
	}

	// TODO(thunder): fix the goroutine leak and open the detection.
	/*
		detector := detector.NewBundleDetector()
		detector.SetTrace()
		defer detector.Verify(t)
	*/

	req := require.New(t)

	tempDir, err := ioutil.TempDir("", "end-to-end-test-voter")
	req.NoError(err)

	chainConfig := testutils.GetDefaultChainDataConfig()
	// give each voter 1000000 TT + 1TT for gas fee
	chainConfig.ValuePerComm = new(big.Int).Mul(big.NewInt(1000000), big.NewInt(1e18))
	chainConfig.AdditionalStakeinForDirectBid = big.NewInt(1e18)
	// NOTE: Use at least one bootnode and one fullnode to cover the scenario that a fullnode catches up from the genesis.
	setting := nodeSetting{
		IsChainSetuped:      false,
		NumProposers:        1,
		NumVoters:           3,
		NumBootnodes:        1,
		NumFullnodes:        1,
		NumAdditionalVoters: 1,
		DateDir:             tempDir,
		UseDirectBid:        true,
		UseGenesis:          true,
		TimePerBlock:        timePerBlock,
		ChainDataConifg:     chainConfig,
	}

	ps, _, psVoterGrp2, chainDataDeployer, fullnodeWsPort := prepareDefaultNodes(
		req, setting)

	defer reCreateTempDir(tempDir)

	checkVoterBalance := func(c *test.Client, address common.Address, expectedBalance *big.Int, blockNumber *big.Int) {
		balance, err := c.GetBalance(context.Background(), address, blockNumber)
		req.NoError(err)
		// expectedBalance = balance + 1TT - gas fee
		// so check abs(expectedBalance - balance) < 1TT
		fmt.Printf("expectedBalance: %v, actual: %v\n", expectedBalance, balance)
		req.True(new(big.Int).Abs(new(big.Int).Sub(expectedBalance, balance)).Cmp(big.NewInt(1e18)) < 0)
	}
	defaultMinBidAmount := new(big.Int).Mul(big.NewInt(100000), big.NewInt(1e18))

	t.Run("normal case", func(t *testing.T) {
		req := require.New(t)

		for _, p := range ps {
			err := p.Start()
			req.NoError(err)
		}
		err = setupChain(chainDataDeployer, setting)
		req.NoError(err)
		defer chainDataDeployer.Close()

		testutils.ExpectReconfiguration(
			req, 25*time.Second, getMediators(ps), testutils.CheckVoterSize(setting.NumVoters+setting.NumAdditionalVoters))

		expected := blockchain.NewBlockSn(2, 1, 1)
		for _, p := range ps {
			actual := p.Mediator().GetBlockChainForTest().GetFreshestNotarizedHeadSn()
			req.True(actual.Compare(expected) >= 0, actual)
		}

		// get latest block
		blockNumber := ps[0].Mediator().GetBlockChainForTest().GetFreshestNotarizedHead().GetNumber()
		c, err := test.DialContext(context.Background(), fmt.Sprintf("ws://127.0.0.1:%d", fullnodeWsPort))
		req.NoError(err)
		defer c.Close()

		// check remain money is right
		remainMoney := new(big.Int).Sub(chainConfig.ValuePerComm, defaultMinBidAmount)
		for _, address := range chainDataDeployer.GetOriginalVotingOperators() {
			checkVoterBalance(c, address, remainMoney, big.NewInt(int64(blockNumber)))
		}
		for _, address := range chainDataDeployer.GetAdditionalVotingOperators() {
			checkVoterBalance(c, address, remainMoney, big.NewInt(int64(blockNumber)))
		}

		for _, p := range ps {
			err := p.Stop()
			req.NoError(err)
		}
	})

	t.Run("stop Addition voters and check refund successfully", func(t *testing.T) {
		// Reset the chain data.
		reCreateTempDir(tempDir)
		req := require.New(t)

		for _, p := range ps {
			err := p.Start()
			req.NoError(err)
		}

		err = setupChain(chainDataDeployer, setting)
		req.NoError(err)
		defer chainDataDeployer.Close()

		// the committees at session N : all voter(voter 1, voter2, voter3)
		testutils.ExpectReconfiguration(
			req, 25*time.Second, getMediators(ps), testutils.CheckVoterSize(setting.NumVoters+setting.NumAdditionalVoters))
		expected := blockchain.NewBlockSn(2, 1, 1)
		for _, p := range ps {
			actual := p.Mediator().GetBlockChainForTest().GetFinalizedHeadSn()
			req.True(actual.Compare(expected) >= 0, actual)
		}

		// psVoterGrp1: voter 1, voter2
		// psVoterGrp2: voter 3
		// stop voter bidder at session current N
		currentS := blockchain.Session(ps[0].Mediator().GetBlockChainForTest().GetFinalizedHeadSn().S)
		for _, p := range psVoterGrp2 {
			p.Bidder().SetStopSessionForTest(currentS)
		}

		// the committees at session N+1 : only original voters(voter 1, voter2)
		testutils.ExpectReconfiguration(
			req, 25*time.Second, getMediators(ps), testutils.CheckVoterSize(setting.NumVoters))
		expected = blockchain.NewBlockSn(uint32(currentS)+1, 1, 1)
		for _, p := range ps {
			actual := p.Mediator().GetBlockChainForTest().GetFinalizedHeadSn()
			req.True(actual.Compare(expected) >= 0, actual)
		}

		// get block number at Sn(N+1, 1, 1)
		blockNumber := ps[0].Mediator().GetBlockChainForTest().GetFreshestNotarizedHead().GetNumber()
		c, err := test.DialContext(context.Background(), fmt.Sprintf("ws://127.0.0.1:%d", fullnodeWsPort))
		req.NoError(err)
		defer c.Close()

		// check remain money is right
		remainMoney := new(big.Int).Sub(chainConfig.ValuePerComm, defaultMinBidAmount)
		for _, address := range chainDataDeployer.GetOriginalVotingOperators() {
			checkVoterBalance(c, address, remainMoney, big.NewInt(int64(blockNumber)))
		}
		// get 100000TT refund
		for _, address := range chainDataDeployer.GetAdditionalVotingOperators() {
			checkVoterBalance(c, address, chainConfig.ValuePerComm, big.NewInt(int64(blockNumber)))
		}

		for _, p := range ps {
			err := p.Stop()
			req.NoError(err)
		}
	})

	t.Run("init 4 voter and setting a additional voter with higher bid amount", func(t *testing.T) {
		// hardfork config:
		//    expectedCommSize = 4
		const expectedCommSize = 4

		// Reset the chain data.
		reCreateTempDir(tempDir)

		chainConfig := testutils.GetDefaultChainDataConfig()
		// give each voter 1000000 TT + 1TT for gas fee
		chainConfig.ValuePerComm = new(big.Int).Mul(big.NewInt(1000000), big.NewInt(1e18))
		chainConfig.AdditionalStakeinForDirectBid = big.NewInt(1e18)
		// NOTE: Use at least one bootnode and one fullnode to cover the scenario that a fullnode catches up from the genesis.
		setting := nodeSetting{
			IsChainSetuped:      false,
			NumProposers:        1,
			NumVoters:           4,
			NumBootnodes:        1,
			NumFullnodes:        1,
			NumAdditionalVoters: 1,
			DateDir:             tempDir,
			UseDirectBid:        true,
			UseGenesis:          true,
			TimePerBlock:        timePerBlock,
			ChainDataConifg:     chainConfig,
			VoterSetting: []voterSetting{
				{
					BidAmount:              big.NewInt(-1),
					RewardAddress:          common.HexToAddress("0x0"),
					EnableDynamicBidAmount: false,
				},
				{
					BidAmount:              big.NewInt(-1),
					RewardAddress:          common.HexToAddress("0x0"),
					EnableDynamicBidAmount: false,
				},
				{
					BidAmount:              big.NewInt(-1),
					RewardAddress:          common.HexToAddress("0x0"),
					EnableDynamicBidAmount: false,
				},
				{
					BidAmount:              big.NewInt(-1),
					RewardAddress:          common.HexToAddress("0x0"),
					EnableDynamicBidAmount: false,
				},
			},
			AdditionalVoterSetting: []voterSetting{
				{
					// 500000 TT
					BidAmount:              new(big.Int).Mul(big.NewInt(500000), big.NewInt(1e18)),
					RewardAddress:          common.HexToAddress("0x0"),
					EnableDynamicBidAmount: false,
				},
			},
		}

		ps, _, psVoterGrp2, chainDataDeployer, fullnodeWsPort := prepareDefaultNodes(req, setting)

		req := require.New(t)

		for _, p := range ps {
			err := p.Start()
			req.NoError(err)
		}
		// stop voter bidder at session 1, => do not bid at the beginning
		for _, p := range psVoterGrp2 {
			p.Bidder().SetStopSessionForTest(1)
		}

		// psVoterGrp1: voter 1, voter2, voter 3, voter 4
		// psVoterGrp2: voter 5
		err = setupChain(chainDataDeployer, setting)
		req.NoError(err)
		defer chainDataDeployer.Close()

		// the committees at session 2 : 4 voter
		testutils.ExpectReconfiguration(
			req, 25*time.Second, getMediators(ps), testutils.CheckVoterSize(expectedCommSize))

		// start additional voter start bid, current block is Sn(2, 1, 1)
		for _, p := range psVoterGrp2 {
			p.Bidder().SetStopSessionForTest(0)
		}

		checkVoter := func(votingKey [32]byte, setting voterSetting) func(req *require.Assertions, tries int, commInfo *committee.CommInfo) bool {
			return func(req *require.Assertions, tries int, commInfo *committee.CommInfo) bool {
				for _, c := range commInfo.MemberInfo {
					if votingKey == sha256.Sum256(c.PubVoteKey.ToBytes()) {
						req.Equal(setting.BidAmount, c.Stake, "bid amount is differenet")
						req.Equal(setting.RewardAddress, c.Coinbase, "bid reward address is differenet")
						return true
					}
				}

				// bidding might take effect at the next session, give it a chance
				if tries > 1 {
					req.Nil(fmt.Sprintf("voter[%x] is not in committee", votingKey))
				}
				return false
			}
		}

		// the committees at session 3: 4 voters (contain voter 5)
		// and, check voter 5 be a committee member
		additionVoterKey := chainDataDeployer.GetAdditionalVotingKeys()[0]
		additionVoterSetting := setting.AdditionalVoterSetting[0]
		testutils.ExpectReconfiguration(
			req, 25*time.Second, getMediators(ps), checkVoter(additionVoterKey, additionVoterSetting))
		expected := blockchain.NewBlockSn(3, 1, 1)
		for _, p := range ps {
			actual := p.Mediator().GetBlockChainForTest().GetFinalizedHeadSn()
			req.True(actual.Compare(expected) >= 0, actual)
		}

		// get current block number
		currentBlockNumber := ps[0].Mediator().GetBlockChainForTest().GetFinalizedHead().GetNumber()
		c, err := test.DialContext(context.Background(), fmt.Sprintf("ws://127.0.0.1:%d", fullnodeWsPort))
		req.NoError(err)
		defer c.Close()

		// check remain money is right
		remainMoney := new(big.Int).Sub(chainConfig.ValuePerComm, additionVoterSetting.BidAmount)
		additionalVoterAddress := chainDataDeployer.GetAdditionalVotingOperators()[0]
		checkVoterBalance(c, additionalVoterAddress, remainMoney, big.NewInt(int64(currentBlockNumber)))

		// stop additional voter bidding process, current block is Sn(3, 1, 1)
		for _, p := range psVoterGrp2 {
			p.Bidder().SetStopSessionForTest(3)
		}

		// check next round, additional voter is not a committee member anymore
		sortedVotingKeys := chainDataDeployer.GetOriginalVotingKeys()
		sort.Slice(sortedVotingKeys, func(i, j int) bool {
			return bytes.Compare(sortedVotingKeys[i][:], sortedVotingKeys[j][:]) < 0
		})
		// check the committee member is original 4 voters
		testutils.ExpectReconfiguration(
			req, 25*time.Second, getMediators(ps), testutils.CheckVoters(sortedVotingKeys))

		// check additional voter money, should be 1000000 TT
		currentBlockNumber = ps[0].Mediator().GetBlockChainForTest().GetFinalizedHead().GetNumber()
		checkVoterBalance(c, additionalVoterAddress, chainConfig.ValuePerComm, big.NewInt(int64(currentBlockNumber)))

		for _, p := range ps {
			err := p.Stop()
			req.NoError(err)
		}
	})
}
func TestEndToEnd_VoterBehavior_VaultBid(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow tests in short mode")
	}
	timePerBlock := 100 * time.Millisecond
	if oTestutils.RaceEnabled {
		timePerBlock = 400 * time.Millisecond
	}

	// TODO(thunder): fix the goroutine leak and open the detection.
	/*
		detector := detector.NewBundleDetector()
		detector.SetTrace()
		defer detector.Verify(t)
	*/

	req := require.New(t)

	tempDir, err := ioutil.TempDir("", "end-to-end-test-vault-bid")
	fmt.Println(tempDir)
	req.NoError(err)

	chainConfig := testutils.GetDefaultChainDataConfig()
	// give each voter 1000000 TT + 1TT for gas fee
	chainConfig.ValuePerComm = new(big.Int).Mul(big.NewInt(1000000), big.NewInt(1e18))
	chainConfig.AdditionalStakeinForDirectBid = big.NewInt(1e18)
	// NOTE: Use at least one bootnode and one fullnode to cover the scenario that a fullnode catches up from the genesis.
	setting := nodeSetting{
		IsChainSetuped:      false,
		NumProposers:        1,
		NumVoters:           2,
		NumBootnodes:        1,
		NumFullnodes:        1,
		NumAdditionalVoters: 1,
		DateDir:             tempDir,
		UseDirectBid:        false,
		UseGenesis:          false,
		TimePerBlock:        timePerBlock,
		ChainDataConifg:     chainConfig,
	}

	ps, _, psVoterGrp2, chainDataDeployer, fullnodeWsPort := prepareDefaultNodes(
		req, setting)

	defer reCreateTempDir(tempDir)

	checkVoterBalance := func(c *test.Client, address common.Address, expectedBalance *big.Int, blockNumber *big.Int) {
		balance, err := c.GetBalance(context.Background(), address, blockNumber)
		req.NoError(err)
		// expectedBalance = balance + 1TT - gas fee
		// so check abs(expectedBalance - balance) < 1TT
		result := (new(big.Int).Abs(new(big.Int).Sub(expectedBalance, balance)).Cmp(big.NewInt(1e18)) < 0)
		if result != true {
			fmt.Printf("address %x expectedBalance: %v, actual: %v\n", address, expectedBalance, balance)
		}
		req.True(result)
	}
	defaultMinBidAmount := new(big.Int).Mul(big.NewInt(100000), big.NewInt(1e18))

	t.Run("normal case", func(t *testing.T) {
		req := require.New(t)

		for _, p := range ps {
			err := p.Start()
			req.NoError(err)
		}
		err = setupChain(chainDataDeployer, setting)
		req.NoError(err)
		defer chainDataDeployer.Close()

		blockNumber := ps[0].Mediator().GetBlockChainForTest().GetFreshestNotarizedHead().GetNumber()
		c, err := test.DialContext(context.Background(), fmt.Sprintf("ws://127.0.0.1:%d", fullnodeWsPort))
		req.NoError(err)
		defer c.Close()

		// check remain money is right
		remainMoney := chainConfig.StakeinValue // 1TT for send tx
		for _, address := range chainDataDeployer.GetOriginalVotingOperators() {
			checkVoterBalance(c, address, remainMoney, big.NewInt(int64(blockNumber)))
		}
		for _, address := range chainDataDeployer.GetAdditionalVotingOperators() {
			checkVoterBalance(c, address, remainMoney, big.NewInt(int64(blockNumber)))
		}

		testutils.ExpectReconfiguration(
			req, 25*time.Second, getMediators(ps), testutils.CheckVoterSize(setting.NumVoters+setting.NumAdditionalVoters))

		blockNumber = ps[0].Mediator().GetBlockChainForTest().GetFreshestNotarizedHead().GetNumber()
		// check remain money is right
		remainMoney = chainConfig.StakeinValue // 1TT for send tx
		for _, address := range chainDataDeployer.GetOriginalVotingOperators() {
			checkVoterBalance(c, address, remainMoney, big.NewInt(int64(blockNumber)))
		}
		for _, address := range chainDataDeployer.GetAdditionalVotingOperators() {
			checkVoterBalance(c, address, remainMoney, big.NewInt(int64(blockNumber)))
		}
		// check vault contract setting
		for _, keyHash := range chainDataDeployer.GetOriginalVotingKeys() {
			balance, err := chainDataDeployer.GetBalanceFromVaultContract(keyHash)
			req.NoError(err)
			remainMoney := big.NewInt(0).Sub(chainConfig.ValuePerComm, defaultMinBidAmount)
			req.Equal(balance, remainMoney)
			availableBalance, err := chainDataDeployer.GetAvailableBalanceFromVaultContract(keyHash)
			req.NoError(err)
			req.Equal(availableBalance, chainConfig.ValuePerComm)
		}
		for _, keyHash := range chainDataDeployer.GetAdditionalVotingKeys() {
			balance, err := chainDataDeployer.GetBalanceFromVaultContract(keyHash)
			req.NoError(err)
			remainMoney := big.NewInt(0).Sub(chainConfig.ValuePerComm, defaultMinBidAmount)
			req.Equal(balance, remainMoney)
			availableBalance, err := chainDataDeployer.GetAvailableBalanceFromVaultContract(keyHash)
			req.NoError(err)
			req.Equal(availableBalance, chainConfig.ValuePerComm)
		}

		for _, p := range ps {
			err := p.Stop()
			req.NoError(err)
		}
	})
	t.Run("stop Addition voters and check refund successfully", func(t *testing.T) {
		// Reset the chain data.
		reCreateTempDir(tempDir)
		req := require.New(t)

		for _, p := range ps {
			err := p.Start()
			req.NoError(err)
		}
		// psVoterGrp1: voter 1, voter2
		// psVoterGrp2: voter 3
		err = setupChain(chainDataDeployer, setting)
		req.NoError(err)
		defer chainDataDeployer.Close()
		c, err := test.DialContext(context.Background(), fmt.Sprintf("ws://127.0.0.1:%d", fullnodeWsPort))
		req.NoError(err)
		defer c.Close()

		// the committees at session n : all voter(voter 1, voter2, voter3)
		testutils.ExpectReconfiguration(
			req, 25*time.Second, getMediators(ps), testutils.CheckVoterSize(setting.NumVoters+setting.NumAdditionalVoters))

		stopBidSession := ps[0].Mediator().GetBlockChainForTest().GetFreshestNotarizedHeadSn().S
		// stop voter bidder
		for _, p := range psVoterGrp2 {
			p.Bidder().SetStopSessionForTest(blockchain.Session(stopBidSession))
		}
		// the committees at session n + 1 : only original voters(voter 1, voter2)
		testutils.ExpectReconfiguration(
			req, 25*time.Second, getMediators(ps), testutils.CheckVoterSize(setting.NumVoters))

		// check vault contract setting
		for _, keyHash := range chainDataDeployer.GetOriginalVotingKeys() {
			balance, err := chainDataDeployer.GetBalanceFromVaultContract(keyHash)
			req.NoError(err)
			remainMoney := big.NewInt(0).Sub(chainConfig.ValuePerComm, defaultMinBidAmount)
			req.Equal(balance, remainMoney)
			availableBalance, err := chainDataDeployer.GetAvailableBalanceFromVaultContract(keyHash)
			req.NoError(err)
			req.Equal(availableBalance, chainConfig.ValuePerComm)
		}
		// check refund
		for _, keyHash := range chainDataDeployer.GetAdditionalVotingKeys() {
			balance, err := chainDataDeployer.GetBalanceFromVaultContract(keyHash)
			req.NoError(err)
			remainMoney := chainConfig.ValuePerComm
			req.Equal(balance, remainMoney)
			availableBalance, err := chainDataDeployer.GetAvailableBalanceFromVaultContract(keyHash)
			req.NoError(err)
			req.Equal(availableBalance, chainConfig.ValuePerComm)
		}
		for _, p := range ps {
			err := p.Stop()
			req.NoError(err)
		}
	})
	t.Run("Addition voters with dynamic bid", func(t *testing.T) {
		// Reset the chain data.
		// server.SetupLogging(server.StdoutLogOutputMode, "", "")
		reCreateTempDir(tempDir)
		setting := nodeSetting{
			IsChainSetuped:      false,
			NumProposers:        1,
			NumVoters:           2,
			NumBootnodes:        1,
			NumFullnodes:        1,
			NumAdditionalVoters: 1,
			DateDir:             tempDir,
			UseDirectBid:        false,
			UseGenesis:          false,
			TimePerBlock:        timePerBlock,
			ChainDataConifg:     chainConfig,
			VoterSetting: []voterSetting{
				{
					BidAmount:              big.NewInt(-1),
					RewardAddress:          common.HexToAddress("0x0"),
					EnableDynamicBidAmount: false,
				},
				{
					BidAmount:              big.NewInt(-1),
					RewardAddress:          common.HexToAddress("0x0"),
					EnableDynamicBidAmount: false,
				},
			},
			AdditionalVoterSetting: []voterSetting{
				{
					BidAmount:              big.NewInt(-1),
					RewardAddress:          common.HexToAddress("0x0"),
					EnableDynamicBidAmount: true,
				},
			},
		}

		ps, _, _, chainDataDeployer, fullnodeWsPort := prepareDefaultNodes(req, setting)

		req := require.New(t)

		for _, p := range ps {
			err := p.Start()
			req.NoError(err)
		}
		// psVoterGrp1: voter 1, voter2
		// psVoterGrp2: voter 3
		err = setupChain(chainDataDeployer, setting)
		req.NoError(err)
		defer chainDataDeployer.Close()
		c, err := test.DialContext(context.Background(), fmt.Sprintf("ws://127.0.0.1:%d", fullnodeWsPort))
		req.NoError(err)
		defer c.Close()

		// set default bid amount
		for _, keyHash := range chainDataDeployer.GetAdditionalVotingKeys() {
			err := chainDataDeployer.SetBiddingAmountToVaultContract(keyHash, defaultMinBidAmount)
			req.NoError(err)
		}

		// the committees at session n : all voter(voter 1, voter2, voter3)
		testutils.ExpectReconfiguration(
			req, 25*time.Second, getMediators(ps), testutils.CheckVoterSize(setting.NumVoters+setting.NumAdditionalVoters))

		// set 0 and make it lost election
		for _, keyHash := range chainDataDeployer.GetAdditionalVotingKeys() {
			err := chainDataDeployer.SetBiddingAmountToVaultContract(keyHash, big.NewInt(0))
			req.NoError(err)
		}

		// the committees at session n + 1 : only original voters(voter 1, voter2)
		testutils.ExpectReconfiguration(
			req, 25*time.Second, getMediators(ps), testutils.CheckVoterSize(setting.NumVoters))

		// set defaultMinBidAmount * 2
		for _, keyHash := range chainDataDeployer.GetAdditionalVotingKeys() {
			bidAmount := big.NewInt(0).Mul(defaultMinBidAmount, big.NewInt(2))
			err := chainDataDeployer.SetBiddingAmountToVaultContract(keyHash, bidAmount)
			req.NoError(err)
		}

		// the committees at session n + 2 : all voter(voter 1, voter2, voter3)
		testutils.ExpectReconfiguration(
			req, 25*time.Second, getMediators(ps), testutils.CheckVoterSize(setting.NumVoters+setting.NumAdditionalVoters))

		// check vault contract setting
		for _, keyHash := range chainDataDeployer.GetOriginalVotingKeys() {
			balance, err := chainDataDeployer.GetBalanceFromVaultContract(keyHash)
			req.NoError(err)
			remainMoney := big.NewInt(0).Sub(chainConfig.ValuePerComm, defaultMinBidAmount)
			req.Equal(balance, remainMoney)
			availableBalance, err := chainDataDeployer.GetAvailableBalanceFromVaultContract(keyHash)
			req.NoError(err)
			req.Equal(availableBalance, chainConfig.ValuePerComm)
		}
		for _, keyHash := range chainDataDeployer.GetAdditionalVotingKeys() {
			balance, err := chainDataDeployer.GetBalanceFromVaultContract(keyHash)
			req.NoError(err)
			bidAmount := big.NewInt(0).Mul(defaultMinBidAmount, big.NewInt(2))
			remainMoney := big.NewInt(0).Sub(chainConfig.ValuePerComm, bidAmount)
			req.Equal(remainMoney, balance)
			availableBalance, err := chainDataDeployer.GetAvailableBalanceFromVaultContract(keyHash)
			req.NoError(err)
			req.Equal(chainConfig.ValuePerComm, availableBalance)
		}
		for _, p := range ps {
			err := p.Stop()
			req.NoError(err)
		}
	})
}

func TestEndToEnd_Bid_With_Chain_Status(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow tests in short mode")
	}
	timePerBlock := 100 * time.Millisecond
	if oTestutils.RaceEnabled {
		timePerBlock = 400 * time.Millisecond
	}

	// TODO(thunder): fix the goroutine leak and open the detection.
	/*
		detector := detector.NewBundleDetector()
		detector.SetTrace()
		defer detector.Verify(t)
	*/

	req := require.New(t)

	tempDir, err := ioutil.TempDir("", "end-to-end-test-voter")
	req.NoError(err)

	chainConfig := testutils.GetDefaultChainDataConfig()
	// give each voter 1000000 TT + 1TT for gas fee
	chainConfig.ValuePerComm = new(big.Int).Mul(big.NewInt(1000000), big.NewInt(1e18))
	chainConfig.AdditionalStakeinForDirectBid = big.NewInt(1e18)
	// NOTE: Use at least one bootnode and one fullnode to cover the scenario that a fullnode catches up from the genesis.
	setting := nodeSetting{
		IsChainSetuped:      false,
		NumProposers:        1,
		NumVoters:           3,
		NumBootnodes:        1,
		NumFullnodes:        1,
		NumAdditionalVoters: 1,
		DateDir:             tempDir,
		UseDirectBid:        true,
		UseGenesis:          true,
		TimePerBlock:        timePerBlock,
		ChainDataConifg:     chainConfig,
	}

	ps, psVoterGrp1, psVoterGrp2, chainDataDeployer, _ := prepareDefaultNodes(
		req, setting)

	defer reCreateTempDir(tempDir)

	t.Run("should not bid while chain is behind", func(t *testing.T) {
		reCreateTempDir(tempDir)
		req := require.New(t)

		for _, p := range ps {
			err := p.Start()
			req.NoError(err)

			// Group2 stop sync block to make a delay chain
			for _, p2 := range psVoterGrp2 {
				if p == p2 {
					p.Mediator().StopSyncerForTest()
				}
			}
		}

		err = setupChain(chainDataDeployer, setting)
		req.NoError(err)
		defer chainDataDeployer.Close()

		testutils.ExpectNoProgress(req, 3*time.Second, getMediators(psVoterGrp2))
		testutils.ExpectProgress(req, 15*time.Second, getMediators(psVoterGrp1), blockchain.NewBlockSn(2, 1, 1))

		// Expect only setting.NumVoters elected
		headSn := psVoterGrp1[0].Mediator().GetBlockChainForTest().GetFinalizedHeadSn()
		commInfo := psVoterGrp1[0].Mediator().GetBlockChainForTest().GetCommInfo(headSn.Epoch.Session)
		req.Equal(setting.NumVoters, len(commInfo.MemberInfo))

		for _, p := range ps {
			p.Mediator().GetBlockChainForTest().StopCreatingNewBlocks(2 * time.Second)
		}
		for _, p := range psVoterGrp2 {
			p.Mediator().StartSyncerForTest()
		}

		headSn = psVoterGrp1[0].Mediator().GetBlockChainForTest().GetFinalizedHeadSn()
		testutils.ExpectProgress(req, 15*time.Second, getMediators(psVoterGrp2), headSn)

		for _, p := range ps {
			p.Mediator().GetBlockChainForTest().StartCreatingNewBlocks(headSn.Epoch, nil)
		}

		nextEpoch := headSn.Epoch.NextSession()
		testutils.ExpectProgress(req, 15*time.Second, getMediators(ps), blockchain.NewBlockSn(uint32(nextEpoch.Session), nextEpoch.E, 1))
		commInfo = psVoterGrp1[0].Mediator().GetBlockChainForTest().GetCommInfo(nextEpoch.Session)
		req.Equal(setting.NumVoters+setting.NumAdditionalVoters, len(commInfo.MemberInfo))
	})
}
