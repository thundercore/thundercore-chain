package server

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/testutils"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	config.InitHardforkConfig("../../../config")
	os.Exit(m.Run())
}

func TestEthRpcGetFreshNotarizedHead(t *testing.T) {
	req := require.New(t)

	port := testutils.NextTestingPort(testutils.TestGroupServer)
	nodeConfig := &NodeConfig{
		Version:           "test_rpc",
		DataDir:           "", /* Use memdb here */
		RpcListenHostname: "127.0.0.1",
		RpcListenPort:     int64(port),
	}

	hardforkCfg := blockchain.InitHardforkValueForTest()

	ethConfig := &EthConfig{
		NoPruning:   true,
		GenesisPath: "",
		HardforkCfg: hardforkCfg,
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

	ethBackend, err := StartNode(nodeConfig, ethConfig)
	req.NoError(err)
	thunderConfig := ethBackend.BlockChain().Config().Thunder

	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(2, 0)

	cg := blockchain.NewChainGeneratorByEthBackend(ethBackend, hardforkK)
	// (1,1,1)->(1,1,2)->(1,1,3)->(1,1,4)->(1,1,5)->(1,1,6)
	// K=2, frestest notarized head = 1,1,4
	err = cg.Init(blockchain.NewBlockSn(1, 1, 6))
	req.NoError(err)

	client, err := ethclient.Dial(fmt.Sprintf("http://127.0.0.1:%s", strconv.Itoa(port)))
	req.NoError(err)
	b1, err := client.BlockByNumber(context.Background(), big.NewInt(4))
	req.NoError(err)
	sn1 := blockchain.GetBlockSnFromDifficulty(b1.Header().Difficulty, b1.Header().Number, thunderConfig)
	req.Equal(sn1.String(), "(1,1,4)")

	// (1,1,1)->(1,1,2)->(1,1,3)->(1,1,4)->(1,1,5)->(1,1,6)
	//                      |
	//                      ----->(1,2,1)->(1,2,2)->(1,2,3)
	// K=2, frestest notarized head = 1,2,1
	err = cg.Branch(blockchain.NewBlockSn(1, 1, 3), blockchain.NewBlockSn(1, 2, 3))
	req.NoError(err)
	b2, err := client.BlockByNumber(context.Background(), big.NewInt(4))
	req.NoError(err)
	sn2 := blockchain.GetBlockSnFromDifficulty(b2.Header().Difficulty, b2.Header().Number, thunderConfig)
	req.Equal(sn2.String(), "(1,2,1)")
}

func TestEthRpcGetPastLogMax15000(t *testing.T) {
	req := require.New(t)

	port := testutils.NextTestingPort(testutils.TestGroupServer)
	nodeConfig := &NodeConfig{
		Version:           "test_rpc",
		DataDir:           "", /* Use memdb here */
		RpcListenHostname: "127.0.0.1",
		RpcListenPort:     int64(port),
	}

	var electionOffsetForTest = config.NewInt64HardforkConfig(
		"server.unused.value", "")
	var proposerListNameForTest = config.NewStringHardforkConfig(
		"server.unused.value2", "")
	var maxCodeSizeForTest = config.NewInt64HardforkConfig(
		"server.unused.value3", "")
	var gasTableForTest = config.NewStringHardforkConfig(
		"setver.unused.value4", "")
	var rewardSchemeForTest = config.NewStringHardforkConfig(
		"server.unused.value5", "")
	var isConsensusInHeaderForTest = config.NewBoolHardforkConfig(
		"server.unused.value6", "")
	var RNGVersionForTest = config.NewStringHardforkConfig(
		"server.unused.value7", "")
	var basefeeForTest = config.NewBigIntHardforkConfig(
		"server.unused.value8", "")
	proposerListNameForTest.SetTestValueAtSession("", 0)
	electionOffsetForTest.SetTestValueAt(100000000, 0)
	rewardSchemeForTest.SetTestValueAtSession("thunderella", 0)
	maxCodeSizeForTest.SetTestValueAtSession(100000, 0)
	gasTableForTest.SetTestValueAt("pala-r2.1", 0)
	isConsensusInHeaderForTest.SetTestValueAtSession(false, 0)
	RNGVersionForTest.SetTestValueAtSession("v1", 0)
	basefeeForTest.SetTestValueAtSession(big.NewInt(0), 0)
	// Use this value for tests that we don't care about the stop block.

	ethConfig := &EthConfig{
		NoPruning:   true,
		GenesisPath: "",
		HardforkCfg: &blockchain.HardforkCfg{
			PalaBlock:               common.Big1,
			ProposerListName:        proposerListNameForTest,
			ElectionStopBlockOffset: electionOffsetForTest,
			RewardScheme:            rewardSchemeForTest,
			GasTable:                gasTableForTest,
			IsConsensusInfoInHeader: isConsensusInHeaderForTest,
			RNGVersion:              RNGVersionForTest,
			BaseFee:                 basefeeForTest,
		},
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
		MaxRpcLogsBlockRange: 15000,
		TxLookupLimit:        0,
	}

	_, err := StartNode(nodeConfig, ethConfig)
	req.NoError(err)

	client, err := ethclient.Dial(fmt.Sprintf("http://127.0.0.1:%s", strconv.Itoa(port)))
	req.NoError(err)

	filter := ethereum.FilterQuery{
		FromBlock: big.NewInt(0),
		ToBlock:   big.NewInt(15000),
	}

	// normal case, should complete without any error
	_, err = client.FilterLogs(context.Background(), filter)
	req.NoError(err)

	filter.ToBlock = big.NewInt(15001)

	// request log with block range over 1500 should failed
	_, err = client.FilterLogs(context.Background(), filter)
	assert.EqualError(t, err, "exceed maximum block range: 15000")

	// block range constraint only apply when ToiBlock is greater thant FromBlock
	filter.FromBlock = big.NewInt(5000)
	filter.ToBlock = big.NewInt(2000)

	_, err = client.FilterLogs(context.Background(), filter)
	req.NoError(err)
}

func TestEthRpcGetPastLogUnlimited(t *testing.T) {
	req := require.New(t)

	port := testutils.NextTestingPort(testutils.TestGroupServer)
	nodeConfig := &NodeConfig{
		Version:           "test_rpc",
		DataDir:           "", /* Use memdb here */
		RpcListenHostname: "127.0.0.1",
		RpcListenPort:     int64(port),
	}

	var electionOffsetForTest = config.NewInt64HardforkConfig(
		"server.unused.value", "")
	var proposerListNameForTest = config.NewStringHardforkConfig(
		"server.unused.value2", "")
	var maxCodeSizeForTest = config.NewInt64HardforkConfig(
		"server.unused.value3", "")
	var gasTableForTest = config.NewStringHardforkConfig(
		"setver.unused.value4", "")
	var rewardSchemeForTest = config.NewStringHardforkConfig(
		"server.unused.value5", "")
	var isConsensusInHeaderForTest = config.NewBoolHardforkConfig(
		"server.unused.value6", "")
	var RNGVersionForTest = config.NewStringHardforkConfig(
		"server.unused.value7", "")
	var basefeeForTest = config.NewBigIntHardforkConfig(
		"server.unused.value8", "")
	proposerListNameForTest.SetTestValueAtSession("", 0)
	electionOffsetForTest.SetTestValueAt(100000000, 0)
	rewardSchemeForTest.SetTestValueAtSession("thunderella", 0)
	maxCodeSizeForTest.SetTestValueAtSession(100000, 0)
	gasTableForTest.SetTestValueAt("pala-r2.1", 0)
	isConsensusInHeaderForTest.SetTestValueAtSession(false, 0)
	RNGVersionForTest.SetTestValueAtSession("v1", 0)
	basefeeForTest.SetTestValueAtSession(big.NewInt(0), 0)
	// Use this value for tests that we don't care about the stop block.

	ethConfig := &EthConfig{
		NoPruning:   true,
		GenesisPath: "",
		HardforkCfg: &blockchain.HardforkCfg{
			PalaBlock:               common.Big1,
			ProposerListName:        proposerListNameForTest,
			ElectionStopBlockOffset: electionOffsetForTest,
			RewardScheme:            rewardSchemeForTest,
			GasTable:                gasTableForTest,
			IsConsensusInfoInHeader: isConsensusInHeaderForTest,
			RNGVersion:              RNGVersionForTest,
			BaseFee:                 basefeeForTest,
		},
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
		MaxRpcLogsBlockRange: -1,
		TxLookupLimit:        0,
	}

	_, err := StartNode(nodeConfig, ethConfig)
	req.NoError(err)

	client, err := ethclient.Dial(fmt.Sprintf("http://127.0.0.1:%s", strconv.Itoa(port)))
	req.NoError(err)

	filter := ethereum.FilterQuery{
		FromBlock: big.NewInt(0),
		ToBlock:   big.NewInt(200000),
	}

	// normal case, should complete without any error
	_, err = client.FilterLogs(context.Background(), filter)
	req.NoError(err)

	// block range constraint only apply when ToiBlock is greater thant FromBlock
	filter.FromBlock = big.NewInt(5000)
	filter.ToBlock = big.NewInt(2000)

	_, err = client.FilterLogs(context.Background(), filter)
	req.NoError(err)
}
