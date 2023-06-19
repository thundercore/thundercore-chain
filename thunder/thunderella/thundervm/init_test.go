package thundervm

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
)

var (
	auctionStakeOverMinStakeRatio = int64(12)
)

func TestMain(m *testing.M) {
	minBidderStake := big.NewInt(5000)
	blkNumSettings := []config.BlockNumSetting{
		config.NewBlockNumSetting("pala.hardfork", false, 0),
		config.NewBlockNumSetting("pala.hardfork", true, 1),
		config.NewBlockNumSetting("trustedRNG.rngActive", false, 0),
		config.NewBlockNumSetting("trustedRNG.rngActive", true, 5),
		config.NewBlockNumSetting("committee.minBidderStake", minBidderStake, config.InitialBlockNum),
		config.NewBlockNumSetting("committee.minGasBidPrice", ScientificBigIntParse("1e+7"), config.InitialBlockNum),
		config.NewBlockNumSetting("committee.minCommitteeSize", 1, config.InitialBlockNum),
		config.NewBlockNumSetting("committee.expectedCommSize", 4, config.InitialBlockNum),
		config.NewBlockNumSetting("committee.electionScheme", "TotalStakeThreshold", config.InitialBlockNum),
		config.NewBlockNumSetting("committee.AuctionStakeThreshold", new(big.Int).Mul(minBidderStake, big.NewInt(auctionStakeOverMinStakeRatio)), config.InitialBlockNum),
		config.NewBlockNumSetting("vault.burnReward", false, config.InitialBlockNum),
	}

	sessionSettings := []config.SessionSetting{
		config.NewSessionSetting("committee.verifyBid", false, 0),
		config.NewSessionSetting("committee.verifyBid", true, 5),
		config.NewSessionSetting("committee.minBidderStake", minBidderStake, 0),
		config.NewSessionSetting("committee.minGasBidPrice", ScientificBigIntParse("1e+7"), 0),
		config.NewSessionSetting("committee.electionScheme", "TotalStakeThreshold", 0),
		config.NewSessionSetting("committee.AuctionStakeThreshold", new(big.Int).Mul(minBidderStake, big.NewInt(auctionStakeOverMinStakeRatio)), 0),
		config.NewSessionSetting("committee.minCommitteeSize", 1, 0),
		config.NewSessionSetting("committee.expectedCommSize", 4, 0),
		config.NewSessionSetting("vault.burnReward", false, 0),
	}

	config.SetHardfork(config.RequiredSettings{
		BlockGasLimit: ScientificBigIntParse("1e+8").Int64(),
	}, blkNumSettings, sessionSettings)

	fmt.Println("Test thundervm without berlin hardfork enabled")
	londonHardorkSession = 65535
	m.Run()

	fmt.Println("Test thundervm with berlin hardfork enabled")
	londonHardorkSession = 0
	m.Run()
}

func ScientificBigIntParse(s string) *big.Int {
	v, err := config.SimpleScientificBigIntParse(s)
	if err != nil {
		debug.Fatal("%s", err)
	}
	return v
}
