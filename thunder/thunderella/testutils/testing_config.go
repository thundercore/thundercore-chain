package testutils

import (
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"
)

func NewElectionStopBlockSessionOffsetForTest(offset, sessionNum int64) *config.Int64HardforkConfig {
	utils.EnsureRunningInTestCode()

	sessionOffsetForTest := config.NewInt64HardforkConfig("test.blockchain.stopBlockOffset", "")
	sessionOffsetForTest.SetTestValueAtSession(offset, sessionNum)
	return sessionOffsetForTest
}
