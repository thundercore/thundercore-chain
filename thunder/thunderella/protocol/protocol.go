package protocol

import (
	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
)

var (
	// We are using fixed gas limit for Testnet (as opposed to adaptive gas limit in Ethereum).
	// Reconfiguration in live accelerator.
	// Datatype is same as that in ethereum's Header.

	// The value is subject to more tuning.
	// Discussion : THUNDER-53
	BlockGasLimit = config.NewInt64HardforkConfig(
		"protocol.blockGasLimit",
		"Gas limit for fastpath blocks")
)
