package thundervm

import (

	// Thunder imports

	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chain"
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chainconfig"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"

	// Vendor imports
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
)

var (
	logger = lgr.NewLgr("/TPC")

	_commElection   = &commElection{base{logger: logger.NewChildLgr("Elect")}}
	_commElectionR2 = &commElectionR2{base{logger: logger.NewChildLgr("Elect")}}
	_commElectionR3 = &commElectionR3{commElectionR2{base{logger: logger.NewChildLgr("Elect")}}}

	_vault   = &vault{base{logger: logger.NewChildLgr("Vault")}}
	_vaultR2 = &vaultR2{base{logger: logger.NewChildLgr("Vault")}}
	_vaultR3 = &vaultR3{vaultR2: vaultR2{base: base{logger: logger.NewChildLgr("Vault")}}}

	_random               = &random{base{logger: logger.NewChildLgr("Random")}}
	_randomR2P5           = &random2P5{random{base{logger: logger.NewChildLgr("Random")}}}
	_randomV3             = &randomV3{base{logger: logger.NewChildLgr("Random")}}
	_randomV4             = &randomV4{randomV3{base{logger: logger.NewChildLgr("Random")}}}
	_tempRngForCopyChange = &tempRngForCopyChange{base{logger: logger.NewChildLgr("Random")}}

	_blocksn = &thunderBlockSn{base{logger: logger.NewChildLgr("BlockSn")}}

	// list of every hardfork activated precompiled contract (for EVM tracer which does not have access to block number)
	hardforkActiveTPCMap = map[common.Address]vm.PrecompiledThunderContract{
		commElectionAddress: _commElection,
		vaultAddress:        _vault,
		randomAddress:       _random,
		blockSnAddress:      _blocksn}

	commElectionAddress = chainconfig.CommElectionTPCAddress
	vaultAddress        = chainconfig.VaultTPCAddress
	randomAddress       = chainconfig.RandomTPCAddress
	blockSnAddress      = chainconfig.BlockSnTPCAddress
	IsRNGActive         = config.NewBoolHardforkConfig(
		"trustedRNG.rngActive",
		"Trusted rng hardfork activation")
	VerifyBid = config.NewBoolHardforkConfig(
		"committee.verifyBid",
		"The session we begin to verify bids.")
	IsBlockSnGetterActive = config.NewBoolHardforkConfig(
		"precompiled.blockSnGetterActive",
		"Session getter hardfork activation")
	VaultVersion = config.NewStringHardforkConfig(
		"precompiled.vaultVersion",
		"Vault version",
	)
	ElectionVersion = config.NewStringHardforkConfig(
		"committee.electVersion",
		"Committee election version",
	)
)

type base struct {
	logger *lgr.Lgr
}

func precompiledContractsForBlock(evm *vm.EVM) map[common.Address]vm.PrecompiledThunderContract {
	// base maps
	r := map[common.Address]vm.PrecompiledThunderContract{
		commElectionAddress: _commElection,
		vaultAddress:        _vault}

	thunderConfig := evm.ChainConfig().Thunder
	b := chain.Seq(evm.Context.BlockNumber.Uint64())
	s := thunderConfig.GetSessionFromDifficulty(evm.Context.Difficulty, evm.Context.BlockNumber, thunderConfig)

	// update based on hard forks
	if IsRNGActive.GetValueAt(b) {
		if thunderConfig.RNGVersion.GetValueAtSession(int64(s)) == "v4" {
			r[randomAddress] = _randomV4
		} else if thunderConfig.RNGVersion.GetValueAtSession(int64(s)) == "v3" {
			r[randomAddress] = _randomV3
		} else if thunderConfig.RNGVersion.GetValueAtSession(int64(s)) == "testnet-fix-rng-broken" {
			r[randomAddress] = _tempRngForCopyChange
		} else if thunderConfig.IsPala2P5GasTable(s) {
			r[randomAddress] = _randomR2P5
		} else {
			r[randomAddress] = _random
		}
	}

	if IsBlockSnGetterActive.GetValueAtSession(int64(s)) {
		r[blockSnAddress] = _blocksn
	}

	if thunderConfig.ShouldVerifyBid(s) {
		r[vaultAddress] = _vaultR2
		r[commElectionAddress] = _commElectionR2
	}

	if VaultVersion.GetValueAtSession(int64(s)) == "r3" {
		r[vaultAddress] = _vaultR3
	}

	if ElectionVersion.GetValueAtSession(int64(s)) == "r3" {
		r[commElectionAddress] = _commElectionR3
	}

	return r
}

func init() {
	// `vm.PrecompiledContractsThunder` is initialized here to get the package dependencies right.
	vm.PrecompiledContractsThunder = precompiledContractsForBlock
	vm.AllThunderPrecompiledContracts = hardforkActiveTPCMap
}
