package thundervm

import (
	"bytes"
	"math/big"
	"sort"

	// Thunder

	"github.com/ethereum/go-ethereum/thunder/thunderella/election"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	// Vendor imports
)

// StakeMsgToBidCall marshals a stake message into a Ethereum ABI call to ETPC.bid
func StakeMsgToBidCall(stakeInfo *election.StakeInfo) ([]byte, error) {
	return ElectionABI.Pack("bid",
		stakeInfo.Coinbase,
		&stakeInfo.Stake,
		&stakeInfo.GasPrice,
		stakeInfo.PubVoteKey.ToBytes(),
		stakeInfo.RefundID,
	)
}

// StakeMsgToVaultBidCall marshals a stake message into a Ethereum ABI call to VaultTPC.bid
func StakeMsgToVaultBidCall(stakeInfo *election.StakeInfo) ([]byte, error) {
	return VaultABI.Pack("bid",
		stakeInfo.Coinbase,
		&stakeInfo.Stake,
		&stakeInfo.GasPrice,
		stakeInfo.PubVoteKey.ToBytes(),
	)
}

func StakeMsgToBidCallR2(stakeInfo *election.SignedStakeInfo) ([]byte, error) {
	return ElectionR2ABI.Pack("bid",
		stakeInfo.Coinbase,
		stakeInfo.Stake,
		stakeInfo.GasPrice,
		stakeInfo.PubVoteKey.ToBytes(),
		stakeInfo.Session,
		stakeInfo.Nonce,
		stakeInfo.Sig.ToBytes(),
		stakeInfo.RefundID,
	)
}

func StakeMsgToVaultBidCallR2(stakeInfo *election.SignedStakeInfo) ([]byte, error) {
	return VaultR2ABI.Pack("bid",
		stakeInfo.Coinbase,
		stakeInfo.Stake,
		stakeInfo.GasPrice,
		stakeInfo.PubVoteKey.ToBytes(),
		stakeInfo.Session,
		stakeInfo.Nonce,
		stakeInfo.Sig.ToBytes(),
	)
}

func GetCurrentBids(state vm.StateDB) ([]*election.StakeInfo, error) {
	bm := StakeMessages(state)

	keys := bm.Keys()

	stakeInfos := make([]*election.StakeInfo, len(keys))

	for i, k := range keys {
		stakeInfos[i] = &election.StakeInfo{}

		err := bm.FindEntry(k, stakeInfos[i])

		if err != nil {
			debug.Bug("StakeMessageTable broken.")
		}
	}

	return stakeInfos, nil
}

func GetAvailableElectionStake(state vm.StateDB, addr common.Address, refundID []byte) *big.Int {
	freezerTable := NewByteMap(commElectionAddress, state, electionFreezerTablePrefix)
	stakeTable := NewByteMap(commElectionAddress, state, electionStakeTablePrefix)

	var staked, frozen stakeValue
	key := makeRefundKey(addr, refundID)
	err1 := freezerTable.FindEntry(key, &frozen)
	err2 := stakeTable.FindEntry(key, &staked)

	output := big.NewInt(0)
	if err1 == nil {
		output.Add(output, frozen.Value)
	}
	if err2 == nil {
		output.Add(output, staked.Value)
	}

	return output
}

// makeRefundKey: (stakingAddr, refundInfo) -> key
func makeRefundKey(addr common.Address, input []byte) string {
	s := append(addr.Bytes(), input...)
	return string(s)
}

// getRefundAddress: (key) -> refundAddress
func getRefundAddress(key string) common.Address {
	bytes := []byte(key)
	return common.BytesToAddress(bytes[:20])
}

// getRefundInput: (key) -> refundID
func getRefundInput(key string) []byte {
	bytes := []byte(key)
	return bytes[20:]
}

// unfreezeStake adds stake from freezerTable to stakeTable
func unfreezeStake(stakeTable, freezerTable, freezerIndex *ByteMap) {
	keys := freezerTable.Keys()

	for _, key := range keys {
		var frozen, current stakeValue
		err := freezerTable.FindEntry(key, &frozen)
		if err != nil {
			debug.Bug("freezerTable broken.")
		}

		err = stakeTable.FindEntry(key, &current)
		if err != nil {
			current.Value = big.NewInt(0)
		}
		current.Value.Add(current.Value, frozen.Value)
		stakeTable.InsertOrReplaceEntry(key, &current)
	}
	// current implementation guarantees that freezer table will have all value transferred out of it at this point (assuming no refund txs fail, but that's the user's problem)  so it's safe to clear the list here.
	freezerTable.Clear()
	freezerIndex.Clear()
}

// freezeStake will move required stake from the stakeTable to freezerTable
// if there is insufficient stake, freezeStake will return false
// freezeStake will map refundKey to voting key in the freezerIndex ByteMap as well which may eventually be used for punishment in some future version (currently unused)
func freezeStake(stakeTable, freezerTable, freezerIndex *ByteMap, s *election.StakeInfo) bool {
	key := makeRefundKey(s.StakingAddr, s.RefundID)

	var current, frozen stakeValue
	err := stakeTable.FindEntry(key, &current)
	if err != nil {
		return false
	}

	if s.Stake.Cmp(current.Value) > 0 {
		return false
	}

	err = freezerTable.FindEntry(key, &frozen)
	if err != nil {
		frozen.Value = big.NewInt(0)
	}
	current.Value.Sub(current.Value, s.Stake)
	frozen.Value.Add(frozen.Value, s.Stake)

	stakeTable.InsertOrReplaceEntry(key, &current)
	freezerTable.InsertOrReplaceEntry(key, &frozen)

	freezeKey := string(s.PubVoteKey.ToBytes())
	index := frozenIndex(key)
	freezerIndex.InsertOrReplaceEntry(freezeKey, &index)

	return true
}

func freezeStakeBound(stakeTable, freezerTable, freezerIndex *ByteMap) func(s *election.StakeInfo) bool {
	return func(s *election.StakeInfo) bool {
		return freezeStake(stakeTable, freezerTable, freezerIndex, s)
	}
}

// clear stake table
func refundAll(evm *vm.EVM, contract *vm.Contract, stakeTable *ByteMap) {
	keys := stakeTable.Keys()

	for _, key := range keys {
		var current stakeValue
		err := stakeTable.FindEntry(key, &current)
		if err != nil {
			debug.Bug("stakeTable broken.")
		}

		// we chose len(key) because len(key) < len(StakeMsg) and len(key) < len(unique)
		// and gas of bid() should be gasByteMapInsert(len(uniqueKey), len(StakeMsg))
		// it MUST be the case that refund gas < bid gas otherwise it is possible to get free gas
		// from refund() after bidding
		gasLimit := gasByteMapInsert(len(key), len(key))

		// EVM INVARIANT BREAKING
		// fake the gas in the contract
		contract.Gas = gasLimit
		_, err = evmCompatibleCall(evm, contract, getRefundAddress(key), getRefundInput(key), current.Value, gasLimit)

		// if refund value is 0, maybe we can skip the CALL?
		if current.Value.Sign() != 0 {
			logger.Info("Refund to %s value %v with err %v", getRefundAddress(key).Hex(),
				current.Value, err)
		}
	}

	// EVM INVARIANT BREAKING
	// PST costs 0 gas, so contract.Gas should be 0 coming into this function
	// lets make sure it's 0 going out of this function too :)
	contract.Gas = 0

	stakeTable.Clear()
}

func safeRefundAll(evm *vm.EVM, contract *vm.Contract, stakeTable *ByteMap) {
	keys := stakeTable.Keys()

	for _, key := range keys {
		var current stakeValue
		err := stakeTable.FindEntry(key, &current)
		if err != nil {
			debug.Bug("stakeTable broken.")
		}

		// we chose len(key) because len(key) < len(StakeMsg) and len(key) < len(unique)
		// and gas of bid() should be gasByteMapInsert(len(uniqueKey), len(StakeMsg))
		// it MUST be the case that refund gas < bid gas otherwise it is possible to get free gas
		// from refund() after bidding
		gasLimit := gasByteMapInsert(len(key), len(key))

		// EVM INVARIANT BREAKING
		// fake the gas in the contract
		contract.Gas = gasLimit

		refundAddress := getRefundAddress(key)
		refundInput := getRefundInput(key)

		isContract := len(evm.StateDB.GetCode(refundAddress)) != 0

		// only refund to plan address or vault contract address
		if refundAddress == vaultAddress || !isContract {
			_, err = evmCompatibleCall(evm, contract, refundAddress, refundInput, current.Value, gasLimit)
		} else {
			if current.Value.Sign() != 0 && !evm.Context.CanTransfer(evm.StateDB, contract.Address(), current.Value) {
				err = vm.ErrInsufficientBalance
			} else {
				evm.Context.Transfer(evm.StateDB, contract.Address(), refundAddress, current.Value)
			}
		}

		// if refund value is 0, maybe we can skip the CALL?
		if current.Value.Sign() != 0 {
			logger.Info("Refund to %s value %v with err %v", getRefundAddress(key).Hex(),
				current.Value, err)
		}
	}

	// EVM INVARIANT BREAKING
	// PST costs 0 gas, so contract.Gas should be 0 coming into this function
	// lets make sure it's 0 going out of this function too :)
	contract.Gas = 0

	stakeTable.Clear()
}

// GetCurrentElectionResult returns the current election result if one exists otherwise nil.
func GetCurrentElectionResult(state vm.StateDB) *election.Result {
	// TODO maybe better to use Ethereum ABI interface to get this data instead of
	// reading it directly out of the StateDB
	raw := ElectionResults(state).ToSlice()
	if len(raw) == 0 {
		return nil
	}

	result := election.Result{}
	err := result.FromBytes(raw[0])
	if err != nil {
		debug.Fatal("GetCurrentElectionResult error: %v", err)
	}
	return &result
}

func SetCurrentElectionResult(state vm.StateDB, result *election.Result) {
	// THUNDER-490: Sort committees based PubVoteKey, so the output will be same if bidder arguments
	// are the same whatever the orders of bidder TXs
	sort.Slice(result.Members, func(i, j int) bool {
		return bytes.Compare(result.Members[i].PubVoteKey.ToBytes(),
			result.Members[j].PubVoteKey.ToBytes()) == -1
	})
	bl := ElectionResults(state)
	bl.Clear()
	bl.Append(result.ToBytes())
}

func evmCompatibleCall(evm *vm.EVM, contract *vm.Contract, addr common.Address, input []byte, value *big.Int, gas uint64) (ret []byte, err error) {
	// NOTE: EVM.Call() assuming code only reverted or out of gas issue.
	// If EVM.run() returns other error than ErrExecutionReverted, the Gas would be taken,
	// We should change the returning error code of our precompiled contract, if there is any.
	var returnGas uint64

	if !contract.UseGas(gas) {
		return nil, vm.ErrOutOfGas
	}
	ret, returnGas, err = evm.Call(contract, addr, input, gas, value)

	contract.Gas += returnGas

	return ret, err
}

func evmABICall(evm *vm.EVM, contract *vm.Contract, addr common.Address, value *big.Int, gas uint64, method *abi.Method, args ...interface{}) (ret []byte, err error) {
	packedArgs, err := method.Inputs.Pack(args...)

	if err != nil {
		return nil, err
	}

	input := append(method.ID, packedArgs...)

	return evmCompatibleCall(evm, contract, addr, input, value, gas)
}

func IsTxPST(tx *types.Transaction) bool {
	if tx == nil {
		return false
	}
	if tx.To() == nil {
		return false
	}
	// PST goes to ETPC address
	if *tx.To() != commElectionAddress {
		return false
	}
	// PST has empty payload
	if len(tx.Data()) != 0 {
		return false
	}
	return true
}
