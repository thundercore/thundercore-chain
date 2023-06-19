package thundervm

import (
	"github.com/ethereum/go-ethereum/thunder/thunderella/election"

	"github.com/ethereum/go-ethereum/core/vm"
)

// electionR2ABIjson is created by https://remix.ethereum.org with contract like that
// contract CSTPCABI {
//    function bid(address rewardAddress, uint256 stake, uint256 gasPrice, bytes votePubKey, uint session, uint nonce, bytes sig, bytes refundID) {}
//    function getAvailableStake(bytes refundID) view returns(int) {}
//    function getNonce(bytes32 key) view returns(uint) {}
// }
//

type commElectionR3 struct {
	commElectionR2
}

func (e *commElectionR3) Run(input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	if len(input) == 0 {
		return e.elect(evm, contract)
	}

	if len(input) < 4 {
		return nil, vm.ErrExecutionReverted
	}

	id := input[:4]
	arg := input[4:]

	method, err := ElectionR2ABI.MethodById(id)
	if err != nil {
		return nil, vm.ErrExecutionReverted
	}

	ret, err := e.commElectionR2.call(method, arg, evm, contract)

	if err != nil {
		return nil, vm.ErrExecutionReverted
	}

	return ret, nil
}

func (e *commElectionR3) elect(evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	if !evm.ChainConfig().Thunder.IsInConsensusTx(evm) {
		return nil, vm.ErrExecutionReverted
	}

	if evm.Origin != contract.Caller() {
		return nil, vm.ErrExecutionReverted
	}

	state := evm.StateDB
	stakeTable := NewByteMap(commElectionAddress, state, electionStakeTablePrefix)
	freezerTable := NewByteMap(commElectionAddress, state, electionFreezerTablePrefix)
	freezerIndex := NewByteMap(commElectionAddress, state, electionFreezerIndexPrefix)

	unfreezeStake(stakeTable, freezerTable, freezerIndex)

	currentBids, err := GetCurrentBids(state)
	if err != nil {
		return nil, vm.ErrExecutionReverted
	}

	session := evm.ChainConfig().Thunder.GetSessionFromDifficulty(evm.Context.Difficulty, evm.Context.BlockNumber, evm.ChainConfig().Thunder)
	// run the election and move funds from stake table to freezer table
	result := election.ElectR3(currentBids,
		freezeStakeBound(stakeTable, freezerTable, freezerIndex),
		int64(session))

	if result == nil {
		e.logger.Warn("Election failed")
		return nil, vm.ErrExecutionReverted
	}

	SetCurrentElectionResult(state, result)
	safeRefundAll(evm, contract, stakeTable)

	// refund() should not have enough gas to call bid() meaning it's impossible for the stake message
	// map to change before/after refundAll() above. Still, we clear after refundAll() to follow
	// smart contract coding conventions.
	StakeMessages(state).Clear()
	Nonces(state).Clear()

	return nil, nil
}
