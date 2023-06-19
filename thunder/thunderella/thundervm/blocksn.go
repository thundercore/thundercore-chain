package thundervm

import (
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

type thunderBlockSn struct {
	base
}

func (r *thunderBlockSn) RequiredGas(input []byte) uint64 {
	return params.Pala2P5Calls
}

func (r *thunderBlockSn) Run(input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	// Adhering to the vault's run implementation
	r.logger.Debug("received tx from %s with payload length %d",
		contract.Caller().Hex(), len(input))
	output, err := r.call(evm, contract)
	if err != nil {
		r.logger.Debug("Get consensus session execution failed, err = %v", err)
		return nil, vm.ErrExecutionReverted
	}

	return output, nil
}

func (r *thunderBlockSn) call(evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	thunderConfig := evm.ChainConfig().Thunder
	sess, e, s := thunderConfig.GetBlockSnFromDifficulty(evm.Context.Difficulty, evm.Context.BlockNumber, thunderConfig)

	uint256Sess := new(uint256.Int).SetUint64(uint64(sess))
	uint256E := new(uint256.Int).SetUint64(uint64(e))
	uint256S := new(uint256.Int).SetUint64(uint64(s))

	sessByte32 := uint256Sess.Bytes32()
	eByte32 := uint256E.Bytes32()
	sByte32 := uint256S.Bytes32()

	ret := []byte{}
	ret = append(ret, sessByte32[:]...)
	ret = append(ret, eByte32[:]...)
	ret = append(ret, sByte32[:]...)

	return ret[:], nil
}
