package blockchain

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

type ConsensusTxValidator struct {
	validator core.Validator
}

func WithConsensusTxValidator(validator core.Validator) *ConsensusTxValidator {
	return &ConsensusTxValidator{
		validator: validator,
	}
}

// ValidateBody only expected the last transaction of a block can be underprice.
func (v *ConsensusTxValidator) ValidateBody(block *types.Block) error {
	txs := block.Transactions()
	if len(txs) > 1 {
		for _, tx := range txs[:len(txs)-1] {
			// TODO (thunder): also validate clearing gas price
			if tx.GasPrice().Cmp(common.Big0) == 0 {
				return core.ErrUnderpriced
			}
		}
	}

	return v.validator.ValidateBody(block)
}

func (v *ConsensusTxValidator) ValidateState(block *types.Block, state *state.StateDB, receipts types.Receipts, usedGas uint64) error {
	return v.validator.ValidateState(block, state, receipts, usedGas)
}

type GasPriceGetter interface {
	GetGasPrice() *big.Int
}

func IsInConsensusTx(e params.Evm) bool {
	evm, ok := e.(GasPriceGetter)
	if !ok {
		return false
	}

	return evm.GetGasPrice().Cmp(common.Big0) == 0
}
