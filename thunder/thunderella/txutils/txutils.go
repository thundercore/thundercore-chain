package txutils

import (
	// Standard imports
	"crypto/ecdsa"
	"math/big"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"

	// Vendor imports
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

var (
	// TODO(thunder): it's not necessary to have a default value. Remove it later.
	defaultGasPrice = big.NewInt(10000100)
)

func MakeSignedTxWithData(from *ecdsa.PrivateKey,
	to *common.Address,
	nonce uint64,
	amount *big.Int,
	chainId *big.Int,
	data []byte,
	gasPrice *big.Int,
) *types.Transaction {

	// TODO DELETE THIS
	if gasPrice == nil {
		gasPrice = defaultGasPrice
		//debug.Bug("must specify gas price")
	}

	txact := MakeTxWithData(nonce, to, amount, data, gasPrice)
	if chainId == nil {
		chainId = params.ThunderChainConfig().ChainID
	}
	signer := types.NewEIP155Signer(chainId)
	signedTx, err := types.SignTx(txact, signer, from)
	if err != nil {
		// TODO(thunder): do not crash the program.
		debug.Bug("Error signing transaction: %s", err)
	}
	return signedTx
}

// helper function to build transactions
func MakeTxWithData(
	nonce uint64,
	to *common.Address,
	amount *big.Int,
	data []byte,
	gasPrice *big.Int,
) *types.Transaction {
	if to != nil {
		// estimate gas limit computation. Will be >= actual cost.
		// See state_transition.go:IntrinsicGas() for proper computation
		// the reason we don't call core.IntrinsicGas is due to circular dependency issue
		// TODO(thunder): let the caller pass the gas.
		gas := params.TxGas + uint64(len(data))*params.TxDataNonZeroGasFrontier
		return types.NewTransaction(nonce, *to, amount, gas, gasPrice, data)
	}
	// same comment as above
	gas := params.TxGasContractCreation + uint64(len(data))*params.TxDataNonZeroGasFrontier
	return types.NewContractCreation(
		nonce, amount, gas, gasPrice, data)
}

func MakeContractRunWithGasLimit(from *ecdsa.PrivateKey,
	to common.Address,
	nonce uint64,
	amount *big.Int,
	data []byte,
	gasLimit uint64,
	gasPrice *big.Int,
) *types.Transaction {
	tx := types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, data)
	chainId := params.ThunderChainConfig().ChainID
	signer := types.NewEIP155Signer(chainId)
	signedTx, err := types.SignTx(tx, signer, from)
	if err != nil {
		// TODO(thunder): do not crash the program.
		debug.Bug("Error signing transaction: %s", err)
	}
	return signedTx
}
