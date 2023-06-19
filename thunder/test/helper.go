package test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/xerrors"
)

var genesisKeyHex = "5082363a2d018a10471c49efac549369a716754ca3c4ac2dc49e33ef726ffc4c"

var wei = big.NewInt(1e18)

func ToWei(v *big.Int) *big.Int {
	return new(big.Int).Mul(v, wei)
}

type Account struct {
	Key     *ecdsa.PrivateKey
	Address common.Address
}

func NewGenesisAccount() (*Account, error) {
	key, err := crypto.HexToECDSA(genesisKeyHex)
	if err != nil {
		return nil, xerrors.Errorf("failed to create the private key: %s", err)
	}

	address := crypto.PubkeyToAddress(key.PublicKey)
	return &Account{
		Key:     key,
		Address: address,
	}, nil
}

func SendRawTransaction(c *Client, signer types.Signer,
	key *ecdsa.PrivateKey, nonce uint64, to common.Address, value *big.Int,
	gasLimit uint64, gasPrice *big.Int, data []byte) (*types.Transaction, error) {
	// create raw transaction
	ctx := context.Background()
	from := crypto.PubkeyToAddress(key.PublicKey)

	if gasPrice.Cmp(big.NewInt(0)) == 0 {
		gasPrice, _ = c.SuggestGasPrice(ctx)
	}

	if gasLimit == 0 {
		gasLimit, _ = c.EstimateGas(ctx,
			ethereum.CallMsg{
				From: from,
				To:   &to,
				Data: data,
			})
	}

	if nonce == 0 {
		nonce, _ = c.GetNonce(ctx, from, nil)
	}
	tx := types.NewTx(&types.DynamicFeeTx{
		Nonce:     nonce,
		To:        &to,
		Value:     value,
		Gas:       gasLimit,
		GasFeeCap: gasPrice,
		GasTipCap: gasPrice,
		Data:      data,
	})

	bytes, _ := json.Marshal(tx)
	fmt.Println(string(bytes))
	signedTx, err := types.SignTx(tx, signer, key)
	if err != nil {
		return nil, xerrors.Errorf("failed to sign tx: %s", err)
	}

	if err = c.SendRawTransaction(ctx, signedTx); err != nil {
		return signedTx, xerrors.Errorf("failed to send transaction: %s", err)
	}

	return signedTx, nil
}
