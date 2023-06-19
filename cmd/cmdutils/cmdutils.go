package cmdutils

import (
	// Standard imports
	"crypto/ecdsa"
	"errors"
	"math/big"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/web3"

	// Vendor imports
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// a transaction generator contains a connector, signer, and private key.  It performs operations
// that require such things
type Account struct {
	Conn *web3.Web3Connector

	signer  types.Signer
	privKey *ecdsa.PrivateKey
	addr    common.Address
	lgr     *lgr.Lgr
}

func NewAccount(conn *web3.Web3Connector, signer types.Signer, privKey *ecdsa.PrivateKey) *Account {
	if signer == nil || privKey == nil {
		return nil
	}
	acct := &Account{
		signer:  signer,
		privKey: privKey,
		Conn:    conn,
		lgr:     conn.NewChildLgr("Account"),
	}
	acct.addr = crypto.PubkeyToAddress(privKey.PublicKey)
	return acct
}

func (acct *Account) Close() {
	acct.Conn.Close()
}

func (acct *Account) GetPrivateKey() *ecdsa.PrivateKey {
	return acct.privKey
}

func (acct *Account) GetNonce() (uint64, error) {
	return acct.Conn.GetNonce(&acct.addr)
}

func (acct *Account) GetNonceAndIncrement() (uint64, error) {
	return acct.Conn.GetNonceAndIncrement(&acct.addr)
}

func (acct *Account) GetBalance() (*big.Int, error) {
	balance, err := acct.Conn.GetBalance(&acct.addr)
	if err != nil {
		acct.lgr.Error("error getting balance for %s: %s", acct.addr.Hex(), err)
		return nil, err
	}
	return balance, nil
}

func (acct *Account) GetSignedTx(gasLimit uint64, gasPrice *big.Int, amount *big.Int,
	toAddr *common.Address, data []byte,
) (*types.Transaction, error) {
	if acct.privKey == nil {
		return nil, errors.New("private key not specified")
	}
	nonce, err := acct.GetNonceAndIncrement()
	if err != nil {
		// conn logged the error
		return nil, err
	}

	tx := types.NewTransaction(nonce, *toAddr, amount, gasLimit, gasPrice, data)
	signedTx, err := types.SignTx(tx, acct.signer, acct.privKey)
	if err != nil {
		acct.lgr.Error("error signing tx: %s", err)
		return nil, err
	}

	return signedTx, nil
}
