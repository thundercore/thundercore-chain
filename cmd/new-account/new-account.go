package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/xerrors"
)

func newAccount() (*ecdsa.PrivateKey, common.Address, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, common.Address{}, xerrors.Errorf("crypto.GenerateKey: %w", err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, common.Address{}, xerrors.Errorf("type assertion:publicKey is not of type *ecdsa.PublicKey: %w", err)
	}

	return privateKey, crypto.PubkeyToAddress(*publicKeyECDSA), nil
}

func main() {
	logger := log.New(os.Stderr, "" /* prefix*/, 0 /*flags*/)
	pk, addr, err := newAccount()
	if err != nil {
		logger.Fatalf("newAccount: %+v", err)
	}
	addrHex := hexutil.Encode(addr[:])
	f, err := os.OpenFile(fmt.Sprintf("%s.hex", addrHex), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		logger.Fatalf("OpenFile: %+v", err)
	}
	defer f.Close()
	pkBytes := crypto.FromECDSA(pk)
	bytes := make([]byte, hex.EncodedLen(len(pkBytes)))
	hex.Encode(bytes, pkBytes)
	f.Write(bytes)
	fmt.Println(addrHex)
}
