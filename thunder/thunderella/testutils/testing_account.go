package testutils

import (
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	// The corresponding private key to chain.TestnetTestingAddr
	TestingKeyHex = "5082363a2d018a10471c49efac549369a716754ca3c4ac2dc49e33ef726ffc4c"

	// The corresponding private key to chain.TestnetTestingTxStressAddr
	TestingTxStressKeyHex = "645243f2f15b09d2e343e919d01e33755274973b21c917083beb438a6bca5376"
	PSTKeyHex             = "FCD8B370EB179F9BEA4D205C4130AFDEC9EB6A4BBFAF02477EC9C8AFC14BAADC"
	TestingLowValueKeyHex = "7c6b0146c2edc783d521c8dbae39aa31090dd9a4f1f393d0173cd8d76e6d2b4d"
)

var (
	TestingKey          *ecdsa.PrivateKey
	TestingAddr         common.Address
	TestingTxStressKey  *ecdsa.PrivateKey
	TestingTxStressAddr common.Address
	TestingLowValueKey  *ecdsa.PrivateKey
	TestingLowValueAddr common.Address
	PSTKey              *ecdsa.PrivateKey
	PSTAddr             common.Address
)

func init() {
	var err error
	TestingKey, err = crypto.HexToECDSA(TestingKeyHex)
	if err != nil {
		debug.Fatal("priv key error")
	}
	TestingAddr = crypto.PubkeyToAddress(TestingKey.PublicKey)

	TestingLowValueKey, err = crypto.HexToECDSA(TestingLowValueKeyHex)
	if err != nil {
		debug.Fatal("priv key error")
	}
	TestingLowValueAddr = crypto.PubkeyToAddress(TestingLowValueKey.PublicKey)

	TestingTxStressKey, err = crypto.HexToECDSA(TestingTxStressKeyHex)
	if err != nil {
		debug.Fatal("priv key error")
	}
	TestingTxStressAddr = crypto.PubkeyToAddress(TestingTxStressKey.PublicKey)

	PSTKey, err = crypto.HexToECDSA(PSTKeyHex)
	if err != nil {
		debug.Fatal("priv key error")
	}
	PSTAddr = crypto.PubkeyToAddress(PSTKey.PublicKey)
}
