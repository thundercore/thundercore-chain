package thundervm

// #cgo LDFLAGS: -L/usr/local/lib/thunder -lrng -Wl,-rpath,/usr/local/lib/thunder
// #cgo CFLAGS: -I/usr/local/include/thunder
// #include "librng.h"
// #include <stdlib.h>
import "C"
import (
	"math/big"
	"unsafe"

	// Thunder imports

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
)

// NOTE: THIS RNG IS A TEMPORARY VERION ONLY USED FOR FIXING THE BEHAVIOR CHANGE OF `Copy()`
// reference: https://thundercore.atlassian.net/browse/THUNDER-1179
type tempRngForCopyChange struct {
	base
}

func (r *tempRngForCopyChange) RequiredGas(input []byte) uint64 {
	return (params.Sha256BaseGas + params.Sha256PerWordGas*2 + params.Pala2P5SLoad + params.SstoreResetGas) * 6 / 5
}

func (r *tempRngForCopyChange) Run(input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	// Adhering to the vault's run implementation
	r.logger.Debug("received tx from %s with payload length %d",
		contract.Caller().Hex(), len(input))
	output, err := r.call(evm, contract)
	if err != nil {
		r.logger.Debug("Generate random execution failed, err = %v", err)
		return nil, vm.ErrExecutionReverted
	}

	return output, nil
}

func (r *tempRngForCopyChange) call(evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	return r.abiGenerateRNG(evm), nil
}

func (r *tempRngForCopyChange) abiGenerateRNG(evm *vm.EVM) []byte {
	// Get and store state in statedb
	nonceToStore := evm.StateDB.GetState(randomAddress, lookupHash)
	r.logger.Debug("Nonce is: %s", nonceToStore.Hex())

	var updatedNonce *big.Int
	if emptyHash(nonceToStore) {
		updatedNonce = big.NewInt(1)
	} else {
		updatedNonce = nonceToStore.Big()
		updatedNonce.Add(updatedNonce, big.NewInt(1))
	}
	evm.StateDB.SetState(randomAddress, lookupHash, common.BigToHash(updatedNonce))

	root := evm.StateDB.CopyOfIntermediateRoot(false)
	randomNumber := generateRandomV3(evm.Context.MixDigest, updatedNonce, root)

	r.logger.Debug("Random number is %s", common.BytesToAddress(randomNumber[:]).Hex())
	return randomNumber[:]
}

type randomV5 struct {
	randomV3
}

func (r *randomV5) RequiredGas(input []byte) uint64 {
	return r.randomV3.RequiredGas(input) * params.RNGGasBumpV5
}

type randomV4 struct {
	randomV3
}

func (r *randomV4) RequiredGas(input []byte) uint64 {
	return r.randomV3.RequiredGas(input) * params.RNGGasBumpV4
}

type randomV3 struct {
	base
}

func (r *randomV3) RequiredGas(input []byte) uint64 {
	return (params.Sha256BaseGas + params.Sha256PerWordGas*2 + params.Pala2P5SLoad + params.SstoreResetGas) * 6 / 5
}

func (r *randomV3) Run(input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	// Adhering to the vault's run implementation
	r.logger.Debug("received tx from %s with payload length %d",
		contract.Caller().Hex(), len(input))
	output, err := r.call(evm, contract)
	if err != nil {
		r.logger.Debug("Generate random execution failed, err = %v", err)
		return nil, vm.ErrExecutionReverted
	}

	return output, nil
}

func (r *randomV3) call(evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	return r.abiGenerateRNG(evm), nil
}

func (r *randomV3) abiGenerateRNG(evm *vm.EVM) []byte {
	// Get and store state in statedb
	nonceToStore := evm.StateDB.GetState(randomAddress, lookupHash)
	r.logger.Debug("Nonce is: %s", nonceToStore.Hex())

	var updatedNonce *big.Int
	if emptyHash(nonceToStore) {
		updatedNonce = big.NewInt(1)
	} else {
		updatedNonce = nonceToStore.Big()
		updatedNonce.Add(updatedNonce, big.NewInt(1))
	}
	evm.StateDB.SetState(randomAddress, lookupHash, common.BigToHash(updatedNonce))

	// We use legacy copy by default because the changes of Copy function will break the consensus.
	root := evm.StateDB.CopyOfIntermediateRoot(true)
	randomNumber := generateRandomV3(evm.Context.MixDigest, updatedNonce, root)

	r.logger.Debug("Random number is %s", common.BytesToAddress(randomNumber[:]).Hex())
	return randomNumber[:]
}

type random2P5 struct {
	random
}

func (r *random2P5) RequiredGas(input []byte) uint64 {
	return params.Sha256BaseGas + params.Sha256PerWordGas*2 + params.Pala2P5SLoad + params.SstoreResetGas
}

type random struct {
	base
}

var (
	// just store nonce at location 0
	lookupHash = common.Hash{}
)

// Gas cost set to sha3 hash gas cost for this function call.
func (r *random) RequiredGas(input []byte) uint64 {
	return params.Sha256BaseGas + params.Sha256PerWordGas*2 + params.SloadGas + params.SstoreResetGas
}

// Run the TPC
func (r *random) Run(input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	// Adhering to the vault's run implementation
	r.logger.Debug("received tx from %s with payload length %d",
		contract.Caller().Hex(), len(input))
	output, err := r.call(evm, contract)
	if err != nil {
		r.logger.Debug("Generate random execution failed, err = %v", err)
		return nil, vm.ErrExecutionReverted
	}

	return output, nil
}

func (r *random) call(evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	return r.abiGenerateRNG(evm), nil
}

func (r *random) abiGenerateRNG(evm *vm.EVM) []byte {
	// Get and store state in statedb
	nonceToStore := evm.StateDB.GetState(randomAddress, lookupHash)
	r.logger.Debug("Nonce is: %s", nonceToStore.Hex())

	var updatedNonce *big.Int
	if emptyHash(nonceToStore) {
		updatedNonce = big.NewInt(1)
	} else {
		updatedNonce = nonceToStore.Big()
		updatedNonce.Add(updatedNonce, big.NewInt(1))
	}
	evm.StateDB.SetState(randomAddress, lookupHash, common.BigToHash(updatedNonce))
	randomNumber := generateRandomV1(evm.Context.MixDigest, updatedNonce)

	r.logger.Debug("Random number is %s", common.BytesToAddress(randomNumber[:]).Hex())
	return randomNumber[:]
}

func emptyHash(h common.Hash) bool {
	return h == common.Hash{}
}

func generateRandomV1(mixDigest common.Hash, updatedNonce *big.Int) []byte {
	digest := C.GoSlice{
		data: C.CBytes(mixDigest.Bytes()),
		len:  C.GoInt(len(mixDigest.Bytes())),
		cap:  C.GoInt(len(mixDigest.Bytes())),
	}

	nonce := C.GoSlice{
		data: C.CBytes(updatedNonce.Bytes()),
		len:  C.GoInt(len(updatedNonce.Bytes())),
		cap:  C.GoInt(len(updatedNonce.Bytes())),
	}

	retBytes := C.RandomV1(digest, nonce)
	randomNumber := C.GoBytes(retBytes, 32)

	C.free(unsafe.Pointer(digest.data))
	C.free(unsafe.Pointer(nonce.data))

	return randomNumber
}

func generateRandomV3(mixDigest common.Hash, updatedNonce *big.Int, intermediateRoot common.Hash) []byte {
	digest := C.GoSlice{
		data: C.CBytes(mixDigest.Bytes()),
		len:  C.GoInt(len(mixDigest.Bytes())),
		cap:  C.GoInt(len(mixDigest.Bytes())),
	}

	nonce := C.GoSlice{
		data: C.CBytes(updatedNonce.Bytes()),
		len:  C.GoInt(len(updatedNonce.Bytes())),
		cap:  C.GoInt(len(updatedNonce.Bytes())),
	}

	root := C.GoSlice{
		data: C.CBytes(intermediateRoot.Bytes()),
		len:  C.GoInt(len(intermediateRoot.Bytes())),
		cap:  C.GoInt(len(intermediateRoot.Bytes())),
	}

	retBytes := C.RandomV3(digest, nonce, root)
	randomNumber := C.GoBytes(retBytes, 32)

	C.free(unsafe.Pointer(digest.data))
	C.free(unsafe.Pointer(nonce.data))
	C.free(unsafe.Pointer(root.data))

	return randomNumber
}
