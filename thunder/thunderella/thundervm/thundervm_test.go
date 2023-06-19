// This tests thunder stuff in "github.com/ethereum/go-ethereum/core/vm"
// This needs to be here becaues it depends on state.StateDB to test stuff in vm module
package thundervm

import (
	// Standard imports
	"crypto/sha256"
	"math/big"
	"strings"
	"testing"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chainconfig"
	"github.com/ethereum/go-ethereum/thunder/thunderella/election"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/testutils"

	// Vendor imports
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStakeMsgToBidCall(t *testing.T) {
	parentAddress := chainconfig.TestnetTestingAddr
	assert := assert.New(t)
	signKey, err := bls.NewSigningKey()
	assert.Nil(err)
	keybytes := signKey.GetPublicKey().ToBytes()
	keyhash := sha256.Sum256(keybytes)
	refundID := append(crypto.Keccak256([]byte("MyRefundSignature(address,bytes32)")), keyhash[:]...)

	stakeInfo := &election.StakeInfo{
		StakeMsg: election.StakeMsg{
			Stake:      big.NewInt(100000),
			PubVoteKey: signKey.GetPublicKey(),
			Coinbase:   parentAddress,
			GasPrice:   big.NewInt(25),
		},
		StakingAddr: parentAddress,
		RefundID:    refundID,
	}

	input, err := StakeMsgToBidCall(stakeInfo)
	assert.Nil(err)

	// do it manually now
	input2 := crypto.Keccak256([]byte("bid(address,uint256,uint256,bytes,bytes)"))[:4]             // function sig
	input2 = append(input2, common.LeftPadBytes(parentAddress.Bytes(), 32)...)                     // reward account
	input2 = append(input2, common.BigToHash(big.NewInt(100000)).Bytes()...)                       // stake
	input2 = append(input2, common.BigToHash(big.NewInt(25)).Bytes()...)                           // gas price
	input2 = append(input2, common.BigToHash(big.NewInt(5*32)).Bytes()...)                         // offset
	input2 = append(input2, common.BigToHash(big.NewInt(int64(5*32+32+len(keybytes)))).Bytes()...) // gas price
	input2 = append(input2, common.BigToHash(big.NewInt(int64(len(keybytes)))).Bytes()...)         // key hash length
	input2 = append(input2, keybytes...)
	input2 = append(input2, common.BigToHash(big.NewInt(int64(len(refundID)))).Bytes()...) // refund input lenth
	input2 = append(input2, refundID...)

	assert.Equal(input2, input)
}

func TestElectionRefundAll(t *testing.T) {
	require := require.New(t)
	bc, state := newEnv(0, 0, false)

	table := []struct {
		addr  common.Address
		stake *big.Int
	}{
		{addr: common.BytesToAddress([]byte{0x10}), stake: big.NewInt(10000)},
		{addr: common.BytesToAddress([]byte{0x11}), stake: big.NewInt(20000)},
		{addr: common.BytesToAddress([]byte{0x12}), stake: big.NewInt(30000)},
		{addr: common.BytesToAddress([]byte{0x13}), stake: big.NewInt(40000)},
		{addr: common.BytesToAddress([]byte{0x14}), stake: big.NewInt(50000)},
	}

	stakeTable := NewByteMap(commElectionAddress, state, electionStakeTablePrefix)

	sum := big.NewInt(0)
	for _, entry := range table {
		sum.Add(sum, entry.stake)

		var current stakeValue
		current.Value = entry.stake
		stakeTable.InsertOrReplaceEntry(makeRefundKey(entry.addr, []byte{}), &current)
	}

	state.SetBalance(commElectionAddress, sum)

	contract := vm.NewContract(vm.AccountRef(testutils.TestingAddr), vm.AccountRef(commElectionAddress), big.NewInt(0), 10000000000)
	header := &types.Header{
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(0),
		GasLimit:   65535,
		Time:       100,
	}

	msg := newFakeMessage(testutils.TestingAddr, commElectionAddress, big.NewInt(0), []byte{}, 0)
	txContext := core.NewEVMTxContext(msg)
	evmContext := core.NewEVMBlockContext(header, bc, nil)

	evm := vm.NewEVM(evmContext, txContext, state, bc.Config(), vm.Config{})

	refundAll(evm, contract, stakeTable)

	for _, entry := range table {
		sum.Add(sum, entry.stake)

		require.True(state.GetBalance(entry.addr).Cmp(entry.stake) == 0, "%v", state.GetBalance(entry.addr))
	}
}

func TestElectionSafeRefundAllToPlanAddress(t *testing.T) {
	require := require.New(t)
	bc, state := newEnv(0, 0, false)

	table := []struct {
		addr  common.Address
		stake *big.Int
	}{
		{addr: common.BytesToAddress([]byte{0x10}), stake: big.NewInt(10000)},
		{addr: common.BytesToAddress([]byte{0x11}), stake: big.NewInt(20000)},
		{addr: common.BytesToAddress([]byte{0x12}), stake: big.NewInt(30000)},
		{addr: common.BytesToAddress([]byte{0x13}), stake: big.NewInt(40000)},
		{addr: common.BytesToAddress([]byte{0x14}), stake: big.NewInt(50000)},
	}

	stakeTable := NewByteMap(commElectionAddress, state, electionStakeTablePrefix)

	sum := big.NewInt(0)
	for _, entry := range table {
		sum.Add(sum, entry.stake)

		var current stakeValue
		current.Value = entry.stake
		stakeTable.InsertOrReplaceEntry(makeRefundKey(entry.addr, []byte{}), &current)
	}

	state.SetBalance(commElectionAddress, sum)

	contract := vm.NewContract(vm.AccountRef(testutils.TestingAddr), vm.AccountRef(commElectionAddress), big.NewInt(0), 10000000000)
	header := &types.Header{
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(0),
		GasLimit:   65535,
		Time:       100,
	}

	msg := newFakeMessage(testutils.TestingAddr, commElectionAddress, big.NewInt(0), []byte{}, 0)
	txContext := core.NewEVMTxContext(msg)
	evmContext := core.NewEVMBlockContext(header, bc, nil)

	evm := vm.NewEVM(evmContext, txContext, state, bc.Config(), vm.Config{})

	safeRefundAll(evm, contract, stakeTable)

	for _, entry := range table {
		sum.Add(sum, entry.stake)
		require.True(state.GetBalance(entry.addr).Cmp(entry.stake) == 0, "%v", state.GetBalance(entry.addr))
	}
}

func TestFreezeStake(t *testing.T) {
	require := require.New(t)
	_, state := newEnv(0, 0, false)

	testCases := []struct {
		addr     common.Address
		stake    *big.Int
		attempt  *big.Int
		key      *bls.SigningKey
		expected bool
	}{
		{addr: common.BytesToAddress([]byte{0x10}), stake: big.NewInt(10000), attempt: big.NewInt(30000), expected: true},
		{addr: common.BytesToAddress([]byte{0x11}), stake: big.NewInt(20000), attempt: big.NewInt(30000), expected: true},
		{addr: common.BytesToAddress([]byte{0x12}), stake: big.NewInt(30000), attempt: big.NewInt(30000), expected: true},
		{addr: common.BytesToAddress([]byte{0x13}), stake: big.NewInt(40000), attempt: big.NewInt(30000), expected: false},
		{addr: common.BytesToAddress([]byte{0x14}), stake: big.NewInt(50000), attempt: big.NewInt(30000), expected: false},
	}

	for i := range testCases {
		testCases[i].key, _ = bls.NewSigningKey()
	}

	xaddr := common.BytesToAddress([]byte{253})

	stakeTable := NewByteMap(xaddr, state, "123")

	for _, c := range testCases {
		var current stakeValue
		current.Value = big.NewInt(0).Set(c.attempt)
		stakeTable.InsertOrReplaceEntry(makeRefundKey(c.addr, []byte{}), &current)
	}

	freezerTable := NewByteMap(xaddr, state, "321")
	freezerIndex := NewByteMap(xaddr, state, "3345")

	for _, c := range testCases {
		suc := freezeStake(stakeTable, freezerTable, freezerIndex, &election.StakeInfo{
			StakeMsg: election.StakeMsg{
				Stake:      c.stake,
				PubVoteKey: c.key.GetPublicKey(),
			},
			StakingAddr: c.addr,
		})
		require.Equal(c.expected, suc)
	}

	for _, c := range testCases {
		var entry stakeValue
		key := makeRefundKey(c.addr, []byte{})
		err := stakeTable.FindEntry(key, &entry)
		require.Nil(err)
		if c.expected {
			require.Equal(entry.Value.Int64(), big.NewInt(0).Sub(c.attempt, c.stake).Int64())
			var frozen stakeValue
			err := freezerTable.FindEntry(key, &frozen)
			require.Nil(err)
			require.Equal(c.stake, frozen.Value)

			var index frozenIndex
			err = freezerIndex.FindEntry(string(c.key.PublicKey.ToBytes()), &index)
			require.Nil(err)
			require.Equal(index, frozenIndex(key))
		} else {
			require.Equal(entry.Value, c.attempt)
		}
	}
}

func TestEvmABICall(t *testing.T) {
	assert := assert.New(t)
	bc, state := newEnv(0, 0, false)
	opAccount, _ := crypto.GenerateKey()
	opAddress := crypto.PubkeyToAddress(opAccount.PublicKey)

	key, err := bls.NewSigningKey()
	assert.Nil(err)
	keyBytes := key.ToBytes()
	keyHash := sha256.Sum256(keyBytes)

	// test precompile contract
	from := chainconfig.TestnetTestingAddr
	to := vaultAddress
	gas := uint64(1000000)
	input := []byte{} // don't care
	nonce := uint64(0)
	value := big.NewInt(0)

	contract := vm.NewContract(vm.AccountRef(from), vm.AccountRef(to), value, gas)
	header := &types.Header{
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(0),
		GasLimit:   65535,
		Time:       100,
	}

	msg := newFakeMessage(from, to, value, input, nonce)
	txContext := core.NewEVMTxContext(msg)
	evmContext := core.NewEVMBlockContext(header, bc, nil)

	evm := vm.NewEVM(evmContext, txContext, state, bc.Config(), vm.Config{})

	beforeHash := state.IntermediateRoot(true)
	method := VaultABI.Methods["createAccount"]
	_, err = evmABICall(evm, contract, to, value, 80000, &method, opAddress, keyHash)
	assert.Nil(err)
	// we didn't use gas in our precompiled contract
	assert.Condition(func() bool { return contract.Gas < gas })
	afterHash := state.IntermediateRoot(true)
	assert.NotEqual(beforeHash, afterHash)

	beforeHash = afterHash
	method = VaultABI.Methods["withdraw"]
	_, err = evmABICall(evm, contract, to, value, 20000, &method, keyHash, big.NewInt(33333))
	assert.NotNil(err)
	assert.Condition(func() bool { return contract.Gas < gas })

	afterHash = state.IntermediateRoot(true)
	assert.Equal(beforeHash, afterHash)
	// TODO: add normal contract test, make sure the revert logic.
}

const delegateCallTestContract = `
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;
contract DelegateCallTest {
	uint256 public randomNumber;
	address public rngAddress = 0x8cC9C2e145d3AA946502964B1B69CE3cD066A9C7;
	constructor() {
	}
	function random() external {
		(bool success, bytes memory data) = rngAddress.delegatecall(abi.encodeWithSignature("random()"));
		require(success, "DelegateCallTest: random() failed");
		randomNumber = abi.decode(data, (uint256));
	}
}
`

const delegateCallABI = `
[
		{
			"inputs": [],
			"stateMutability": "nonpayable",
			"type": "constructor"
		},
		{
			"inputs": [],
			"name": "random",
			"outputs": [],
			"stateMutability": "nonpayable",
			"type": "function"
		},
		{
			"inputs": [],
			"name": "randomNumber",
			"outputs": [
				{
					"internalType": "uint256",
					"name": "",
					"type": "uint256"
				}
			],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [],
			"name": "rngAddress",
			"outputs": [
				{
					"internalType": "address",
					"name": "",
					"type": "address"
				}
			],
			"stateMutability": "view",
			"type": "function"
		}
	]
`

func TestRevertDelegateCallOnPrecompiledContractBeforeHardfork(t *testing.T) {
	req := require.New(t)

	session := int64(rngV3EnableSession)
	chain, state := newEnv(0, session, false)

	if evmHardforkVersion.GetValueAtSession(session) == "" {
		return
	}

	parsedABI, err := abi.JSON(strings.NewReader(delegateCallABI))
	req.NoError(err)

	chain.Config().Thunder.TPCRevertDelegateCall.SetTestValueAtSession(false, 0)

	code := compileSol(req, "DelegateCallTest", delegateCallTestContract, "0.8.9")
	input := mustDecode(code)

	addressCreated := testDeployContract(req, chain, state, testutils.TestingAddr, input, big.NewInt(0))

	encodedData, err := parsedABI.Pack("random")
	req.NoError(err)

	fakeMsg := newFakeMessage(testutils.TestingAddr, addressCreated, big.NewInt(0), encodedData, state.GetNonce(testutils.TestingAddr))
	_, _, err = run(chain, state, fakeMsg)
	req.NoError(err)

	encodedData, err = parsedABI.Pack("randomNumber")
	req.NoError(err)

	fakeMsg = newFakeMessage(testutils.TestingAddr, addressCreated, big.NewInt(0), encodedData, state.GetNonce(testutils.TestingAddr))
	ret, _, err := run(chain, state, fakeMsg)
	req.NoError(err)

	r, err := parsedABI.Unpack("randomNumber", ret)
	req.NoError(err)

	req.NotEqual(uint64(0), r[0].(*big.Int).Uint64())
}

func TestRevertDelegateCallOnPrecompiledContractAfterHardfork(t *testing.T) {
	req := require.New(t)

	session := int64(rngV3EnableSession)
	chain, state := newEnv(0, session, false)

	if evmHardforkVersion.GetValueAtSession(session) == "" {
		return
	}

	parsedABI, err := abi.JSON(strings.NewReader(delegateCallABI))
	req.NoError(err)

	chain.Config().Thunder.TPCRevertDelegateCall.SetTestValueAtSession(true, 0)

	code := compileSol(req, "DelegateCallTest", delegateCallTestContract, "0.8.9")
	input := mustDecode(code)

	addressCreated := testDeployContract(req, chain, state, testutils.TestingAddr, input, big.NewInt(0))

	encodedData, err := parsedABI.Pack("random")
	req.NoError(err)

	fakeMsg := newFakeMessage(testutils.TestingAddr, addressCreated, big.NewInt(0), encodedData, state.GetNonce(testutils.TestingAddr))
	ret, _, err := run(chain, state, fakeMsg)
	req.Error(err)
	req.True(strings.Contains(string(ret), "DelegateCallTest: random()"))
}
