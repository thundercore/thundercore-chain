package thundervm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/thunder/thunderella/election"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
)

const (
	nonceTablePrefix = "nonce"
)

func init() {
	// generate ABI from json
	{
		_abi, err := abi.JSON(strings.NewReader(electionR2ABIjson))
		if err != nil {
			debug.Fatal("could not parse CSTPC abi")
		}
		ElectionR2ABI = _abi
	}
}

func Nonces(stateDB vm.StateDB) *ByteMap {
	return NewByteMap(commElectionAddress, stateDB, nonceTablePrefix)
}

type StakeMsgR2ABI struct {
	RewardAddress common.Address
	Stake         *big.Int
	GasPrice      *big.Int
	VotePubKey    []byte
	Session       *big.Int
	Nonce         *big.Int
	Sig           []byte
	RefundID      []byte // not used in vault
}

// electionR2ABIjson is created by https://remix.ethereum.org with contract like that
// contract CSTPCABI {
//    function bid(address rewardAddress, uint256 stake, uint256 gasPrice, bytes votePubKey, uint session, uint nonce, bytes sig, bytes refundID) {}
//    function getAvailableStake(bytes refundID) view returns(int) {}
//    function getNonce(bytes32 key) view returns(uint) {}
// }
//
var electionR2ABIjson = `
[
	{
		"constant": false,
		"inputs": [
			{
				"name": "rewardAddress",
				"type": "address"
			},
			{
				"name": "stake",
				"type": "uint256"
			},
			{
				"name": "gasPrice",
				"type": "uint256"
			},
			{
				"name": "votePubKey",
				"type": "bytes"
			},
			{
				"name": "session",
				"type": "uint256"
			},
			{
				"name": "nonce",
				"type": "uint256"
			},
			{
				"name": "sig",
				"type": "bytes"
			},
			{
				"name": "refundID",
				"type": "bytes"
			}
		],
		"name": "bid",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "key",
				"type": "bytes32"
			}
		],
		"name": "getNonce",
		"outputs": [
			{
				"name": "",
				"type": "uint256"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "refundID",
				"type": "bytes"
			}
		],
		"name": "getAvailableStake",
		"outputs": [
			{
				"name": "",
				"type": "int256"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	}
]
`

// CSTPCABI is exposed for stake in tool to pack its message
var ElectionR2ABI abi.ABI

type commElectionR2 struct {
	base
}

func (e *commElectionR2) call(method *abi.Method, input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	switch method.Name {
	case "bid":
		var arg StakeMsgR2ABI

		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}
		if err := method.Inputs.Copy(&arg, vs); err != nil {
			return nil, err
		}

		pubkey, err := bls.PublicKeyFromBytes(arg.VotePubKey)
		if err != nil {
			e.logger.Warn("Error from PublicKeyFromBytes sender %s: %s, key %s",
				arg.RewardAddress.Hex(), err, hex.EncodeToString(arg.VotePubKey))
			return nil, err
		}

		sig, err := bls.SignatureFromBytes(arg.Sig)
		if err != nil {
			e.logger.Warn("Failed to get signature for sender %s: %s", arg.RewardAddress.Hex(), err)
			return nil, err
		}

		var msg = &election.SignedStakeInfo{
			StakeInfo: election.StakeInfo{
				StakeMsg: election.StakeMsg{
					Stake:      arg.Stake,
					Coinbase:   arg.RewardAddress,
					GasPrice:   arg.GasPrice,
					PubVoteKey: pubkey,
				},
				StakingAddr: contract.Caller(),
				RefundID:    arg.RefundID,
			},
			Session: arg.Session,
			Nonce:   arg.Nonce,
			Sig:     sig,
		}

		return nil, e.abiBid(evm, contract, msg)

	case "getAvailableStake":
		var RefundID []byte
		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}
		if err := method.Inputs.Copy(&RefundID, vs); err != nil {
			return nil, err
		}
		return e.abiGetAvailableStake(evm, contract, RefundID)
	case "getNonce":
		var key common.Hash
		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}
		if err := method.Inputs.Copy(&key, vs); err != nil {
			return nil, err
		}
		return e.abiGetNonce(evm, key)
	default:
		return nil, fmt.Errorf("no such method")
	}
}

func (c *commElectionR2) RequiredGas(input []byte) uint64 {
	// We allow the Run() part of this precompiled contract to consume more gas
	// Note the elect method is hacked to always be 0 gas (despite using gas to call refund())
	// this is so that elect will never go over the block gas limit
	// We set 0 here and comsuming gas in Run() since we have vm.Contract to use
	return 0
}

// Run processes the PST/EST and stores the result in the stateb
// it does not conform to Ethereum ABI because it should never be called from a smart contract
func (e *commElectionR2) Run(input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
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

	ret, err := e.call(method, arg, evm, contract)

	if err != nil {
		return nil, vm.ErrExecutionReverted
	}

	return ret, nil
}

func (e *commElectionR2) elect(evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
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
	result := election.Elect(currentBids,
		freezeStakeBound(stakeTable, freezerTable, freezerIndex),
		int64(session))

	if result == nil {
		e.logger.Warn("Election failed")
		return nil, vm.ErrExecutionReverted
	}

	SetCurrentElectionResult(state, result)

	refundAll(evm, contract, stakeTable)

	// refund() should not have enough gas to call bid() meaning it's impossible for the stake message
	// map to change before/after refundAll() above. Still, we clear after refundAll() to follow
	// smart contract coding conventions.
	StakeMessages(state).Clear()
	Nonces(state).Clear()

	return nil, nil
}

func (c *commElectionR2) abiBid(evm *vm.EVM, contract *vm.Contract, signedStakeInfo *election.SignedStakeInfo) error {
	c.logger.Info("bid(reward:%s, stake:%s eth, gas:%s, votekey:%s...)",
		signedStakeInfo.Coinbase.Hex(),
		utils.WeiToEther(signedStakeInfo.Stake).String(),
		signedStakeInfo.GasPrice.String(),
		hex.EncodeToString(signedStakeInfo.PubVoteKey.ToBytes())[:16])
	c.logger.Info("    from:%s value:%s refundID:%s",
		contract.Caller().Hex(),
		contract.Value().String(),
		hex.EncodeToString(signedStakeInfo.RefundID))

	session := evm.ChainConfig().Thunder.GetSessionFromDifficulty(evm.Context.Difficulty, evm.Context.BlockNumber, evm.ChainConfig().Thunder)
	if !isValidBid(&signedStakeInfo.StakeInfo, int64(session)) {
		return fmt.Errorf("invalid bid")
	}
	if err := c.verifySigAndIncNonce(signedStakeInfo, contract, evm); err != nil {
		return err
	}

	key := makeRefundKey(signedStakeInfo.StakingAddr, signedStakeInfo.RefundID)
	uniqueKey := string(signedStakeInfo.PubVoteKey.ToBytes()) + key

	gas := gasByteMapInsert(len(uniqueKey), len(signedStakeInfo.StakeInfo.ToBytes()))

	if !contract.UseGas(gas) {
		c.logger.Warn("incoming bid is not enough gas, expecting %v sender %s", gas,
			contract.Caller().Hex())
		return vm.ErrOutOfGas
	}

	bm := StakeMessages(evm.StateDB)
	bm.InsertOrReplaceEntry(uniqueKey, &signedStakeInfo.StakeInfo)

	// if no money was sent with this transaction, no need to update the stake table
	if contract.Value().Sign() == 0 {
		c.logger.Debug("incoming bid sends no money, sender %s", contract.Caller().Hex())
		return nil
	}

	stakeTable := NewByteMap(commElectionAddress, evm.StateDB, electionStakeTablePrefix)

	gas = gasByteMapReplace(len(key), common.HashLength)
	if !contract.UseGas(gas) {
		c.logger.Info("incoming bid: out of gas, sender %s", contract.Caller().Hex())
		return vm.ErrOutOfGas
	}

	var current stakeValue
	err := stakeTable.FindEntry(key, &current)

	if err != nil {
		current.Value = big.NewInt(0).Set(contract.Value())
	} else {
		current.Value.Add(current.Value, contract.Value())
	}

	stakeTable.InsertOrReplaceEntry(key, &current)

	return nil
}

func (c *commElectionR2) abiGetAvailableStake(evm *vm.EVM, contract *vm.Contract, refundID []byte) ([]byte, error) {
	output := GetAvailableElectionStake(evm.StateDB, contract.Caller(), refundID)

	return common.BigToHash(output).Bytes(), nil
}

func (c *commElectionR2) abiGetNonce(evm *vm.EVM, key common.Hash) ([]byte, error) {
	nonces := Nonces(evm.StateDB)
	bytes, found := nonces.Find(key.Str())
	if found {
		return common.BytesToHash(bytes).Bytes(), nil
	} else {
		return common.BigToHash(big.NewInt(0)).Bytes(), nil
	}
}

func (c *commElectionR2) verifySigAndIncNonce(ssi *election.SignedStakeInfo, contract *vm.Contract, evm *vm.EVM) error {
	var nonce *big.Int
	thunderConfig := evm.ChainConfig().Thunder
	s := thunderConfig.GetSessionFromDifficulty(evm.Context.Difficulty, evm.Context.BlockNumber, thunderConfig)
	if ssi.Session.Cmp(big.NewInt(int64(s))) != 0 {
		// The client may reference a node which has not caught up the latest status.
		c.logger.Note("Invalid session %s(expected %d) in bid from sender %s", ssi.Session.String(), s, ssi.StakingAddr.Hex())
		return fmt.Errorf("Invalid session")
	}

	nonces := Nonces(evm.StateDB)
	key := common.Hash(sha256.Sum256(ssi.PubVoteKey.ToBytes())).Str()
	bytes, found := nonces.Find(key)
	if found {
		nonce = new(big.Int).SetBytes(bytes)
	} else {
		nonce = big.NewInt(0)
	}

	if nonce.Cmp(ssi.Nonce) != 0 {
		// The client may reference a node which has not caught up the latest status.
		c.logger.Note("Invalid nonce %s(expected %s) in bid from sender %s", ssi.Nonce.String(), nonce.String(), ssi.StakingAddr.Hex())
		return fmt.Errorf("Invalid nonce")
	}

	if thunderConfig.BidVerificationEnabled() {
		if !ssi.Verify() {
			c.logger.Note("Failed to verify bid from sender %s", ssi.StakingAddr.Hex())
			return fmt.Errorf("Failed to verify stake info")
		}
	}

	gas := gasByteMapReplace(len(key), common.HashLength)
	if !contract.UseGas(gas) {
		c.logger.Info("incoming bid: out of gas, sender %s", contract.Caller().Hex())
		return vm.ErrOutOfGas
	}
	nonce.Add(nonce, common.Big1)
	nonces.InsertOrReplace(key, nonce.Bytes())
	return nil
}
