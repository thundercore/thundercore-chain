package thundervm

import (
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
	commElectionStakeMessagePrefix   = "stake"
	commElectionElectionResultPrefix = "electionResult"
	electionStakeTablePrefix         = "estp"
	electionFreezerTablePrefix       = "eftp"
	electionFreezerIndexPrefix       = "efip"

	// refundIdMaxLength = len(hash256()) + len(method.Id())
	// refundId should limited to a hash and abi packed method
	refundIDMaxLength = common.HashLength + 4
)

type commElection struct {
	base
}

func init() {

	// generate ABI from json
	{
		abi, err := abi.JSON(strings.NewReader(electionABIjson))
		if err != nil {
			debug.Fatal("could not parse CSTPC abi")
		}
		ElectionABI = abi
	}
}

// TODO add VotePubKeySig to this
type StakeMsgABI_0p5 struct {
	RewardAddress common.Address
	Stake         *big.Int
	GasPrice      *big.Int
	VotePubKey    []byte
	RefundID      []byte
}

// CSTPCABI is created by https://remix.ethereum.org with contract like that
// contract CSTPCABI {
//	function bid(address rewardAddress, uint256 stake, uint256 gasPrice, bytes votePubKey, bytes refundID) {}
//	function getAvailableStake(bytes refundID) view returns(int) {}
// }
//
var electionABIjson = `
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
				"name": "refundID",
				"type": "bytes"
			}
		],
		"outputs": [
			{
				"type": "int256"
			}
		],
		"name": "getAvailableStake",
		"stateMutability": "view",
		"type": "function"
	}
]
`

// CSTPCABI is exposed for stake in tool to pack its message
var ElectionABI abi.ABI

func (e *commElection) call(method *abi.Method, input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	switch method.Name {
	case "bid":
		var arg StakeMsgABI_0p5

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

		var msg = &election.StakeInfo{
			StakeMsg: election.StakeMsg{
				Stake:      arg.Stake,
				Coinbase:   arg.RewardAddress,
				GasPrice:   arg.GasPrice,
				PubVoteKey: pubkey,
			},
			StakingAddr: contract.Caller(),
			RefundID:    arg.RefundID,
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
	default:
		return nil, fmt.Errorf("no such method")
	}
}

func (c *commElection) RequiredGas(input []byte) uint64 {
	// We allow the Run() part of this precompiled contract to consume more gas
	// Note the elect method is hacked to always be 0 gas (despite using gas to call refund())
	// this is so that elect will never go over the block gas limit
	// We set 0 here and comsuming gas in Run() since we have vm.Contract to use
	return 0
}

// Run processes the PST/EST and stores the result in the stateb
// it does not conform to Ethereum ABI because it should never be called from a smart contract
func (e *commElection) Run(input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	if len(input) == 0 {
		return e.elect(evm, contract)
	}

	if len(input) < 4 {
		return nil, vm.ErrExecutionReverted
	}

	id := input[:4]
	arg := input[4:]

	method, err := ElectionABI.MethodById(id)
	if err != nil {
		return nil, vm.ErrExecutionReverted
	}

	ret, err := e.call(method, arg, evm, contract)

	if err != nil {
		return nil, vm.ErrExecutionReverted
	}

	return ret, nil
}

func (e *commElection) elect(evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
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

	return nil, nil
}

// isValidBid check incoming bid make sense, bls key should be 128 bytes.
// Refund ID should be less than votingkey and gas price should never be zero.
func isValidBid(stakeMsg *election.StakeInfo, sessionNumber int64) bool {
	isValid := stakeMsg.GasPrice.Cmp(election.MinBidPrice.GetValueAtSession(sessionNumber)) >= 0 &&
		len(stakeMsg.RefundID) <= refundIDMaxLength
	if !isValid {
		logger.Warn("invalid bid, sender %s: gas price %v refundid len=%v",
			stakeMsg.StakingAddr.Hex(), stakeMsg.GasPrice, len(stakeMsg.RefundID))
	}
	return isValid
}

func StakeMessages(stateDB vm.StateDB) *ByteMap {
	return NewByteMap(commElectionAddress, stateDB, commElectionStakeMessagePrefix)
}

func ElectionResults(stateDB vm.StateDB) *ByteList {
	return NewByteList(stateDB, commElectionAddress, commElectionElectionResultPrefix)
}

func (c *commElection) abiBid(evm *vm.EVM, contract *vm.Contract, stakeMsg *election.StakeInfo) error {

	c.logger.Info("bid(reward:%s, stake:%s eth, gas:%s, votekey:%s...)",
		stakeMsg.Coinbase.Hex(),
		utils.WeiToEther(stakeMsg.Stake).String(),
		stakeMsg.GasPrice.String(),
		hex.EncodeToString(stakeMsg.PubVoteKey.ToBytes())[:16])
	c.logger.Info("    from:%s value:%s refundID:%s",
		contract.Caller().Hex(),
		contract.Value().String(),
		hex.EncodeToString(stakeMsg.RefundID))

	session := evm.ChainConfig().Thunder.GetSessionFromDifficulty(evm.Context.Difficulty, evm.Context.BlockNumber, evm.ChainConfig().Thunder)
	if !isValidBid(stakeMsg, int64(session)) {
		return fmt.Errorf("invalid bid")
	}

	bm := StakeMessages(evm.StateDB)

	key := makeRefundKey(stakeMsg.StakingAddr, stakeMsg.RefundID)

	uniqueKey := string(stakeMsg.PubVoteKey.ToBytes()) + key

	gas := gasByteMapInsert(len(key), len(stakeMsg.ToBytes()))

	if !contract.UseGas(gas) {
		c.logger.Warn("incoming bid is not enough gas, expecting %v sender %s", gas,
			contract.Caller().Hex())
		return vm.ErrOutOfGas
	}

	bm.InsertOrReplaceEntry(uniqueKey, stakeMsg)

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

func (c *commElection) abiGetAvailableStake(evm *vm.EVM, contract *vm.Contract, refundID []byte) ([]byte, error) {
	output := GetAvailableElectionStake(evm.StateDB, contract.Caller(), refundID)

	return common.BigToHash(output).Bytes(), nil
}
