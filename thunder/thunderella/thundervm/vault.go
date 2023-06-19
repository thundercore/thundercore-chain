package thundervm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/thunder/thunderella/election"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
)

const (
	vaultBalancePrefix = "vaultbalance"
)

func init() {
	{
		abi, err := abi.JSON(strings.NewReader(vaultABIjson))
		if err != nil {
			debug.Fatal("could not parse vault abi")
		}
		VaultABI = abi
	}
}

func Balances(stateDB vm.StateDB) *ByteMap {
	return NewByteMap(vaultAddress, stateDB, vaultBalancePrefix)
}

type vault struct {
	base
}

// vaultABIjson is created by https://remix.ethereum.org with contract like that
// contract Vault {
// 	function createAccount(address operator, bytes32 keyHash) payable { }
// 	function withdraw(bytes32 keyHash, uint amount) external { }
// 	function deposit(bytes32 keyHash) external payable { }
// 	function bid(address rewardAddress, uint stake, uint gasPrice, bytes votePubKey) external { }
// 	function changeOperator(bytes32 keyHash, address operator) external { }
// 	function getBalance(bytes32 keyHash) view returns(uint) { }
//	function getOwner(bytes32 keyHash) view returns(address) { }
//	function getOperator(bytes32 keyHash) view returns(address) { }
//	function getAvailableBalance(bytes32 keyHash) view returns(int) { }
// }
//
var vaultABIjson = `
[
	{
		"constant": false,
		"inputs": [
			{
				"name": "keyHash",
				"type": "bytes32"
			},
			{
				"name": "amount",
				"type": "uint256"
			}
		],
		"name": "withdraw",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
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
			}
		],
		"name": "bid",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "keyHash",
				"type": "bytes32"
			},
			{
				"name": "operator",
				"type": "address"
			}
		],
		"name": "changeOperator",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "keyHash",
				"type": "bytes32"
			}
		],
		"name": "deposit",
		"outputs": [],
		"payable": true,
		"stateMutability": "payable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "operator",
				"type": "address"
			},
			{
				"name": "keyHash",
				"type": "bytes32"
			}
		],
		"name": "createAccount",
		"outputs": [],
		"payable": true,
		"stateMutability": "payable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "keyHash",
				"type": "bytes32"
			}
		],
		"name": "getBalance",
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
				"name": "keyHash",
				"type": "bytes32"
			}
		],
		"outputs": [
			{
				"type": "address"
			}
		],
		"name": "getOwner",
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "keyHash",
				"type": "bytes32"
			}
		],
		"outputs": [
			{
				"type": "address"
			}
		],
		"name": "getOperator",
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "keyHash",
				"type": "bytes32"
			}
		],
		"outputs": [
			{
				"type": "int256"
			}
		],
		"name": "getAvailableBalance",
		"stateMutability": "view",
		"type": "function"
	}
]
`
var VaultABI abi.ABI

func (v *vault) RequiredGas(input []byte) uint64 {
	// NOTE: We set 0 here and comsuming gas in Run() since we have vm.Contract to use
	return 0
}

func (v *vault) Run(input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {
	v.logger.Debug("received tx from %s with payload length %d", contract.Caller().Hex(), len(input))
	if len(input) < 4 {
		v.logger.Debug("reverting on bad input")
		return nil, vm.ErrExecutionReverted
	}

	id := input[:4]
	arg := input[4:]

	method, err := VaultABI.MethodById(id)
	if err != nil {
		v.logger.Debug("no method error %v", err)
		return nil, vm.ErrExecutionReverted
	}

	output, err := v.call(method, arg, evm, contract)
	if err != nil {
		v.logger.Debug("Vault execution failed, err = %v", err)
		return nil, vm.ErrExecutionReverted
	}

	return output, nil
}

func (v *vault) call(method *abi.Method, input []byte, evm *vm.EVM, contract *vm.Contract) ([]byte, error) {

	v.logger.Debug("calling %v", method.Name)
	switch method.Name {
	case "deposit":
		var arg common.Hash

		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}
		if err := method.Inputs.Copy(&arg, vs); err != nil {
			return nil, err
		}

		return nil, v.abiDeposit(evm, contract, arg)
	case "withdraw":
		var arg struct {
			KeyHash common.Hash
			Amount  *big.Int
		}

		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}
		if err := method.Inputs.Copy(&arg, vs); err != nil {
			return nil, err
		}

		return nil, v.abiWithdraw(evm, contract, arg.KeyHash, arg.Amount)
	case "createAccount":
		var arg struct {
			Operator common.Address
			KeyHash  common.Hash
		}

		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}
		if err := method.Inputs.Copy(&arg, vs); err != nil {
			return nil, err
		}

		return nil, v.abiCreateAccount(evm, contract, arg.Operator, arg.KeyHash)
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
			v.logger.Debug("could not parse vote key %v", pubkey)
			return nil, err
		}

		rewardAddress := arg.RewardAddress
		session := evm.ChainConfig().Thunder.GetSessionFromDifficulty(evm.Context.Difficulty, evm.Context.BlockNumber, evm.ChainConfig().Thunder)
		if election.BurnReward.GetValueAtSession(int64(session)) {
			rewardAddress = common.Address{}
		}
		var msg = &election.StakeMsg{
			Stake:      arg.Stake,
			Coinbase:   rewardAddress,
			GasPrice:   arg.GasPrice,
			PubVoteKey: pubkey,
		}

		return nil, v.abiBid(evm, contract, msg)
	case "changeOperator":
		var arg struct {
			Operator common.Address
			KeyHash  common.Hash
		}

		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}
		if err := method.Inputs.Copy(&arg, vs); err != nil {
			return nil, err
		}

		return nil, v.abiChangeOperator(evm, contract, arg.KeyHash, arg.Operator)
	case "getBalance":
		var arg common.Hash
		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}
		if err := method.Inputs.Copy(&arg, vs); err != nil {
			return nil, err
		}
		return v.abiGetBalance(evm, contract, arg)

	case "getOwner":
		var arg common.Hash
		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}
		if err := method.Inputs.Copy(&arg, vs); err != nil {
			return nil, err
		}
		return v.abiGetOwner(evm, contract, arg)

	case "getOperator":
		var arg common.Hash
		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}
		if err := method.Inputs.Copy(&arg, vs); err != nil {
			return nil, err
		}
		return v.abiGetOperator(evm, contract, arg)

	case "getAvailableBalance":
		var arg common.Hash
		vs, err := method.Inputs.Unpack(input)
		if err != nil {
			return nil, err
		}
		if err := method.Inputs.Copy(&arg, vs); err != nil {
			return nil, err
		}
		return v.abiGetAvailableBalance(evm, contract, arg)
	default:
		return nil, fmt.Errorf("no such method")
	}
}

type VaultBalance struct {
	parentAccount      common.Address
	operationalAccount common.Address
	Balance            *big.Int
}

func NewVaultBalanceEntry(parent, operationalAccount common.Address) *VaultBalance {
	return &VaultBalance{
		parentAccount:      parent,
		operationalAccount: operationalAccount,
		Balance:            big.NewInt(0),
	}
}

var (
	parentOffset       = 0
	parentEnd          = parentOffset + common.AddressLength
	opOffset           = parentEnd
	opEnd              = opOffset + common.AddressLength
	balanceOffset      = opEnd
	balanceEnd         = balanceOffset + HashLength
	vaultBalanceLength = balanceEnd
)

// ToBytes serialized the structure to bytes
// TODO: extract an interface and change bytemap implementation
func (vb *VaultBalance) ToBytes() []byte {
	out := make([]byte, vaultBalanceLength)
	copy(out[parentOffset:], vb.parentAccount.Bytes())
	copy(out[opOffset:], vb.operationalAccount.Bytes())
	copy(out[balanceOffset:], common.BigToHash(vb.Balance).Bytes())

	return out
}

func (vb *VaultBalance) FromBytes(input []byte) error {
	if len(input) < 40 {
		return fmt.Errorf("cannot parse input to VaultBalance")
	}
	vb.parentAccount = common.BytesToAddress(input[parentOffset:parentEnd])
	vb.operationalAccount = common.BytesToAddress(input[opOffset:opEnd])
	vb.Balance = big.NewInt(0).SetBytes(input[balanceOffset:balanceEnd])

	return nil
}

func getVaultBalanceFromTable(table *ByteMap, key string) (*VaultBalance, error) {
	entry := new(VaultBalance)
	err := table.FindEntry(key, entry)

	return entry, err
}

func (v *vault) abiCreateAccount(evm *vm.EVM, contract *vm.Contract,
	operationalAccount common.Address, keyHash common.Hash) error {
	msgSender := contract.CallerAddress
	v.logger.Debug("createAccount(%s, %s) from %s",
		operationalAccount.Hex(), keyHash.Hex(), msgSender.Hex())

	balanceTable := Balances(evm.StateDB)
	key := keyHash.Str()

	gas := gasByteMapFind(common.HashLength, vaultBalanceLength)
	if !contract.UseGas(gas) {
		return vm.ErrOutOfGas
	}

	_, exists := balanceTable.Find(key)

	if exists {
		v.logger.Debug("failed, key %s already registered", keyHash.Hex())
		return fmt.Errorf("already registered")
	}

	// note balance is 0 and you will be paying for storing these 0s
	// this makes gas computation for deposit easier.
	gas = gasByteMapInsert(common.HashLength, vaultBalanceLength)
	if !contract.UseGas(gas) {
		return vm.ErrOutOfGas
	}

	entry := NewVaultBalanceEntry(msgSender, operationalAccount)

	entry.Balance.Set(contract.Value())
	balanceTable.InsertOrReplace(key, entry.ToBytes())

	return nil
}

func (v *vault) abiDeposit(evm *vm.EVM, contract *vm.Contract, keyHash common.Hash) error {
	v.logger.Debug("deposit(%s) value:%s from:%s",
		keyHash.Hex(), contract.Value().String(), contract.CallerAddress.Hex())

	key := keyHash.Str()

	gas := gasByteMapFind(common.HashLength, vaultBalanceLength)
	if !contract.UseGas(gas) {
		return vm.ErrOutOfGas
	}

	balanceTable := Balances(evm.StateDB)
	entry, err := getVaultBalanceFromTable(balanceTable, key)

	if err != nil {
		v.logger.Debug("no entry")
		return err
	}

	gas = gasByteMapReplace(common.HashLength, balanceEnd-balanceOffset)
	if !contract.UseGas(gas) {
		return vm.ErrOutOfGas
	}

	v.logger.Debug("added %s to account", contract.Value().String())
	entry.Balance.Add(entry.Balance, contract.Value())
	balanceTable.InsertOrReplaceEntry(key, entry)

	return nil
}

func (v *vault) abiWithdraw(evm *vm.EVM, contract *vm.Contract,
	keyHash common.Hash, amount *big.Int) error {
	v.logger.Debug("withdraw(%s, %s)", keyHash.Hex(), amount.String())
	msgSender := contract.CallerAddress
	key := keyHash.Str()

	gas := gasByteMapFind(common.HashLength, vaultBalanceLength)
	if !contract.UseGas(gas) {
		return vm.ErrOutOfGas
	}

	balanceTable := Balances(evm.StateDB)
	entry, err := getVaultBalanceFromTable(balanceTable, key)
	if err != nil {
		return err
	}

	// only operator and owner account allowed to withdraw
	if entry.parentAccount != msgSender && entry.operationalAccount != msgSender {
		return fmt.Errorf("sender Account mismatch")
	}

	if entry.Balance.Cmp(amount) < 0 {
		return vm.ErrInsufficientBalance
	}

	entry.Balance.Sub(entry.Balance, amount)

	gas = gasByteMapReplace(common.HashLength, balanceEnd-balanceOffset)
	if !contract.UseGas(gas) {
		return vm.ErrOutOfGas
	}

	balanceTable.InsertOrReplaceEntry(key, entry)

	// CanTransfer checks for sufficient transfer. This should never happen assuming all accounting
	// is correct in Vault implementation.
	if !evm.Context.CanTransfer(evm.StateDB, vaultAddress, amount) {
		debug.Bug("Cannot withdraw from vault")
	}

	evm.Context.Transfer(evm.StateDB, vaultAddress, entry.parentAccount, amount)

	return nil
}

var (
	gasRead = uint64(1000)
	gasBid  = uint64(168000)
)

func (v *vault) abiBid(evm *vm.EVM, contract *vm.Contract,
	stakeMsg *election.StakeMsg) error {
	msgSender := contract.CallerAddress
	balanceTable := Balances(evm.StateDB)

	keyHash := common.Hash(sha256.Sum256(stakeMsg.PubVoteKey.ToBytes()))
	key := keyHash.Str()

	v.logger.Debug("bidding for %s", keyHash.Hex())
	gas := gasByteMapFind(common.HashLength, vaultBalanceLength)
	if !contract.UseGas(gas) {
		return vm.ErrOutOfGas
	}

	entry, err := getVaultBalanceFromTable(balanceTable, key)
	if err != nil {
		v.logger.Debug("account not found")
		return err
	}

	if entry.operationalAccount != msgSender {
		v.logger.Debug("invalid operator account")
		return fmt.Errorf("operation Account mismatch")
	}

	// use refund(keyHash) as our refund callback
	refundID, err := VaultABI.Pack("deposit", keyHash)
	if err != nil {
		v.logger.Debug("packing vailed")
		return errors.New("pack failed")
	}

	// calculate the required amount of thunder to transfer
	stakeQueryMethod := ElectionABI.Methods["getAvailableStake"]
	ret, err := evmABICall(evm, contract, commElectionAddress, big.NewInt(0), gasRead, &stakeQueryMethod, refundID)
	if err != nil {
		v.logger.Debug("get available stake failed")
		return err
	}

	bidBalance := common.BytesToHash(ret).Big()

	requiredValue := big.NewInt(0).Sub(stakeMsg.Stake, bidBalance)
	if requiredValue.Sign() < 0 {
		requiredValue.SetInt64(0)
	}

	if entry.Balance.Cmp(requiredValue) < 0 {
		v.logger.Debug("insufficient balance for transefr %s %s", entry.Balance.String(), requiredValue.String())
		return vm.ErrInsufficientBalance
	}

	gas = gasByteMapReplace(common.HashLength, balanceEnd-balanceOffset)
	if !contract.UseGas(gas) {
		return vm.ErrOutOfGas
	}

	// update our accounting
	entry.Balance.Sub(entry.Balance, requiredValue)
	balanceTable.InsertOrReplaceEntry(key, entry)

	bidMethod := ElectionABI.Methods["bid"]
	_, err = evmABICall(evm, contract, commElectionAddress, requiredValue, gasBid, &bidMethod,
		stakeMsg.Coinbase, &stakeMsg.Stake, &stakeMsg.GasPrice, stakeMsg.PubVoteKey.ToBytes(), refundID)

	v.logger.Debug("bid done with err %v", err)
	return err
}

func (v *vault) abiChangeOperator(evm *vm.EVM, contract *vm.Contract, keyHash common.Hash, operator common.Address) error {
	balanceTable := Balances(evm.StateDB)
	key := keyHash.Str()

	v.logger.Debug("changeOperator(%s, %s)", keyHash.Hex(), operator.Hex())

	gas := gasByteMapFind(common.HashLength, vaultBalanceLength)
	if !contract.UseGas(gas) {
		return vm.ErrOutOfGas
	}

	entry, err := getVaultBalanceFromTable(balanceTable, key)
	if err != nil {
		return err
	}

	if contract.Caller() != entry.parentAccount {
		return fmt.Errorf("ParentAccount mismatch")
	}

	gas = gasByteMapReplace(common.HashLength, opEnd-opOffset)
	if !contract.UseGas(gas) {
		return vm.ErrOutOfGas
	}

	entry.operationalAccount = operator
	balanceTable.InsertOrReplaceEntry(key, entry)

	return nil
}

func (v *vault) abiGetBalance(evm *vm.EVM, contract *vm.Contract, keyHash common.Hash) ([]byte, error) {
	balanceTable := Balances(evm.StateDB)
	key := keyHash.Str()

	gas := gasByteMapFind(common.HashLength, vaultBalanceLength)
	if !contract.UseGas(gas) {
		return nil, vm.ErrOutOfGas
	}

	entry, err := getVaultBalanceFromTable(balanceTable, key)
	if err != nil {
		return nil, err
	}
	return common.BigToHash(entry.Balance).Bytes(), nil
}

func (v *vault) abiGetOwner(evm *vm.EVM, contract *vm.Contract, keyHash common.Hash) ([]byte, error) {
	balanceTable := Balances(evm.StateDB)
	key := keyHash.Str()

	gas := gasByteMapFind(common.HashLength, vaultBalanceLength)
	if !contract.UseGas(gas) {
		return nil, vm.ErrOutOfGas
	}

	entry, err := getVaultBalanceFromTable(balanceTable, key)
	if err != nil {
		return nil, err
	}
	return entry.parentAccount.Hash().Bytes(), nil
}

func (v *vault) abiGetOperator(evm *vm.EVM, contract *vm.Contract, keyHash common.Hash) ([]byte, error) {
	balanceTable := Balances(evm.StateDB)
	key := keyHash.Str()

	gas := gasByteMapFind(common.HashLength, vaultBalanceLength)
	if !contract.UseGas(gas) {
		return nil, vm.ErrOutOfGas
	}

	entry, err := getVaultBalanceFromTable(balanceTable, key)
	if err != nil {
		return nil, err
	}
	return entry.operationalAccount.Hash().Bytes(), nil
}

func (v *vault) abiGetAvailableBalance(evm *vm.EVM, contract *vm.Contract, keyHash common.Hash) ([]byte, error) {
	balanceTable := Balances(evm.StateDB)
	key := keyHash.Str()

	gas := gasByteMapFind(common.HashLength, vaultBalanceLength)
	if !contract.UseGas(gas) {
		return nil, vm.ErrOutOfGas
	}

	entry, err := getVaultBalanceFromTable(balanceTable, key)
	if err != nil {
		v.logger.Debug("account not found")
		return nil, err
	}

	// use refund(keyHash) as our refund callback
	refundID, err := VaultABI.Pack("deposit", keyHash)
	if err != nil {
		v.logger.Debug("packing vailed")
		return nil, errors.New("pack failed")
	}

	// forward call the getAvailableStake
	stakeQueryMethod := ElectionABI.Methods["getAvailableStake"]
	ret, err := evmABICall(evm, contract, commElectionAddress, big.NewInt(0), gasRead, &stakeQueryMethod, refundID)
	if err != nil {
		v.logger.Debug("get available stake failed")
		return nil, err
	}

	// add our own balance
	bidBalance := common.BytesToHash(ret).Big()

	retValue := big.NewInt(0).Add(entry.Balance, bidBalance)

	return common.BigToHash(retValue).Bytes(), nil
}
