// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package testutils

import (
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
)

// VaultProxyABI is the input ABI used to generate the binding from.
const VaultProxyABI = "[{\"constant\":true,\"inputs\":[],\"name\":\"operator\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"operationalAccount\",\"type\":\"address\"}],\"name\":\"reset\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"index\",\"type\":\"int256\"},{\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"withdraw\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"name\":\"ownerAccount\",\"type\":\"address\"},{\"name\":\"size\",\"type\":\"uint256\"},{\"name\":\"operators\",\"type\":\"address[]\"},{\"name\":\"votingKeys\",\"type\":\"bytes32[]\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"payable\":true,\"stateMutability\":\"payable\",\"type\":\"fallback\"}]"

// VaultProxyBin is the compiled bytecode used for deploying new contracts.
var VaultProxyBin = "0x608060405273ec45c94322eafeeb2cf441cd1ab9e81e58901a08600560006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555034801561006557600080fd5b50604051610c96380380610c96833981018060405281019080805190602001909291908051906020019092919080518201929190602001805182019291905050506000846000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555083600281905550600090505b83811015610210576003838281518110151561014d57fe5b9060200190602002015190806001815401808255809150509060018203906000526020600020016000909192909190916101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050600482828151811015156101ca57fe5b9060200190602002015190806001815401808255809150509060018203906000526020600020016000909192909190915090600019169055508080600101915050610135565b600090505b6002548110156103fb57600560009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660038281548110151561026757fe5b9060005260206000200160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff166004838154811015156102a157fe5b9060005260206000200154604051602401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018260001916600019168152602001925050506040516020818303038152906040527ff14ddffc000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505060405180828051906020019080838360005b838110156103a1578082015181840152602081019050610386565b50505050905090810190601f1680156103ce5780820380516001836020036101000a031916815260200191505b509150506000604051808303816000865af191505015156103ee57600080fd5b8080600101915050610215565b50505050506108878061040f6000396000f300608060405260043610610062576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063570ca735146102495780636b8ab97d146102a05780638da5cb5b146102e357806393de9b091461033a575b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16141561024657600090505b60025481101561024557600560009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166002543481151561010e57fe5b0460048381548110151561011e57fe5b90600052602060002001546040516024018082600019166000191681526020019150506040516020818303038152906040527fb214faa5000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505060405180828051906020019080838360005b838110156101eb5780820151818401526020810190506101d0565b50505050905090810190601f1680156102185780820380516001836020036101000a031916815260200191505b5091505060006040518083038185875af192505050151561023857600080fd5b80806001019150506100be565b5b50005b34801561025557600080fd5b5061025e610371565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b3480156102ac57600080fd5b506102e1600480360381019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610397565b005b3480156102ef57600080fd5b506102f8610436565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34801561034657600080fd5b5061036f600480360381019080803590602001909291908035906020019092919050505061045b565b005b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b3373ffffffffffffffffffffffffffffffffffffffff166000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff161415156103f257600080fd5b80600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60003373ffffffffffffffffffffffffffffffffffffffff16600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff161415156104b957600080fd5b7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff83141561066c57600090505b60025481101561066757600560009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1660048281548110151561053857fe5b906000526020600020015483604051602401808360001916600019168152602001828152602001925050506040516020818303038152906040527f040cf020000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505060405180828051906020019080838360005b8381101561060d5780820151818401526020810190506105f2565b50505050905090810190601f16801561063a5780820380516001836020036101000a031916815260200191505b509150506000604051808303816000865af1915050151561065a57600080fd5b80806001019150506104e6565b6107d7565b600560009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166004848154811015156106b457fe5b906000526020600020015483604051602401808360001916600019168152602001828152602001925050506040516020818303038152906040527f040cf020000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505060405180828051906020019080838360005b8381101561078957808201518184015260208101905061076e565b50505050905090810190601f1680156107b65780820380516001836020036101000a031916815260200191505b509150506000604051808303816000865af191505015156107d657600080fd5b5b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166108fc3073ffffffffffffffffffffffffffffffffffffffff16319081150290604051600060405180830381858888f19350505050158015610855573d6000803e3d6000fd5b505050505600a165627a7a723058202e6abdad272eb275e5be6e7be84e4bddde3f6eec6e83a94b5bd26032b4ee69090029"

// DeployVaultProxy deploys a new Ethereum contract, binding an instance of VaultProxy to it.
func DeployVaultProxy(auth *bind.TransactOpts, backend bind.ContractBackend, ownerAccount common.Address, size *big.Int, operators []common.Address, votingKeys [][32]byte) (common.Address, *types.Transaction, *VaultProxy, error) {
	parsed, err := abi.JSON(strings.NewReader(VaultProxyABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}

	address, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(VaultProxyBin), backend, ownerAccount, size, operators, votingKeys)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &VaultProxy{VaultProxyCaller: VaultProxyCaller{contract: contract}, VaultProxyTransactor: VaultProxyTransactor{contract: contract}, VaultProxyFilterer: VaultProxyFilterer{contract: contract}}, nil
}

// VaultProxy is an auto generated Go binding around an Ethereum contract.
type VaultProxy struct {
	VaultProxyCaller     // Read-only binding to the contract
	VaultProxyTransactor // Write-only binding to the contract
	VaultProxyFilterer   // Log filterer for contract events
}

// VaultProxyCaller is an auto generated read-only Go binding around an Ethereum contract.
type VaultProxyCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// VaultProxyTransactor is an auto generated write-only Go binding around an Ethereum contract.
type VaultProxyTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// VaultProxyFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type VaultProxyFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// VaultProxySession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type VaultProxySession struct {
	Contract     *VaultProxy       // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// VaultProxyCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type VaultProxyCallerSession struct {
	Contract *VaultProxyCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts     // Call options to use throughout this session
}

// VaultProxyTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type VaultProxyTransactorSession struct {
	Contract     *VaultProxyTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts     // Transaction auth options to use throughout this session
}

// VaultProxyRaw is an auto generated low-level Go binding around an Ethereum contract.
type VaultProxyRaw struct {
	Contract *VaultProxy // Generic contract binding to access the raw methods on
}

// VaultProxyCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type VaultProxyCallerRaw struct {
	Contract *VaultProxyCaller // Generic read-only contract binding to access the raw methods on
}

// VaultProxyTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type VaultProxyTransactorRaw struct {
	Contract *VaultProxyTransactor // Generic write-only contract binding to access the raw methods on
}

// NewVaultProxy creates a new instance of VaultProxy, bound to a specific deployed contract.
func NewVaultProxy(address common.Address, backend bind.ContractBackend) (*VaultProxy, error) {
	contract, err := bindVaultProxy(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &VaultProxy{VaultProxyCaller: VaultProxyCaller{contract: contract}, VaultProxyTransactor: VaultProxyTransactor{contract: contract}, VaultProxyFilterer: VaultProxyFilterer{contract: contract}}, nil
}

// NewVaultProxyCaller creates a new read-only instance of VaultProxy, bound to a specific deployed contract.
func NewVaultProxyCaller(address common.Address, caller bind.ContractCaller) (*VaultProxyCaller, error) {
	contract, err := bindVaultProxy(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &VaultProxyCaller{contract: contract}, nil
}

// NewVaultProxyTransactor creates a new write-only instance of VaultProxy, bound to a specific deployed contract.
func NewVaultProxyTransactor(address common.Address, transactor bind.ContractTransactor) (*VaultProxyTransactor, error) {
	contract, err := bindVaultProxy(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &VaultProxyTransactor{contract: contract}, nil
}

// NewVaultProxyFilterer creates a new log filterer instance of VaultProxy, bound to a specific deployed contract.
func NewVaultProxyFilterer(address common.Address, filterer bind.ContractFilterer) (*VaultProxyFilterer, error) {
	contract, err := bindVaultProxy(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &VaultProxyFilterer{contract: contract}, nil
}

// bindVaultProxy binds a generic wrapper to an already deployed contract.
func bindVaultProxy(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(VaultProxyABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_VaultProxy *VaultProxyRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _VaultProxy.Contract.VaultProxyCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_VaultProxy *VaultProxyRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _VaultProxy.Contract.VaultProxyTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_VaultProxy *VaultProxyRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _VaultProxy.Contract.VaultProxyTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_VaultProxy *VaultProxyCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _VaultProxy.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_VaultProxy *VaultProxyTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _VaultProxy.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_VaultProxy *VaultProxyTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _VaultProxy.Contract.contract.Transact(opts, method, params...)
}

// Operator is a free data retrieval call binding the contract method 0x570ca735.
//
// Solidity: function operator() view returns(address)
func (_VaultProxy *VaultProxyCaller) Operator(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _VaultProxy.contract.Call(opts, &out, "operator")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Operator is a free data retrieval call binding the contract method 0x570ca735.
//
// Solidity: function operator() view returns(address)
func (_VaultProxy *VaultProxySession) Operator() (common.Address, error) {
	return _VaultProxy.Contract.Operator(&_VaultProxy.CallOpts)
}

// Operator is a free data retrieval call binding the contract method 0x570ca735.
//
// Solidity: function operator() view returns(address)
func (_VaultProxy *VaultProxyCallerSession) Operator() (common.Address, error) {
	return _VaultProxy.Contract.Operator(&_VaultProxy.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_VaultProxy *VaultProxyCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _VaultProxy.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_VaultProxy *VaultProxySession) Owner() (common.Address, error) {
	return _VaultProxy.Contract.Owner(&_VaultProxy.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_VaultProxy *VaultProxyCallerSession) Owner() (common.Address, error) {
	return _VaultProxy.Contract.Owner(&_VaultProxy.CallOpts)
}

// Reset is a paid mutator transaction binding the contract method 0x6b8ab97d.
//
// Solidity: function reset(address operationalAccount) returns()
func (_VaultProxy *VaultProxyTransactor) Reset(opts *bind.TransactOpts, operationalAccount common.Address) (*types.Transaction, error) {
	return _VaultProxy.contract.Transact(opts, "reset", operationalAccount)
}

// Reset is a paid mutator transaction binding the contract method 0x6b8ab97d.
//
// Solidity: function reset(address operationalAccount) returns()
func (_VaultProxy *VaultProxySession) Reset(operationalAccount common.Address) (*types.Transaction, error) {
	return _VaultProxy.Contract.Reset(&_VaultProxy.TransactOpts, operationalAccount)
}

// Reset is a paid mutator transaction binding the contract method 0x6b8ab97d.
//
// Solidity: function reset(address operationalAccount) returns()
func (_VaultProxy *VaultProxyTransactorSession) Reset(operationalAccount common.Address) (*types.Transaction, error) {
	return _VaultProxy.Contract.Reset(&_VaultProxy.TransactOpts, operationalAccount)
}

// Withdraw is a paid mutator transaction binding the contract method 0x93de9b09.
//
// Solidity: function withdraw(int256 index, uint256 amount) returns()
func (_VaultProxy *VaultProxyTransactor) Withdraw(opts *bind.TransactOpts, index *big.Int, amount *big.Int) (*types.Transaction, error) {
	return _VaultProxy.contract.Transact(opts, "withdraw", index, amount)
}

// Withdraw is a paid mutator transaction binding the contract method 0x93de9b09.
//
// Solidity: function withdraw(int256 index, uint256 amount) returns()
func (_VaultProxy *VaultProxySession) Withdraw(index *big.Int, amount *big.Int) (*types.Transaction, error) {
	return _VaultProxy.Contract.Withdraw(&_VaultProxy.TransactOpts, index, amount)
}

// Withdraw is a paid mutator transaction binding the contract method 0x93de9b09.
//
// Solidity: function withdraw(int256 index, uint256 amount) returns()
func (_VaultProxy *VaultProxyTransactorSession) Withdraw(index *big.Int, amount *big.Int) (*types.Transaction, error) {
	return _VaultProxy.Contract.Withdraw(&_VaultProxy.TransactOpts, index, amount)
}

// Fallback is a paid mutator transaction binding the contract fallback function.
//
// Solidity: fallback() payable returns()
func (_VaultProxy *VaultProxyTransactor) Fallback(opts *bind.TransactOpts, calldata []byte) (*types.Transaction, error) {
	return _VaultProxy.contract.RawTransact(opts, calldata)
}

// Fallback is a paid mutator transaction binding the contract fallback function.
//
// Solidity: fallback() payable returns()
func (_VaultProxy *VaultProxySession) Fallback(calldata []byte) (*types.Transaction, error) {
	return _VaultProxy.Contract.Fallback(&_VaultProxy.TransactOpts, calldata)
}

// Fallback is a paid mutator transaction binding the contract fallback function.
//
// Solidity: fallback() payable returns()
func (_VaultProxy *VaultProxyTransactorSession) Fallback(calldata []byte) (*types.Transaction, error) {
	return _VaultProxy.Contract.Fallback(&_VaultProxy.TransactOpts, calldata)
}
