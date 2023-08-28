package blockchain

import (
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/vm"
)

type TraceTransactionResult struct {
	Type                   string          `json:"type"`
	CallType               *string         `json:"callType,omitempty"`
	From                   common.Address  `json:"from"`
	To                     *common.Address `json:"to,omitempty"`
	Value                  *hexutil.Big    `json:"value"`
	Error                  *string         `json:"error,omitempty"`
	TraceAddress           []uint64        `json:"traceAddress"`
	Gas                    hexutil.Uint64  `json:"gas"`
	GasUsed                hexutil.Uint64  `json:"gasUsed"`
	CreatedContractAddress *common.Address `json:"createdContractAddressHash,omitempty"`
	Input                  string          `json:"input,omitempty"`
	Init                   hexutil.Bytes   `json:"init,omitempty"`
	Output                 string          `json:"output,omitempty"`
	CreatedContractCode    hexutil.Bytes   `json:"createdContractCode,omitempty"`

	InputHex     hexutil.Bytes             `json:"-"`
	OutputHex    hexutil.Bytes             `json:"-"`
	Calls        []*TraceTransactionResult `json:"-"`
	OutputOffset uint64                    `json:"-"`
	OutputLength uint64                    `json:"-"`
}

type scanTracer struct {
	root      *TraceTransactionResult
	callStack []*TraceTransactionResult
}

func NewScanTracer() *scanTracer {
	return &scanTracer{
		callStack: []*TraceTransactionResult{&TraceTransactionResult{}},
	}
}

func (t *scanTracer) putError(err error) {
	if len(t.callStack) > 1 {
		t.putErrorInTopCall(err)
	} else {
		t.putErrorInBottomCall(err)
	}
}

func (t *scanTracer) putErrorInTopCall(err error) {
	call := t.popCallStack()
	t.putErrorInCall(err, call)
	t.pushChildCall(call)
}

func (t *scanTracer) putErrorInBottomCall(err error) {
	t.putErrorInCall(err, t.bottomCall())
}

func (t *scanTracer) putErrorInCall(err error, call *TraceTransactionResult) {
	errorString := err.Error()
	call.Error = &errorString
	if call.Gas != 0 {
		call.GasUsed = call.Gas
	}
}

func (t *scanTracer) popCallStack() *TraceTransactionResult {
	call := t.topCall()
	t.callStack = t.callStack[:len(t.callStack)-1]
	return call
}

func (t *scanTracer) pushCallStack(call *TraceTransactionResult) {
	t.callStack = append(t.callStack, call)
}

func (t *scanTracer) topCall() *TraceTransactionResult {
	return t.callStack[len(t.callStack)-1]
}

func (t *scanTracer) bottomCall() *TraceTransactionResult {
	return t.callStack[0]
}

func (t *scanTracer) pushChildCall(child *TraceTransactionResult) {
	t.topCall().Calls = append(t.topCall().Calls, child)
}

func (t *scanTracer) putBottomChildCalls(call *TraceTransactionResult) {
	calls := t.bottomCall().Calls

	if len(calls) != 0 {
		call.Calls = calls
	}
}

func (t *scanTracer) pushGasToTopCall(gas, cost uint64) {
	topCall := t.topCall()

	if topCall.Gas == 0 {
		topCall.Gas = hexutil.Uint64(gas)
	}
	topCall.GasUsed = topCall.Gas - hexutil.Uint64(gas) - hexutil.Uint64(cost)
}

func (t *scanTracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	var (
		init           []byte          = nil
		inputData      []byte          = nil
		createdAddress *common.Address = nil
		callType       *string         = nil
		toAddress      *common.Address = nil
	)

	call := strings.ToLower(vm.CALL.String())
	if create {
		call = strings.ToLower(vm.CREATE.String())
		init = input
		createdAddress = &to
	} else {
		inputData = input
		callType = &call
		toAddress = &to
	}

	t.root = &TraceTransactionResult{
		Type:                   call,
		CallType:               callType,
		CreatedContractAddress: createdAddress,
		From:                   from,
		To:                     toAddress,
		InputHex:               inputData,
		Init:                   init,
		Value:                  (*hexutil.Big)(new(big.Int).Set(value)),
		TraceAddress:           []uint64{},
		Gas:                    hexutil.Uint64(gas),
	}
}

func (t *scanTracer) beforeOp(env *vm.EVM, pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	if depth < len(t.callStack) {
		call := t.popCallStack()
		ret := scope.Stack.Back(0)

		if !ret.IsZero() {
			if call.Type == strings.ToLower(vm.CREATE.String()) ||
				call.Type == strings.ToLower(vm.CREATE2.String()) {
				createdAddress := common.HexToAddress(ret.Hex())
				call.CreatedContractCode = env.StateDB.GetCode(createdAddress)
				call.CreatedContractAddress = &createdAddress
			} else {
				call.OutputHex = scope.Memory.GetCopy(int64(call.OutputOffset), int64(call.OutputLength))
			}
		} else if call.Error != nil {
			s := "internal failure"
			call.Error = &s
		}

		t.pushChildCall(call)
	} else {
		t.pushGasToTopCall(gas, cost)
	}
}

func (t *scanTracer) CaptureState(env *vm.EVM, pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	if err != nil {
		t.CaptureFault(env, pc, op, gas, cost, scope, depth, err)
		return
	}

	t.beforeOp(env, pc, op, gas, cost, scope, rData, depth, err)

	switch op {
	case vm.CREATE:
		t.createOp(op, pc, gas, cost, scope, depth)
	case vm.CREATE2:
		t.create2Op(op, pc, gas, cost, scope, depth)
	case vm.SELFDESTRUCT:
		t.selfDestructOp(env, op, pc, gas, cost, scope, depth)
	case vm.CALL, vm.CALLCODE, vm.DELEGATECALL, vm.STATICCALL:
		t.callOp(env, op, pc, gas, cost, scope, depth)
	case vm.REVERT:
		t.revertOp(op, pc, gas, cost, scope, depth)
	}
}

func (t *scanTracer) createOp(op vm.OpCode, pc uint64, gas, cost uint64, scope *vm.ScopeContext, depth int) {
	inputOffset := scope.Stack.Back(1)
	inputLength := scope.Stack.Back(2)
	value := scope.Stack.Back(0)

	call := &TraceTransactionResult{
		Type:  strings.ToLower(vm.CREATE.String()),
		From:  scope.Contract.Address(),
		Init:  scope.Memory.GetCopy(int64(inputOffset.Uint64()), int64(inputLength.Uint64())),
		Value: (*hexutil.Big)(value.ToBig()),
	}

	t.pushCallStack(call)
}

func (t *scanTracer) create2Op(op vm.OpCode, pc uint64, gas, cost uint64, scope *vm.ScopeContext, depth int) {
	inputOffset := scope.Stack.Back(1)
	inputLength := scope.Stack.Back(2)
	value := scope.Stack.Back(0)

	call := &TraceTransactionResult{
		Type:  strings.ToLower(vm.CREATE2.String()),
		From:  scope.Contract.Address(),
		Init:  scope.Memory.GetCopy(int64(inputOffset.Uint64()), int64(inputLength.Uint64())),
		Value: (*hexutil.Big)(value.ToBig()),
	}

	t.pushCallStack(call)
}

func (t *scanTracer) selfDestructOp(env *vm.EVM, op vm.OpCode, pc uint64, gas, cost uint64, scope *vm.ScopeContext, depth int) {
	contractAddress := scope.Contract.Address()
	toAddress := common.HexToAddress(scope.Stack.Back(0).Hex())

	callType := strings.ToLower(vm.SELFDESTRUCT.String())

	t.pushChildCall(&TraceTransactionResult{
		Type:     callType,
		CallType: &callType,
		From:     contractAddress,
		To:       &toAddress,
		Gas:      hexutil.Uint64(gas),
		GasUsed:  hexutil.Uint64(cost),
		Value:    (*hexutil.Big)(env.StateDB.GetBalance(contractAddress)),
	})
}

func (t *scanTracer) callOp(env *vm.EVM, op vm.OpCode, pc uint64, gas, cost uint64, scope *vm.ScopeContext, depth int) {
	toAddress := common.HexToAddress(scope.Stack.Back(1).Hex())

	thunderConfig := env.ChainConfig().Thunder
	session := thunderConfig.GetSessionFromDifficulty(env.Context.Difficulty, env.Context.BlockNumber, thunderConfig)
	rules := env.ChainConfig().Rules(env.Context.BlockNumber, session)
	precompiled := vm.ActivePrecompiles(rules)

	for _, precompileAddress := range precompiled {
		if toAddress == precompileAddress {
			return
		}
	}

	thunderPrecompiles := vm.AllThunderPrecompiledContracts
	_, isThunderPrecompiled := thunderPrecompiles[toAddress]

	if isThunderPrecompiled {
		return
	}

	t.customOp(env, op, pc, gas, cost, scope, depth, toAddress)
}

func (t *scanTracer) customOp(env *vm.EVM, op vm.OpCode, pc uint64, gas, cost uint64, scope *vm.ScopeContext, depth int, toAddress common.Address) {
	stackOffset := 1
	if op == vm.DELEGATECALL || op == vm.STATICCALL {
		stackOffset = 0
	}
	inputOffset := scope.Stack.Back(2 + stackOffset)
	inputLength := scope.Stack.Back(3 + stackOffset)

	callType := strings.ToLower(op.String())

	call := &TraceTransactionResult{
		Type:         strings.ToLower(vm.CALL.String()),
		CallType:     &callType,
		From:         scope.Contract.Address(),
		To:           &toAddress,
		InputHex:     scope.Memory.GetCopy(int64(inputOffset.Uint64()), int64(inputLength.Uint64())),
		OutputOffset: scope.Stack.Back(4 + stackOffset).Uint64(),
		OutputLength: scope.Stack.Back(5 + stackOffset).Uint64(),
	}

	switch op {
	case vm.CALL, vm.CALLCODE:
		call.Value = (*hexutil.Big)(scope.Stack.Back(2).ToBig())
	case vm.DELEGATECALL:
	case vm.STATICCALL:
		call.Value = (*hexutil.Big)(big.NewInt(0))
	default:
		logger.Error("Unknown call type", "op", op)
	}

	t.pushCallStack(call)
}

func (t *scanTracer) revertOp(op vm.OpCode, pc uint64, gas, cost uint64, scope *vm.ScopeContext, depth int) {
	s := "execution reverted"
	t.topCall().Error = &s
}

func (t *scanTracer) CaptureFault(env *vm.EVM, pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, depth int, err error) {
	if t.topCall().Error == nil {
		t.putError(err)
	}
}

func (t *scanTracer) CaptureEnd(output []byte, gasUsed uint64, cost time.Duration, err error) {
	if err != nil {
		errStr := err.Error()
		t.root.Error = &errStr
	} else {
		if t.root.CreatedContractAddress != nil {
			t.root.CreatedContractCode = output
		} else {
			t.root.OutputHex = output
		}
	}

	t.root.GasUsed = hexutil.Uint64(gasUsed)
	t.putBottomChildCalls(t.root)
}

func (t *scanTracer) GetResults() []*TraceTransactionResult {
	return t.sequence(t.root, []*TraceTransactionResult{}, t.root.Value, []uint64{})
}

func (t *scanTracer) sequence(call *TraceTransactionResult, callSeq []*TraceTransactionResult, availableValue *hexutil.Big, traceAddress []uint64) []*TraceTransactionResult {
	subcalls := call.Calls
	call.Calls = nil

	call.TraceAddress = traceAddress

	if call.Type == strings.ToLower(vm.CALL.String()) && (call.CallType != nil && *call.CallType == strings.ToLower(vm.DELEGATECALL.String())) {
		call.Value = availableValue
	}

	// any call type except CREATE should have input value
	if call.Type != strings.ToLower(vm.CREATE.String()) {
		call.Input = call.InputHex.String()
	}

	// only successful CALL, DELEGATECALL, CALLCODE has output value
	if call.CallType != nil && call.Error == nil &&
		(*call.CallType == strings.ToLower(vm.CALL.String()) ||
			*call.CallType == strings.ToLower(vm.DELEGATECALL.String()) ||
			*call.CallType == strings.ToLower(vm.CALLCODE.String()) ||
			*call.CallType == strings.ToLower(vm.STATICCALL.String())) {
		call.Output = call.OutputHex.String()
	}

	newCallSeq := append(callSeq, call)

	if len(subcalls) != 0 {
		for i, subcall := range subcalls {
			nestedSeq := t.sequence(
				subcall,
				newCallSeq,
				call.Value,
				append(traceAddress, uint64(i)),
			)
			newCallSeq = nestedSeq
		}
	}
	return newCallSeq
}
