package thundervm

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"
	"path"

	"github.com/ethereum/go-ethereum/thunder/thunderella/config"

	"github.com/ethereum/go-ethereum/thunder/thunderella/election"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/stretchr/testify/require"
)

// fakeMessage helps us to test EVM contracts outside of actual EVM
type fakeMessage struct {
	from     common.Address
	to       common.Address
	value    *big.Int
	input    []byte
	nonce    uint64
	gasPrice *big.Int
}

func newFakeMessage(from, to common.Address, value *big.Int, input []byte, nonce uint64) *fakeMessage {

	return &fakeMessage{
		from:     from,
		to:       to,
		value:    value,
		input:    input,
		nonce:    nonce,
		gasPrice: big.NewInt(1),
	}
}

// /	From() common.Address
func (fm *fakeMessage) From() common.Address {
	return fm.from
}

func (fm *fakeMessage) To() *common.Address {
	return &fm.to
}

func (fm *fakeMessage) GasPrice() *big.Int {
	return fm.gasPrice
}

func (fm *fakeMessage) Gas() uint64 {
	return 40000000 // 100 * 400'000 for refund
}

func (fm *fakeMessage) Value() *big.Int {
	return fm.value
}

func (fm *fakeMessage) Nonce() uint64 {
	return fm.nonce
}

func (fm *fakeMessage) CheckNonce() bool {
	return true
}

func (fm *fakeMessage) Data() []byte {
	return fm.input
}

func (fm *fakeMessage) AccessList() types.AccessList {
	return types.AccessList{}
}

func (fm *fakeMessage) GasFeeCap() *big.Int {
	return nil
}

func (fm *fakeMessage) GasTipCap() *big.Int {
	return nil
}

func (fm *fakeMessage) IsFake() bool {
	return true
}

// run runs an EVM msg call in on provided chain and state
func run(chain *core.BlockChain, state vm.StateDB, msg core.Message) ([]byte, uint64, error) {
	header := &types.Header{
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(0).Add(chain.CurrentHeader().Number, big.NewInt(1)),
		GasLimit:   65535,
		Time:       100,
	}

	txContext := core.NewEVMTxContext(msg)
	evmContext := core.NewEVMBlockContext(header, chain, nil)
	evm := vm.NewEVM(evmContext, txContext, state, chain.Config(), vm.Config{})

	return evm.Call(vm.AccountRef(msg.From()), *msg.To(), msg.Data(), msg.Gas(), msg.Value())
}

func createContract(chain *core.BlockChain, state vm.StateDB, msg core.Message) (common.Address, error) {
	header := &types.Header{
		Difficulty: big.NewInt(1),
		Number:     big.NewInt(0).Add(chain.CurrentHeader().Number, big.NewInt(1)),
		GasLimit:   65535,
		Time:       100,
	}

	txContext := core.NewEVMTxContext(msg)
	evmContext := core.NewEVMBlockContext(header, chain, nil)
	evm := vm.NewEVM(evmContext, txContext, state, chain.Config(), vm.Config{})

	_, contractAddr, _, err := evm.Create(vm.AccountRef(msg.From()), msg.Data(), msg.Gas(), msg.Value())

	return contractAddr, err
}

const palaR2P5GasTableEnabledSession = 3
const rngV3EnableSession = 4
const rngV4EnableSession = 5

var londonHardorkSession = 3
var vaultR3StartSession = int64(10)
var electionOffsetForTest = config.NewInt64HardforkConfig("thunder.test.unused", "")
var proposerListNameForTest = config.NewStringHardforkConfig("thunder.test.unused2", "")
var maxCodeSizeForTest = config.NewInt64HardforkConfig("thunder.test.unused3", "")
var vaultGasUnlimitedForTest = config.NewBoolHardforkConfig("thunder.test.unused4", "")
var gasTableForTest = config.NewStringHardforkConfig("thunder.test.unused5", "")
var evmHardforkVersion = config.NewStringHardforkConfig("evm.hardforkVersion", "")
var rewardSchemeForTest = config.NewStringHardforkConfig("blockchain.unused.value5", "")
var rngVersionForTest = config.NewStringHardforkConfig("rng.version", "")
var baseFeeForTest = config.NewBigIntHardforkConfig("thunder.test.basefee", "")
var tpcRevertDelegateCallForTest = config.NewBoolHardforkConfig("thunder.test.tpcRevertDelegateCall", "")

func newEnvWithBlockSn(n int, session int64, epoch, S uint32, enableBidVerification bool) (*core.BlockChain, *state.StateDB) {
	// we use ethash.NewFaker() as our consensus engine here instead of thunder consensus engine
	// to avoid a circular dependency. We never actually make a block in these tests so the engine
	// never gets used and therefore it doesn't matter what it is.
	memdb, chain, _ := core.NewThunderCanonical(ethash.NewFaker(), 0, true)
	state, _ := chain.State()
	chain.Config().Thunder.PalaBlock = new(big.Int).SetInt64(int64(n))
	chain.Config().Thunder.RNGVersion = rngVersionForTest

	stopBlockOffset := big.NewInt(25)

	electionOffsetForTest.SetTestValueAtSession(stopBlockOffset.Int64(), 0)
	maxCodeSizeForTest.SetTestValueAtSession(102400, 0)
	rewardSchemeForTest.SetTestValueAtSession("thunderella", 0)
	vaultGasUnlimitedForTest.SetTestValueAtSession(true, 0)

	rngVersionForTest.SetTestValueAtSession("v1", 0)
	rngVersionForTest.SetTestValueAtSession("v3", rngV3EnableSession)
	rngVersionForTest.SetTestValueAtSession("v4", rngV4EnableSession)
	evmHardforkVersion.SetTestValueAtSession("", 0)
	evmHardforkVersion.SetTestValueAtSession("london", int64(londonHardorkSession))
	gasTableForTest.SetTestValueAtSession("", 0)
	gasTableForTest.SetTestValueAtSession("pala-r2.1", palaR2P5GasTableEnabledSession)

	tpcRevertDelegateCallForTest.SetTestValueAtSession(false, 0)
	IsRNGActive.SetTestValueAtSession(true, 0)
	IsRNGActive.SetTestValueAt(true, 0)

	var gwei *big.Int = big.NewInt(1000000000)
	baseFee := new(big.Int).Mul(big.NewInt(10), gwei)
	baseFeeForTest.SetTestValueAtSession(baseFee, 0)

	IsBlockSnGetterActive.SetTestValueAtSession(false, 0)
	VaultVersion.SetTestValueAtSession("", 0)
	VaultVersion.SetTestValueAtSession("r3", vaultR3StartSession)
	ElectionVersion.SetTestValueAtSession("", 0)

	chain.Config().Thunder.VerifyBidSession = uint32(VerifyBid.GetEnabledSession())
	chain.Config().Thunder.IsInConsensusTx = func(evm params.Evm) bool { return true }
	chain.Config().Thunder.BidVerificationEnabled = func() bool { return enableBidVerification }
	chain.Config().Thunder.GetSessionFromDifficulty = func(df, bn *big.Int, cfg *params.ThunderConfig) uint32 { return uint32(session) }
	chain.Config().Thunder.GetBlockSnFromDifficulty = func(i1, i2 *big.Int, tc *params.ThunderConfig) (uint32, uint32, uint32) {
		return uint32(session), epoch, S
	}
	chain.Config().Thunder.ElectionStopBlockSessionOffset = electionOffsetForTest
	chain.Config().Thunder.ProposerListName = proposerListNameForTest
	chain.Config().Thunder.MaxCodeSize = maxCodeSizeForTest
	chain.Config().Thunder.VaultGasUnlimited = vaultGasUnlimitedForTest
	chain.Config().Thunder.GasTable = gasTableForTest
	chain.Config().Thunder.EVMHardforkVersion = evmHardforkVersion
	chain.Config().Thunder.BaseFee = baseFeeForTest
	chain.Config().Thunder.TPCRevertDelegateCall = tpcRevertDelegateCallForTest

	blocks, _ := core.GenerateChain(chain.Config(), chain.Genesis(), chain.Engine(), memdb, n, nil)
	chain.InsertChain(blocks)

	return chain, state
}

// newEnv creates a new environment and state
func newEnv(n int, session int64, enableBidVerification bool) (*core.BlockChain, *state.StateDB) {
	return newEnvWithBlockSn(n, session, 0, 0, enableBidVerification)
}

func compileSol(req *require.Assertions, contractName, sol string, solcversion string) string {
	tmpDir, err := ioutil.TempDir("", "sol")
	req.NoError(err)
	defer os.RemoveAll(tmpDir)

	buf := bytes.NewBufferString(sol)
	cmd := exec.Command("solc", "--bin", "-o", tmpDir, "-")
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, fmt.Sprintf("SOLC_VERSION=%v", solcversion))
	cmd.Stdin = buf
	// var stderr bytes.Buffer
	// cmd.Stderr = &stderr
	err = cmd.Run()
	// fmt.Printf("stderr = %s\n", stderr.String())
	req.NoError(err)

	outFile := fmt.Sprintf("%s.bin", contractName)
	outFile = path.Join(tmpDir, outFile)
	code, err := ioutil.ReadFile(outFile)
	req.NoError(err)
	return string(code)
}

func getStakeInfoSignature(stake *big.Int, coinbase common.Address, gasPrice *big.Int, votingKey bls.BlsSigner, session, nonce *big.Int) *bls.Signature {

	stakeInfo := &election.SignedStakeInfo{
		StakeInfo: election.StakeInfo{
			StakeMsg: election.StakeMsg{
				Stake:      stake,
				Coinbase:   coinbase,
				GasPrice:   gasPrice,
				PubVoteKey: votingKey.GetPublicKey(),
			},
		},
		Session: session,
		Nonce:   nonce,
	}
	stakeInfo.Sign(votingKey)
	return stakeInfo.Sig
}
