// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of // MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package thunder implements the proof-of-stake consensus engine.
package thunder

import (
	// Standard imports
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chain"
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chainconfig"
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"
	"github.com/ethereum/go-ethereum/thunder/thunderella/testutils"
	"github.com/ethereum/go-ethereum/thunder/thunderella/thundervm/reward"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	// Vendor imports
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
)

const (
	// Future block time is large for now, and can be reconfigured at a later date
	allowedFutureBlockTime = 365 * 24 * 3600 * time.Second
)

var (
	zeroUncleHash          = types.EmptyUncleHash
	defaultCoinbaseAddress = chainconfig.TestnetTxnFeeAddr
	unityDifficulty        = big.NewInt(1)

	// Used by ethhash for DAO header
	zeroExtraData = make([]byte, 0)

	// Various error messages to mark blocks invalid.
	// These should only be referenced in this package
	errUnknownBlock = errors.New("block number is nil")

	errSealOperationOnGenesisBlock = errors.New(
		"verifySeal/Seal operations on genesis block not permitted")

	// Errors for unused fields not set to zero/empty
	errNonEmptyUncleHash = errors.New("non empty uncle hash")
	errNonDefaultAddress = errors.New("non default coinbase address")
	errNonZeroDifficulty = errors.New("non zero difficulty")
	errNonEmptyExtra     = errors.New("non empty extra")
	stlogger             = lgr.NewLgr("/PST")
)

///////////////////////////////////////////////////////////////////////
// Protocol Special Transaction
///////////////////////////////////////////////////////////////////////

// STProcessor Protocol special transaction processor
type STProcessor struct {
	// committee information during committee switch interval.
	// on init it's the last committee, after ST elects new committee,
	// it will get updated from election result
	isPala    bool
	engClient EngineClient // check if it's a stop block.
}

// Process executes special transactions, e.g. distribute transaction fees to committees.
func (s *STProcessor) Process(
	chainReader consensus.ChainHeaderReader, header *types.Header,
	state *state.StateDB, txs []*types.Transaction, receipts []*types.Receipt,
) {
	if s.isPala {
		s.processPala(chainReader, header, state, txs, receipts)
		return
	}
	s.processThunderZeroPointFive(chainReader, header, state, txs, receipts)
}

func (s *STProcessor) processThunderZeroPointFive(
	chainReader consensus.ChainHeaderReader, header *types.Header,
	state *state.StateDB, txs []*types.Transaction, receipts []*types.Receipt,
) {
	debug.Bug("Don't expect to enter 0.5 logic")

	commInfo := s.engClient.GetBlockCommittee(header, state)
	parentHeader := chainReader.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parentHeader == nil {
		stlogger.Warn("This logic is only for test: get parentHeader from currentHeader")
		parentHeader = chainReader.CurrentHeader()
	}

	stlogger.Info("process block %v nonce %v parentNonce %v txs %v receipts %v committee %v",
		header.Number.Uint64(), header.Nonce.Uint64(), parentHeader.Nonce.Uint64(),
		len(txs), len(receipts), len(commInfo.MemberInfo))

	reward.UpdateFees(
		state, txs, receipts, commInfo.ClearingGasPrice(), commInfo.AccelGasPrice())

	if !committee.IsBoundary(header, parentHeader) {
		return
	}

	bc := chainReader.(*core.BlockChain)
	config := bc.Config()
	fakegp := new(core.GasPool).AddGas(math.MaxUint64)

	// needing to write to blockchain in Finalize step of consensus is exception thunder behavior
	// it was easier for us just to typecast here than to try and modify the ethereum interface
	// to support blockchain read/write in consensus interface
	// at block boundary, run Thunder CommElection precompiled smart contract
	stlogger.Info("commElection block %v nonce %v parentNonce %v",
		header.Number.Uint64(), header.Nonce.Uint64(),
		parentHeader.Nonce.Uint64())

	// Note, we allow 0 gas price here and gas limit is 21000 (intrinsic gas)
	// the PSTAddr does NOT need any money in it because 21000*0 = 0
	msg := types.NewMessage(testutils.PSTAddr, &chainconfig.CommElectionTPCAddress,
		state.GetNonce(testutils.PSTAddr), big.NewInt(0), params.TxGas,
		big.NewInt(0), nil, nil, []byte{}, types.AccessList{}, true)

	txContext := core.NewEVMTxContext(msg)
	evmContext := core.NewEVMBlockContext(header, bc, &chainconfig.CommElectionTPCAddress)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vm := vm.NewEVM(evmContext, txContext, state, config, vm.Config{})
	if _, err := core.ApplyMessage(vm, msg, fakegp); err != nil {
		debug.Bug("could not apply PST, %s", err)
	}

	// distribute rewards to previous committee members then write to stateDB
	reward.Distribute(commInfo, state)
}

func (s *STProcessor) processPala(
	chainReader consensus.ChainHeaderReader, header *types.Header,
	state *state.StateDB, txs []*types.Transaction, receipts []*types.Receipt,
) {
	// update STProcessor's commInfo, this has to be done after reward is distributed
	// since we distribute to previous committee
	// TODO (frog): change s.commInfo into s.genesisCommInfo when removing 0.5 code.
	currentInfo := s.engClient.GetBlockCommittee(header, state)

	session := int64(chainReader.Config().Thunder.GetSessionFromDifficulty(header.Difficulty, header.Number, chainReader.Config().Thunder))

	stlogger.Info("process block %v txs %v receipts %v committee %v blocktime %s",
		header.Number.Uint64(), len(txs), len(receipts), len(currentInfo.MemberInfo), time.Unix(int64(header.Time), 0))

	rewardScheme := chainReader.Config().Thunder.RewardScheme.GetValueAtSession(session)
	switch rewardScheme {
	case "thunderella":
		reward.UpdateFees(
			state, txs, receipts, currentInfo.ClearingGasPrice(), currentInfo.AccelGasPrice())
	case "pala-r2.1":
		reward.UpdateFeesR2P5(state, txs, receipts)
	case "inflation":
		inflation := chainReader.Config().Thunder.TokenInflation.GetValueAtSession(session)
		if s.engClient.IsAfterStopBlockHeader(header, false) {
			inflation = common.Big0
		}
		commRewardRatio := chainReader.Config().Thunder.CommitteeRewardRatio.GetValueAtSession(session)
		reward.UpdateFeesR4(state, txs, receipts, inflation, header.BaseFee, commRewardRatio)
	default:
		debug.Bug("Unsupported reward scheme.")
	}

	if !s.engClient.IsStopBlockHeader(header) {
		return
	}

	bc := chainReader.(*core.BlockChain)
	config := bc.Config()
	fakegp := new(core.GasPool).AddGas(math.MaxUint64)

	// needing to write to blockchain in Finalize step of consensus is exception thunder behavior
	// it was easier for us just to typecast here than to try and modify the ethereum interface
	// to support blockchain read/write in consensus interface
	// at block boundary, run Thunder CommElection precompiled smart contract
	stlogger.Info("commElection block %v", header.Number.Uint64())

	tmpBase := header.BaseFee
	header.BaseFee = common.Big0
	defer func() {
		header.BaseFee = tmpBase
	}()

	// Note, we allow 0 gas price here and gas limit is 21000 (intrinsic gas)
	// the PSTAddr does NOT need any money in it because 21000*0 = 0
	msg := types.NewMessage(testutils.PSTAddr, &chainconfig.CommElectionTPCAddress,
		state.GetNonce(testutils.PSTAddr), big.NewInt(0), params.TxGas,
		common.Big0, common.Big0, common.Big0, []byte{}, types.AccessList{}, true)

	txContext := core.NewEVMTxContext(msg)
	evmContext := core.NewEVMBlockContext(header, bc, &chainconfig.CommElectionTPCAddress)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vm := vm.NewEVM(evmContext, txContext, state, config, vm.Config{})
	if _, err := core.ApplyMessage(vm, msg, fakegp); err != nil {
		debug.Bug("could not apply PST, %s", err)
	}

	// distribute rewards to previous committee members then write to stateDB
	switch rewardScheme {
	case "pala-r2.1", "thunderella":
		reward.Distribute(currentInfo, state)
	case "inflation":
		reward.DistributeR4(currentInfo, state)
	}
}

// Stopblockchecker checks if input block number is a stop block return false if not or not sure yet.
type StopBlockChecker interface {
	IsStopBlockHeader(*types.Header) bool
	IsAfterStopBlockHeader(*types.Header, bool) bool
}

type CommitteeGetter interface {
	GetBlockCommittee(header *types.Header, stateDb *state.StateDB) *committee.CommInfo
}

type EngineClient interface {
	CommitteeGetter
	StopBlockChecker
}

// Thunder is the proof-of-stake consensus engine.
type Thunder struct {
	config      *params.ThunderConfig // Consensus engine configuration parameters
	stProcessor *STProcessor          // Consensus engine special transaction processor
	privateApi  *PrivateApi           // Respond RPC requests for internal usages.
	publicApi   *PublicApi            // Respond RPC requests for public usages.
}

type RpcDelegate interface {
	GetStatus() (interface{}, error)
	GetMetrics() (interface{}, error)
	GetTxPoolStatus() (interface{}, error)
	GetCommInfo(uint32) (interface{}, error)
	GetCommInfoByNumber(int64) (interface{}, error)
	SetHead(uint64) error
	IsReadyForService(minHeightDiff uint64) (interface{}, error)
	GetReward(int64) (interface{}, error)
	TraceTxRoute(waitingSeconds uint8) (interface{}, error)
	GetBlockSnByNumber(n uint64) (interface{}, error)
	GetBlockInfo(rpc.BlockNumber) (interface{}, error)
	GetNumberByBlockSn(session, epoch, s uint32) (interface{}, error)
	GetTtTransfersByBlockNumber(number uint64) (interface{}, error)
	GetPalaMetaForSnapshot() (interface{}, error)
	GetTrieStateForSnapshot([]common.Hash) (interface{}, error)
	GetTtBlockForSnapshot(uint64) (interface{}, error)
	GetTotalSupply(rpc.BlockNumber) (interface{}, error)
	GetTotalFeeBurned(rpc.BlockNumber) (interface{}, error)
	GetTotalInflation(rpc.BlockNumber) (interface{}, error)
	// GetSessionStatus return the start block, stop block, end block and K value in the given session
	GetSessionStatus(uint32) (interface{}, error)
	GetBidStatus(rpc.BlockNumber) (interface{}, error)
}

// New creates a Thunder proof-of-stake consensus engine.
func New(config *params.ThunderConfig) *Thunder {
	return &Thunder{
		config:      config,
		stProcessor: &STProcessor{isPala: config.PalaBlock != nil},
		privateApi:  &PrivateApi{},
		publicApi:   &PublicApi{},
	}
}

func (thunder *Thunder) SetEngineClient(engClient EngineClient) {
	thunder.stProcessor.engClient = engClient
}

func getLatestCommSwitchHeaderThunderZeroPointFive(bc *core.BlockChain) *types.Header {
	seq := bc.CurrentBlock().NumberU64()
	if seq < 2 {
		return nil
	}
	for {
		hdr1 := bc.GetHeaderByNumber(seq)
		hdr2 := bc.GetHeaderByNumber(seq - 1)
		if committee.IsBoundary(hdr1, hdr2) {
			return hdr1
		}
		seq--
		if seq < 2 {
			return nil
		}
	}
}

func slowChainHeightFromHdr(h *types.Header) chain.Height {
	return chain.Height(h.Nonce.Uint64())
}

func GetLatestCommSwitchHeight(sc StopBlockChecker, bc *core.BlockChain) chain.Height {
	// TODO: unify getLatestCommSwitch code using StopBlockChecker
	var h *types.Header
	if sc != nil {
		return 0
	}

	h = getLatestCommSwitchHeaderThunderZeroPointFive(bc)
	if h == nil {
		return 0
	}

	return slowChainHeightFromHdr(h)
}

//////////////////////////////////
// consensus.Engine implementation
//////////////////////////////////

// Author implements consensus.Engine.
func (thunder *Thunder) Author(header *types.Header) (common.Address, error) {
	return defaultCoinbaseAddress, nil
}

// CalcDifficulty implements consensus.Engine
// CalcDifficulty is used for difficulty adjustment in PoW algorithms, and
// is not needed for PoS consensus schemes.
func (thunder *Thunder) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64,
	parent *types.Header) *big.Int {
	return big.NewInt(0)

}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (thunder *Thunder) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header,
	seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error)

	go func() {
		for i, header := range headers {
			var parent *types.Header
			if i == 0 {
				parent = chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
			} else {
				parent = headers[i-1]
			}
			var err error
			if parent == nil {
				err = consensus.ErrUnknownAncestor
			} else {
				err = thunder.verifyHeader(chain, parent, header, seals[i])
			}

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

func verifyHeaderUnusedFieldsAreDefault(header *types.Header, config *params.ThunderConfig) error {
	// Ensure that the block doesn't contain any uncles which are meaningless in PoA
	if header.UncleHash != zeroUncleHash {
		return errNonEmptyUncleHash
	}
	if header.Coinbase != defaultCoinbaseAddress {
		return errNonDefaultAddress
	}

	if !config.IsPala(header.Number) && header.Difficulty.Cmp(unityDifficulty) != 0 {
		return errNonZeroDifficulty
	}

	session := config.GetSessionFromDifficulty(header.Difficulty, header.Number, config)
	if !config.IsConsensusInfoInHeader.GetValueAtSession(int64(session)) && !bytes.Equal(header.Extra, zeroExtraData) {
		return errNonEmptyExtra
	}
	return nil
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (thunder *Thunder) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header,
	seal bool) error {
	if header.Number == nil {
		return errUnknownBlock
	}
	// If the block already exists, skip verification
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}
	if chain.GetHeader(header.Hash(), number) != nil {
		return nil
	}
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}

	return thunder.verifyHeader(chain, parent, header, seal)
}

func (thunder *Thunder) verifyHeader(chain consensus.ChainHeaderReader, parent *types.Header,
	header *types.Header, seal bool) error {
	// Verify that the block number is parent's +1
	if diff := new(big.Int).Sub(header.Number, parent.Number); diff.Cmp(big.NewInt(1)) != 0 {
		return consensus.ErrInvalidNumber
	}
	// Don't check future blocks.
	if header.Time > uint64(time.Now().Add(allowedFutureBlockTime).Unix()) {
		return consensus.ErrFutureBlock
	}
	// check that the new block's timestamp is strictly greater than it's parents
	if header.Time <= parent.Time {
		return fmt.Errorf("block timestamp (%d) <= parent's timestamp (%d)",
			header.Time, parent.Time)
	}
	if err := verifyHeaderUnusedFieldsAreDefault(header, chain.Config().Thunder); err != nil {
		return err
	}
	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed,
			header.GasLimit)
	}
	// Verify the engine specific seal securing the block
	if seal {
		if err := thunder.VerifySeal(chain, header); err != nil {
			return err
		}
	}

	return nil
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (thunder *Thunder) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// VerifySeal implements consensus.Engine.
// In thunder protocol, we don't store signed proposals in the block.
func (thunder *Thunder) VerifySeal(chain consensus.ChainHeaderReader, header *types.Header) error {
	// Verifying the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errSealOperationOnGenesisBlock
	}
	return nil
}

// All header fields which are not relevant in Thunder protocol are set to predefined zero values.
func setHeaderUnusedFieldsToDefault(header *types.Header, config *params.ThunderConfig) {
	header.UncleHash = zeroUncleHash
	header.Coinbase = defaultCoinbaseAddress
	if !config.IsPala(header.Number) {
		header.Difficulty = unityDifficulty
	}

	session := config.GetSessionFromDifficulty(header.Difficulty, header.Number, config)
	if !config.IsConsensusInfoInHeader.GetValueAtSession(int64(session)) {
		header.Extra = zeroExtraData
	}
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (thunder *Thunder) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	setHeaderUnusedFieldsToDefault(header, chain.Config().Thunder)
	number := header.Number.Uint64()

	// Ensure the timestamp has the correct delay
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	return nil
}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given, and returns the final block.
func (thunder *Thunder) Finalize(chain consensus.ChainHeaderReader, header *types.Header,
	state *state.StateDB, txs []*types.Transaction, _ []*types.Header,
) {
	panic("should use FinalizeAndAssemble instead of Finalize")
}

// FinalizeAndAssemble implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given, and returns the final block.
func (thunder *Thunder) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header,
	state *state.StateDB, txs []*types.Transaction, _ []*types.Header, receipts []*types.Receipt,
) (*types.Block, error) {
	thunder.stProcessor.Process(chain, header, state, txs, receipts)
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	setHeaderUnusedFieldsToDefault(header, chain.Config().Thunder)

	// Assemble and return the final block for sealing
	return types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil)), nil
}

// Seal implements consensus.Engine.
// 'stop' channel is not important in case of thunder protocol. Its only use is to abort mining
// before the nonce is found (see ethhash/consensus.go)
// Note that we seal the blocks irrespective of transaction count i.e. can be 0, that's because
// thunder protocol may need to seal empty block if an alive message is due,
// but there are no transactions.
// TODO: document contract with callee
func (thunder *Thunder) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block,
	stop <-chan struct{}) error {
	header := block.Header()

	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errSealOperationOnGenesisBlock
	}

	results <- block.WithSeal(header)
	return nil
}

// SealHash returns the hash of a block prior to it being sealed.
func (thunder *Thunder) SealHash(header *types.Header) common.Hash {
	return common.Hash{}
}

// Close implements consensus.Engine close. Thunder does not have background threads
func (thunder *Thunder) Close() error {
	return nil
}

func (thunder *Thunder) SetRPCDelegate(d RpcDelegate) {
	thunder.privateApi.rpcDelegate = d
	thunder.publicApi.rpcDelegate = d
}

// APIs implements consensus.Engine, returning the user facing RPC API to allow
// controlling the signer voting.
func (thunder *Thunder) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	if chain != nil && chain.Config().Thunder.PalaBlock != nil {
		return []rpc.API{
			{
				Namespace: "dev",
				Version:   "0.6",
				Service:   thunder.privateApi,
				Public:    false,
			},
			{
				Namespace: "thunder",
				Version:   "0.6",
				Service:   thunder.publicApi,
				Public:    true,
			},
		}
	}

	return nil
}

// GetThunderEngine get consensus engine from core.BlockChain and cast
// it to thunder consensus engine.
func GetThunderEngine(bc *core.BlockChain) *Thunder {
	return bc.Engine().(*Thunder)
}

////////////////////////////////////////////////////////////////////////
// Test support functions
////////////////////////////////////////////////////////////////////////

// MakeThunderTestChain create a core.BlockChain object using thunder
// consensus engine for testing
func MakeThunderTestChain() (
	ethdb.Database, *core.BlockChain, error) {
	return MakeThunderTestChainWithBlocks(0)
}

// MakeThunderTestChain create a core.BlockChain object using thunder
// consensus engine for testing
func MakeThunderTestChainWithBlocks(blocks int) (ethdb.Database, *core.BlockChain, error) {
	isConsensusInfoInHeader := config.NewBoolHardforkConfig("consensus.in.header", "")
	isConsensusInfoInHeader.SetTestValueAtSession(false, 0)

	db, bc, err := core.NewThunderCanonical(New(&params.ThunderConfig{}), blocks, true)

	bc.Config().Thunder.GetSessionFromDifficulty = func(_, _ *big.Int, _ *params.ThunderConfig) uint32 { return 0 }
	bc.Config().Thunder.GetBlockSnFromDifficulty = func(_, _ *big.Int, _ *params.ThunderConfig) (uint32, uint32, uint32) { return 0, 0, 0 }
	bc.Config().Thunder.IsConsensusInfoInHeader = isConsensusInfoInHeader

	return db, bc, err
}

type FakeEngineClient struct{}

func (f *FakeEngineClient) IsStopBlockHeader(*types.Header) bool {
	utils.EnsureRunningInTestCode()
	return false
}

func (f *FakeEngineClient) GetBlockCommittee(header *types.Header, stateDb *state.StateDB) *committee.CommInfo {
	utils.EnsureRunningInTestCode()
	return &testutils.TestingCommInfo
}

func (f *FakeEngineClient) IsAfterStopBlockHeader(*types.Header, bool) bool {
	utils.EnsureRunningInTestCode()
	return false
}
