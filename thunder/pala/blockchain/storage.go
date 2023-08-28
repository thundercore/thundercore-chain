package blockchain

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math/big"
	"strconv"
	"sync"

	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/consensus/thunder"
	"github.com/ethereum/go-ethereum/thunder/thunderella/election"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/thundervm"
	"github.com/ethereum/go-ethereum/thunder/thunderella/thundervm/reward"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	"golang.org/x/xerrors"
)

var InitialSupply = big.NewInt(0)

// StorageImpl Data Integrity Design
// The only two kinds of write operations into offchain data are:
//  1. AddNotarization(): add notarization uses a batch atomic commit when updating notarization, freshest notarization head, and finalized head.
//     The geth uses to record its "canonical chain" must also be kept consistent when adding a notarization but is not updated in the same commit.
//     We maintain canonical chain data integrity by doing data recovery between `bc.CurrentBlock()` and `storage.GetFreshestNotarization` on our initial
//     call of `integrityCheck()`.
//  2. InsertBlock() & WriteBlockWithState(): When writing, we first insert the block into `core.BlockChain` then write our block index (BlockSn)
//     When reading, we always read the index and block in reverse order, so altough the block insertion and index write is not one
//     atomic operation, data integrity is still maintained.
type StorageImpl struct {
	db                  ethdb.Database
	bc                  *core.BlockChain
	k                   *config.Int64HardforkConfig
	marshaller          DataUnmarshaller
	genesisCommInfo     *committee.CommInfo
	alternativeCommInfo map[string]*committee.CommInfo
	palaFromGenesis     bool
	cachedStopBlock     Block
	cachedStopBlockLock sync.Mutex
	tracerCache         *tracerCache
}

type StorageConfig struct {
	Db              ethdb.Database
	Bc              *core.BlockChain
	Marshaller      DataUnmarshaller
	Info            *committee.CommInfo
	AlterInfo       map[string]*committee.CommInfo
	PalaFromGenesis bool

	UnnotarizedWindow *config.Int64HardforkConfig

	TracerCacheSize int64
}

type GenesisConfig struct {
	GenesisCommPath string
}

func (s *StorageImpl) GetThunderConfig() *params.ThunderConfig {
	return s.bc.Config().Thunder
}

func (s *StorageImpl) GetBlock(sn BlockSn) Block {
	if !sn.IsGenesis() && !sn.IsPala() && s.bc.Config().Thunder.IsPala(new(big.Int).SetUint64(uint64(sn.S))) {
		return nil
	}
	block := readBlock(s.db, sn, s.bc)
	return block
}

func (s *StorageImpl) GetHeader(sn BlockSn) Header {
	if !sn.IsGenesis() && !sn.IsPala() && s.bc.Config().Thunder.IsPala(new(big.Int).SetUint64(uint64(sn.S))) {
		return nil
	}
	header := readHeader(s.db, sn, s.bc)
	if header == nil {
		return nil
	}
	return newHeader(header, s.bc.Config().Thunder)
}

func (s *StorageImpl) GetNotarization(sn BlockSn) Notarization {
	return readNotarization(s.db, s.marshaller, sn)
}

func (s *StorageImpl) GetHeaderByNumber(number uint64) Header {
	header := s.bc.GetHeaderByNumber(number)
	if header == nil {
		return nil
	}
	return newHeader(header, s.bc.Config().Thunder)
}

func (s *StorageImpl) GetRawBlockBody(hash Hash) []byte {
	return s.bc.GetBodyRLP(common.Hash(hash))
}

func (s *StorageImpl) GetRawNotarization(sn BlockSn) []byte {
	return readRawNotarization(s.db, sn)
}

func (s *StorageImpl) InsertBlock(block Block) error {
	b := block.(*blockImpl).B
	chain := make([]*types.Block, 0, 1)
	chain = append(chain, b)

	_, err := s.bc.InsertChain(chain)
	if err != nil && err != core.ErrKnownBlock {
		return err
	}

	// NOTE: we ensure write the block meta after insert the block into chain.
	// So if we crash here, we don't need to recovery.
	batch := s.db.NewBatch()

	if err := s.handleStopBlock(batch, block); err != nil {
		return err
	}

	if err := writeBlockMeta(batch, block); err != nil {
		return err
	}

	if err := batch.Write(); err != nil {
		return err
	}

	return nil
}

func (s *StorageImpl) writeBlockWithState(block Block, receipts []*types.Receipt, logs []*types.Log, state *state.StateDB) error {
	b := block.(*blockImpl).B
	for _, r := range receipts {
		for _, l := range r.Logs {
			l.BlockHash = b.Hash()
		}
	}

	_, err := s.bc.WriteBlockWithState(b, receipts, logs, state, true)
	if err != nil {
		logger.Error("Failed writing block(seq: %d) to chain: %s", b.NumberU64(), err)
		return err
	}

	batch := s.db.NewBatch()

	if err := s.handleStopBlock(batch, block); err != nil {
		return err
	}

	if err := writeBlockMeta(batch, block); err != nil {
		return err
	}

	if err := batch.Write(); err != nil {
		return err
	}

	return nil
}

func (s *StorageImpl) handleStopBlock(writer ethdb.KeyValueWriter, block Block) error {
	b := block.(*blockImpl).B
	sn := block.GetBlockSn()
	parentSn := block.GetParentBlockSn()

	if s.IsStopBlockHeader(b.Header()) {
		if err := writeSessionStopBlockNumber(writer, sn.Epoch.Session, b.NumberU64()); err != nil {
			return err
		}
	}

	if !parentSn.IsPala() {
		if header, _ := readSessionStopHeader(s.db, parentSn.Epoch.Session); header == nil {
			if err := writeSessionStopBlockNumber(writer, parentSn.Epoch.Session, b.NumberU64()-1); err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *StorageImpl) AddNotarization(nota Notarization) (BlockSn, BlockSn, error) {
	var freshestExt, finalExt BlockSn
	sn := nota.GetBlockSn()
	batch := s.db.NewBatch()
	oldFreshest := readFreshestNotarization(s.db)

	s.cachedStopBlockLock.Lock()
	defer s.cachedStopBlockLock.Unlock()

	if err := writeNotarization(batch, sn, nota); err != nil {
		return BlockSn{}, BlockSn{}, err
	}

	k := uint32(s.k.GetValueAtSession(int64(sn.Epoch.Session)))

	if sn.Compare(oldFreshest) > 0 {
		if err := writeFreshestNotarization(batch, sn); err != nil {
			return BlockSn{}, BlockSn{}, err
		}
		freshestExt = sn

		// only try to extend finalized when extending freshest
		if sn.S > k {
			candidate := sn
			candidate.S -= k
			oldFinal := readFinalizedBlockSn(s.db)
			if candidate.Compare(oldFinal) > 0 {
				if err := writeFinalizeBlockSn(batch, candidate); err != nil {
					return BlockSn{}, BlockSn{}, err
				}
				finalExt = candidate
				s.cachedStopBlock = nil
			}
		}
	}

	if err := batch.Write(); err != nil {
		return BlockSn{}, BlockSn{}, err
	}

	if freshestExt != (BlockSn{}) {
		block := readBlock(s.db, sn, s.bc)
		// We handle notarization here
		// NOTE: we change the canonical chain after notarization is added
		// If we crash before this write,
		// `StorageImpl.recoverFreshestNotarizationChainIfNeeded()` would recover this write.
		if err := s.bc.WriteKnownBlock(block.(*blockImpl).B); err != nil {
			return BlockSn{}, BlockSn{}, err
		}

		if sn.Epoch.Session == oldFreshest.Epoch.Session {
			oldHeader := readHeader(s.db, oldFreshest, s.bc)
			hdr := readHeader(s.db, sn, s.bc)
			for hdr.Number.Cmp(oldHeader.Number) > 0 {
				h := newHeader(hdr, s.bc.Config().Thunder)
				hdr = readHeader(s.db, h.GetParentBlockSn(), s.bc)
			}
			if hdr.Hash() != oldHeader.Hash() {
				logger.Note("Head-fork switch from %s to %s", oldFreshest, sn)
			}
		}
	}

	return freshestExt, finalExt, nil

}

func (s *StorageImpl) GetFreshestNotarizedHeadSn() BlockSn {
	return readFreshestNotarization(s.db)
}

func (s *StorageImpl) GetFreshestNotarizedHeadInfo() BlockInfo {
	sn := s.GetFreshestNotarizedHeadSn()
	header := readHeader(s.db, sn, s.bc)
	if header == nil {
		debug.Bug("failed to get the header of the freshest notarized head %s", sn)
	}
	return BlockInfo{
		Sn:     sn,
		Number: header.Number.Uint64(),
		Hash:   Hash(header.Hash()),
	}
}

func (s *StorageImpl) GetGenesisBlock() Block {
	return newBlock(s.bc.Genesis(), s.bc.Config().Thunder)
}

// Note that genesis block or the last block in thunder 0.5
// is not a finalized stop block.
func (s *StorageImpl) GetLatestFinalizedStopBlock() Block {
	s.cachedStopBlockLock.Lock()
	defer s.cachedStopBlockLock.Unlock()

	if s.cachedStopBlock != nil {
		return s.cachedStopBlock
	}

	return s.updateLatestFinalizedStopBlockIfNeeded()
}

func (s *StorageImpl) updateLatestFinalizedStopBlockIfNeeded() Block {
	sn := readFinalizedBlockSn(s.db)
	es := updateEpochStatusIfNotExisted(s.db, s.marshaller)
	for session := es.epoch.Session; session > 0; session-- {
		if header, stopSn := readSessionStopHeader(s.db, session); header != nil {
			if sn.Compare(stopSn) >= 0 {
				b := s.GetBlock(stopSn)
				s.cachedStopBlock = b
				return b
			}
		}
	}
	return nil
}

func (s *StorageImpl) GetBlockByNumber(number uint64) Block {
	b := s.bc.GetBlockByNumber(number)
	if b == nil {
		return nil
	}
	return newBlock(b, s.bc.Config().Thunder)
}

func (s *StorageImpl) GetCommInfo(session Session) *committee.CommInfo {
	h, _ := readSessionStopHeader(s.db, session-1)
	var (
		statedb *state.StateDB
		err     error
	)
	if h == nil {
		statedb, err = s.bc.State()
	} else {
		statedb, err = s.bc.StateAt(h.Root)
	}
	if err != nil {
		debug.Bug("Failed to get statedb")
	}

	proposers := s.genesisCommInfo.AccelInfo
	name := s.bc.Config().Thunder.ProposerListName.GetValueAtSession(int64(session))
	if name != "" {
		if p, ok := s.alternativeCommInfo[name]; ok {
			proposers = p.AccelInfo
		} else {
			debug.Bug("Missing consensus setting config: proposer list name %q", name)
		}
	}

	cInfo := s.getCommInfo(statedb, proposers)
	if cInfo == nil {
		debug.Bug("Cannot get election result from state")
	}

	return cInfo
}

func (s *StorageImpl) GetClearingGasPrice(session Session) *big.Int {
	if s.genesisCommInfo == nil && utils.InTest() {
		// We may use the real BlockChain with VerifierFake.
		return big.NewInt(1)
	}

	info := s.GetCommInfo(session)
	if info == nil {
		logger.Warn("session %d does not have comm info", session)
		return big.NewInt(1)
	}

	return info.ClearingGasPrice()
}

func (s *StorageImpl) getElectionResult(statedb *state.StateDB) *election.Result {
	raw := thundervm.ElectionResults(statedb).ToSlice()

	if len(raw) == 0 {
		return nil
	}

	result := election.Result{}
	err := result.FromBytes(raw[0])
	if err != nil {
		return nil
	}
	return &result
}

func NewGenesisCommInfo(cfg GenesisConfig) (*committee.CommInfo, error) {
	cInfo := &committee.CommInfo{}
	data, err := ioutil.ReadFile(cfg.GenesisCommPath)
	if err != nil {
		return nil, xerrors.Errorf("failed to read JSON file %q: %w", cfg.GenesisCommPath, err)
	}
	err = cInfo.FromJSON(data)
	if err != nil {
		return nil, xerrors.Errorf("FromJSON failed for CommInfo: %w", err)
	}

	return cInfo, nil
}

func (s *StorageImpl) getCommInfo(statedb *state.StateDB, proposers []committee.AccelInfo) *committee.CommInfo {
	result := s.getElectionResult(statedb)
	if result != nil {
		cInfo := &committee.CommInfo{}
		cInfo.AccelInfo = proposers
		cInfo.MemberInfo = result.Members
		return cInfo
	}
	if s.palaFromGenesis {
		cInfo := &committee.CommInfo{}
		if s.genesisCommInfo == nil {
			debug.Bug("genesisCommInfo doesn't exist")
		}
		cInfo.MemberInfo = append(cInfo.MemberInfo, s.genesisCommInfo.MemberInfo...)
		cInfo.AccelInfo = proposers
		return cInfo
	}

	return nil
}

func (s *StorageImpl) GetProposerAddresses(session Session) map[ConsensusId]string {
	cInfo := s.GetCommInfo(session)
	r := make(map[ConsensusId]string)
	for _, a := range cInfo.AccelInfo {
		r[ConsensusIdFromPubKey(a.PubVoteKey)] = a.HostPort
	}

	return r
}

// Note that genesis block or the last block in thunder 0.5
// is not a finalized stop block.
func (s *StorageImpl) IsStopBlockHeader(header *types.Header) bool {
	number := header.Number.Uint64()
	if !s.bc.Config().Thunder.IsPala(header.Number) {
		logger.Warn("(*StorageImpl).IsStopBlockHeader(seq: %d) called before palaHardfork", number)
		return false
	}

	sessionOffset := header.Nonce.Uint64()
	session := s.bc.Config().Thunder.GetSessionFromDifficulty(header.Difficulty, header.Number, s.bc.Config().Thunder)
	offset := s.bc.Config().Thunder.ElectionStopBlockSessionOffset.GetValueAtSession(int64(session))

	return sessionOffset == uint64(offset)
}

func (s *StorageImpl) IsAfterStopBlockHeader(header *types.Header, includingStopBlock bool) bool {
	number := header.Number.Uint64()
	if !s.bc.Config().Thunder.IsPala(header.Number) {
		logger.Warn("(*StorageImpl).IsStopBlockHeader(seq: %d) called before palaHardfork", number)
		return false
	}

	sessionOffset := header.Nonce.Uint64()
	session := s.bc.Config().Thunder.GetSessionFromDifficulty(header.Difficulty, header.Number, s.bc.Config().Thunder)
	offset := uint64(s.bc.Config().Thunder.ElectionStopBlockSessionOffset.GetValueAtSession(int64(session)))

	if includingStopBlock {
		return sessionOffset >= offset
	}
	return sessionOffset > offset
}

// Note that genesis block or the last block in thunder 0.5
// is not a finalized stop block.
func (s *StorageImpl) IsStopBlock(block Block) bool {
	header := block.(*blockImpl).B.Header()
	return s.IsStopBlockHeader(header)
}

func (s *StorageImpl) IsAfterStopBlock(block Block, includingStopBlock bool) bool {
	header := block.(*blockImpl).B.Header()
	return s.IsAfterStopBlockHeader(header, includingStopBlock)
}

func (s *StorageImpl) GetFinalizedHeadSn() BlockSn {
	return readFinalizedBlockSn(s.db)
}

func NewStorage(cfg StorageConfig) *StorageImpl {
	s := &StorageImpl{
		db:                  cfg.Db,
		bc:                  cfg.Bc,
		marshaller:          cfg.Marshaller,
		genesisCommInfo:     cfg.Info,
		alternativeCommInfo: cfg.AlterInfo,
		palaFromGenesis:     cfg.PalaFromGenesis,
		k:                   cfg.UnnotarizedWindow,
		tracerCache:         newTracerCache(cfg.TracerCacheSize),
	}

	s.bc.SetValidator(WithConsensusTxValidator(core.NewBlockValidator(s.bc.Config(), s.bc, s.bc.Engine())))

	if tEngine, ok := s.bc.Engine().(*thunder.Thunder); ok {
		tEngine.SetEngineClient(s)
	}

	s.ensureIntegrity()

	return s
}

func (s *StorageImpl) ensureIntegrity() {
	s.recoverFreshestNotarizationChainIfNeeded()
	s.recoverLocalEpochIfNeeded()
}

func (s *StorageImpl) recoverFreshestNotarizationChainIfNeeded() {
	sn := readFreshestNotarization(s.db)
	block := newBlock(s.bc.CurrentBlock(), s.bc.Config().Thunder)
	if block.GetBlockSn().Compare(sn) != 0 {
		logger.Warn("The head of the canonical chain is inconsistent: geth=%s, pala=%s",
			block.GetBlockSn(), sn)
		blk := readBlock(s.db, sn, s.bc)
		if blk == nil {
			debug.Bug("Recovery failed: readBlock cannot get the block")
		}

		var finalSn BlockSn
		if block.GetBlockSn().Compare(sn) < 0 {
			if err := s.bc.WriteKnownBlock(blk.(*blockImpl).B); err != nil {
				debug.Bug("Recovery failed: WriteKnownBlock(%s):%s", sn, err)
			}
			finalSn = sn
		} else {
			if err := s.bc.SetHead(blk.GetNumber()); err != nil {
				debug.Bug("Recovery failed:SetHead(%s):%s", blk.GetNumber(), err)
			}
			finalSn = blk.GetBlockSn()
		}
		logger.Warn("fixed freshest notarized head: %s", finalSn)
	}
}

func (s *StorageImpl) recoverLocalEpochIfNeeded() {
	e := readEpochStatus(s.db, s.marshaller)
	if e == nil {
		// Do nothing at the first time
		return
	}
	headE := s.GetFreshestNotarizedHeadInfo().Sn.Epoch
	if e.epoch != headE {
		logger.Warn(
			"local epoch %s != head's epoch %s, override the local epoch by the head's epoch",
			e.epoch, headE)
		es := &epochStatus{
			epoch:     headE,
			clockNota: readClockMsgNotarization(s.db, s.marshaller, headE),
		}

		if err := writeEpochStatus(s.db, es); err != nil {
			debug.Bug("Cannot write local epoch to %s: %s", headE, err)
		}
	}
}

// setHead() deletes the nota and index in (number, currentHeadNumber]
// and set the fresh nota and recalculate finalized chain
func (s *StorageImpl) setHead(number uint64) {
	logger.Warn("rewind head to number(%d)", number)
	if !s.bc.Config().Thunder.IsPala(new(big.Int).SetUint64(number)) {
		debug.Bug("Not support to set a number before Pala.")
	}

	batch := s.db.NewBatch()

	blk := s.GetBlock(s.GetFreshestNotarizedHeadSn())
	if blk.GetNumber() <= number {
		return
	}

	for blk.GetNumber() > number {
		parentSn := blk.GetParentBlockSn()
		sn := blk.GetBlockSn()
		deleteBlockMeta(batch, sn)
		deleteNotarization(batch, sn)
		blk = s.GetBlock(parentSn)

		if batch.ValueSize() > ethdb.IdealBatchSize {
			if err := batch.Write(); err != nil {
				debug.Bug("Cannot write the batch while setHead to %s.", sn)
			}
			batch.Reset()
		}
	}

	sn := blk.GetBlockSn()
	logger.Warn("rewind head to %s", sn)

	if err := writeFreshestNotarization(batch, sn); err != nil {
		debug.Bug("Cannot rewind head to %s", sn)
	}

	e := sn.Epoch
	k := uint32(s.k.GetValueAtSession(int64(e.Session)))

	for blk.GetBlockSn().S <= k {
		blk = s.GetBlock(blk.GetParentBlockSn())
		if !blk.GetBlockSn().IsPala() {
			break
		}
	}

	sn = blk.GetBlockSn()
	if blk.GetBlockSn().IsPala() {
		// in thunder 0.5, blocks are always considered finalized
		sn.S -= k
	}

	logger.Warn("rewind finalized to %s", sn)

	if err := writeFinalizeBlockSn(batch, sn); err != nil {
		debug.Bug("Cannot rewind finalized head to %s", sn)
	}

	es := &epochStatus{
		epoch:     e,
		clockNota: readClockMsgNotarization(s.db, s.marshaller, e),
	}

	if err := writeEpochStatus(batch, es); err != nil {
		debug.Bug("Cannot rewind finalized head to %s", sn)
	}

	if err := batch.Write(); err != nil {
		debug.Bug("Cannot write the batch while setHead to %s.", sn)
	}

	if err := s.bc.SetHead(number); err != nil {
		debug.Bug("Cannot call core.BlockChain.SetHead(%d): %s", number, err)
	}
}

func (s *StorageImpl) GetReward(number uint64) (*reward.Results, error) {
	h := s.GetHeaderByNumber(number)
	if h == nil {
		return nil, xerrors.Errorf("Cannot find header for block number %d", number)
	}
	header := h.(*headerImpl).H
	if !s.IsStopBlockHeader(header) {
		return nil, xerrors.Errorf("Block number %d is not stop block", number)
	}
	commInfo := s.GetCommInfo(h.GetBlockSn().Epoch.Session)
	state, err := s.bc.StateAt(header.Root)
	if err != nil {
		return nil, err
	}
	return reward.GetPreviousDistribution(commInfo, state)
}

func (s *StorageImpl) GetBlockCommittee(header *types.Header, stateDb *state.StateDB) *committee.CommInfo {
	blockSn := GetBlockSnFromDifficulty(header.Difficulty, header.Number, s.bc.Config().Thunder)
	return s.GetCommInfo(blockSn.Epoch.Session)
}

type TtTransferWithHash struct {
	From    common.Address  `json:"from"`
	To      *common.Address `json:"to,omitempty"`
	Value   *hexutil.Big    `json:"value,omitempty"`
	Error   *string         `json:"error,omitempty"`
	Reason  *string         `json:"reason,omitempty"`
	OpCode  string          `json:"opCode"`
	Indices []uint64        `json:"indices"`
	Gas     hexutil.Uint64  `json:"gas"`
	GasUsed hexutil.Uint64  `json:"gasUsed"`
	Hash    common.Hash     `json:"hash"`
}

func (s *StorageImpl) GetTtTransfersByBlockNumber(number uint64) ([]TtTransferWithHash, error) {
	block := s.bc.GetBlockByNumber(number)
	if block == nil {
		return nil, ErrBlockNotFound
	}
	hash := block.Hash()
	r, err := s.tracerCache.get(number, hash)
	if err != nil {
		if err != ErrBlockNotFound {
			return nil, err
		}
		logger.Info("Tracer cache missed on block #%d(%s)", number, hash.Hex())
		r, err = s.getTtTransfersByBlockNumberInternal(number)
		if err != nil {
			return nil, err
		}
		s.tracerCache.put(number, hash, r)
	} else {
		logger.Info("Tracer cache hit on block #%d(%s)", number, hash.Hex())
	}

	return r, nil
}

func appendTransfer(ori []TtTransferWithHash, transfer *VmCall, h common.Hash) []TtTransferWithHash {
	var hv *hexutil.Big
	if transfer.OpCode != "DELEGATECALL" && transfer.OpCode != "STATICCALL" {
		var v big.Int
		v.Set(transfer.Value)
		hv = new(hexutil.Big)
		*hv = (hexutil.Big)(v)
	}
	withHash := TtTransferWithHash{
		From:    transfer.From,
		To:      transfer.To,
		Value:   hv,
		OpCode:  transfer.OpCode,
		Indices: transfer.Indices,
		Gas:     hexutil.Uint64(transfer.Gas),
		GasUsed: hexutil.Uint64(transfer.GasUsed),
		Hash:    h,
	}
	if transfer.Error != nil && len(*transfer.Error) != 0 {
		withHash.Error = transfer.Error
	}
	if transfer.Reason != nil && len(*transfer.Reason) != 0 {
		withHash.Reason = transfer.Reason
	}
	return append(ori, withHash)
}

// Reference from Ethereum.stateAtTransaction(...)
func (s *StorageImpl) getTtTransfersByBlockNumberInternal(number uint64) ([]TtTransferWithHash, error) {
	block := s.bc.GetBlockByNumber(number)
	parent := s.bc.GetBlockByNumber(number - 1)
	if block == nil || parent == nil {
		return nil, ErrBlockNotFound
	}

	statedb, err := s.bc.StateAt(parent.Root())
	if err != nil {
		return nil, xerrors.Errorf("Block (%s) truncated, we only support archive mode.", parent.Hash())
	}

	ret := make([]TtTransferWithHash, 0)
	header := block.Header()
	blockSn := GetBlockSnFromDifficulty(header.Difficulty, header.Number, s.bc.Config().Thunder)
	signer := types.MakeSigner(s.bc.Config(), block.Number(), uint32(blockSn.Epoch.Session))
	for idx, tx := range block.Transactions() {
		msg, _ := tx.AsMessage(signer, block.BaseFee())
		txContext := core.NewEVMTxContext(msg)
		evmContext := core.NewEVMBlockContext(block.Header(), s.bc, nil)

		trace := &tracer{}
		// Not yet the searched for transaction, execute on top of the current state
		vmenv := vm.NewEVM(evmContext, txContext, statedb, s.bc.Config(), vm.Config{
			Debug:  true,
			Tracer: trace,
		})
		statedb.Prepare(tx.Hash(), idx)
		execResult, err := core.ApplyMessage(vmenv, msg, new(core.GasPool).AddGas(tx.Gas()))
		if err != nil {
			return nil, fmt.Errorf("transaction %#x failed: %v", tx.Hash(), err)
		}
		transfers := trace.getTransfers()
		transfers[0].Gas = tx.Gas()
		transfers[0].GasUsed = execResult.UsedGas

		for _, transfer := range transfers {
			ret = appendTransfer(ret, transfer, tx.Hash())
		}

		// Ensure any modifications are committed to the state
		statedb.IntermediateRoot(true)
	}

	return ret, nil
}

// For storage snapshot
type PalaMeta struct {
	BlockSn
	RawBlockMeta     []byte
	RawNotarization  []byte
	SessionStopBlock []byte
}

type TtBlockForSnapshot struct {
	Header        *types.Header
	BlockBody     *types.Body
	Receipts      types.Receipts
	CanonicalHash common.Hash
	Td            string
	IsPala        bool
	BlockNumber   *uint64
	*PalaMeta
}

func WritePalaMeta(snapshotDb DatabaseWriter, palaMeta map[string][]byte) (uint64, error) {
	snInByte, ok := palaMeta[string(freshestNotarizedHead)]
	if !ok {
		return 0, xerrors.Errorf("Frestest nota sn not found")
	}
	sn, _, err := NewBlockSnFromBytes(snInByte)
	if err != nil {
		return 0, err
	}

	logger.Info("Fresh notarized head: %v\n", sn.String())

	lastStopBlockSn, _, err := NewBlockSnFromBytes(palaMeta["lastStopBlockSn"])
	if err != nil {
		return 0, err
	}

	stopKey := sessionStopKey(lastStopBlockSn.GetBlockSn().Epoch.Session)
	sessionStopBlk := palaMeta[string(sessionStopBlockPrefix)]
	logger.Info("Write session stop block: %v\n", lastStopBlockSn.String())
	if err := snapshotDb.Put(stopKey, sessionStopBlk); err != nil {
		return 0, err
	}

	if _, err := sn.Epoch.PreviousEpoch(); err == nil {
		notaKey := clockMsgNotaKey(sn.Epoch)
		clockMsgNota := palaMeta[string(clockNotarizationPrefix)]
		logger.Info("Write clock message nota: %v\n", sn.Epoch.String())
		if err := snapshotDb.Put(notaKey, clockMsgNota); err != nil {
			return 0, err
		}
	}

	keys := [][]byte{
		freshestNotarizedHead,
		finalizedSnKey,
		epochStatusKey,
		schemaVersionKey,
	}

	for _, key := range keys {
		var keyBuf bytes.Buffer
		keyBuf.Write(key)

		if value, ok := palaMeta[keyBuf.String()]; ok {
			logger.Info("Write pala meta %s", keyBuf.String())
			if err := snapshotDb.Put(key, value); err != nil {
				return 0, err
			}
		} else {
			logger.Error("Meta key `%s` not found", keyBuf.String())
		}
	}

	heightInByte, ok := palaMeta["blockHeight"]
	if !ok {
		return 0, xerrors.Errorf("block height not found")
	}
	height, err := strconv.ParseUint(string(heightInByte), 10, 64)
	if err != nil {
		return 0, err
	}
	return height, nil
}

func (s *StorageImpl) GetPalaMetaForSnapshot(bn rpc.BlockNumber) (map[string][]byte, error) {
	ret := make(map[string][]byte)

	var sn BlockSn
	var lastStopBlock Block
	if bn == rpc.LatestBlockNumber {
		sn = s.GetFreshestNotarizedHeadSn()
		lastStopBlock = s.GetLatestFinalizedStopBlock()
	} else {
		head := s.GetBlockByNumber(uint64(bn.Int64()))
		if head != nil {
			sn = head.GetBlockSn()
		}
		h, stopSn := readSessionStopHeader(s.db, sn.Epoch.Session-1)
		if h == nil {
			return nil, xerrors.Errorf("failed to get last stop block")
		}
		lastStopBlock = s.GetBlock(stopSn)
	}

	block := s.GetBlock(sn)
	ret["blockHeight"] = []byte(strconv.FormatUint(block.GetNumber(), 10))
	ret["lastStopBlockSn"] = lastStopBlock.GetBlockSn().ToBytes()

	if _, err := sn.Epoch.PreviousEpoch(); err == nil {
		// `err == nil` means there existed a previous epoch
		if clkNota, err := readHistoryDatabase(s.db, clockMsgNotaKey(sn.Epoch)); err == nil {
			ret[string(clockNotarizationPrefix)] = clkNota
		} else {
			return ret, xerrors.Errorf(
				"epoch=%v > 1 but clock message nota not found: %s",
				sn.Epoch.String(),
				err.Error(),
			)
		}
	}

	if lastStopBlock != nil {
		sessionKey := sessionStopKey(lastStopBlock.GetBlockSn().Epoch.Session)
		stopBlk, err := readHistoryDatabase(s.db, sessionKey)
		if err != nil {
			return ret, xerrors.Errorf(
				"failed to get last stop block nota %v: %s",
				lastStopBlock.GetBlockSn().String(),
				err.Error(),
			)
		}
		ret[string(sessionStopBlockPrefix)] = stopBlk
	}

	keys := [][]byte{
		freshestNotarizedHead,
		finalizedSnKey,
		epochStatusKey,
		schemaVersionKey,
	}

	for _, key := range keys {
		value, err := readHistoryDatabase(s.db, key)
		if err != nil {
			logger.Error("%s not found: %s", string(key), err.Error())
			continue
		}
		var keyBuf bytes.Buffer
		keyBuf.Write(key)
		ret[keyBuf.String()] = value[:]
	}

	return ret, nil
}

func (s *StorageImpl) GetTrieStateForSnapshot(keys []common.Hash) ([]trie.SyncResult, error) {
	res := make([]trie.SyncResult, len(keys))
	for i, hash := range keys {
		node, err := s.bc.TrieNode(hash)
		if len(node) == 0 || err != nil {
			node, err = s.bc.ContractCodeWithPrefix(hash)
			if err != nil {
				return res, err
			}
		}
		res[i] = trie.SyncResult{Hash: hash, Data: node}
	}
	return res, nil
}

func (s *StorageImpl) GetTtBlockForSnapshot(number uint64) (*TtBlockForSnapshot, error) {
	hash := rawdb.ReadCanonicalHash(s.db, number)
	if hash == (common.Hash{}) {
		return nil, xerrors.Errorf("failed to get canonical hash")
	}
	body := rawdb.ReadBody(s.db, hash, number)
	header := rawdb.ReadHeader(s.db, hash, number)
	receipts := rawdb.ReadReceipts(s.db, hash, number, s.bc.Config())
	td := rawdb.ReadTd(s.db, hash, number).String()

	meta := &PalaMeta{}
	isPala := s.bc.Config().Thunder.IsPala(new(big.Int).SetUint64(number))

	if isPala {
		sn := GetBlockSnFromDifficulty(header.Difficulty, header.Number, s.bc.Config().Thunder)
		blockMeta, err := readHistoryDatabase(s.db, blockSnKey(sn))
		if err != nil {
			logger.Error("Failed to read history database for block sn: %v", sn.String())
			return nil, err
		}

		sessionStopBlock := []byte{}
		if s.IsStopBlockHeader(header) {
			key := sessionStopKey(sn.Epoch.Session)
			sessionStopBlock, err = readHistoryDatabase(s.db, key)
			if err != nil {
				logger.Error("Failed to read history database for session stop: %v", sn.String())
				return nil, err
			}
		}

		meta = &PalaMeta{
			BlockSn:          sn,
			RawNotarization:  readRawNotarization(s.db, sn),
			RawBlockMeta:     blockMeta,
			SessionStopBlock: sessionStopBlock,
		}
	}

	return &TtBlockForSnapshot{
		BlockBody:     body,
		Header:        header,
		Receipts:      receipts,
		Td:            td,
		CanonicalHash: hash,
		PalaMeta:      meta,
		IsPala:        isPala,
		BlockNumber:   &number,
	}, nil
}

// End of storage snapshot

// Start of chain status rpc
type NumericRpcRespnse struct {
	BlockNumber *big.Int
	Result      *big.Int
}

func (s *StorageImpl) GetTotalInflation(bn rpc.BlockNumber) (*NumericRpcRespnse, error) {
	var block *types.Block
	if bn == rpc.LatestBlockNumber {
		block = s.bc.CurrentBlock()
	} else {
		block = s.bc.GetBlockByNumber(uint64(bn.Int64()))
	}
	statedb, err := s.bc.StateAt(block.Root())
	if err != nil {
		return nil, xerrors.Errorf("Block (%v) truncated, we only support archive mode.", err)
	}
	inflation := reward.GetTotalInflation(statedb)
	return &NumericRpcRespnse{block.Number(), inflation}, nil
}

func (s *StorageImpl) GetTotalFeeBurned(bn rpc.BlockNumber) (*NumericRpcRespnse, error) {
	var block *types.Block
	if bn == rpc.LatestBlockNumber {
		block = s.bc.CurrentBlock()
	} else {
		block = s.bc.GetBlockByNumber(uint64(bn.Int64()))
	}
	statedb, err := s.bc.StateAt(block.Root())
	if err != nil {
		return nil, xerrors.Errorf("Block (%v) truncated, we only support archive mode.", err)
	}
	feeBurned := reward.GetTotalFeeBurned(statedb)
	return &NumericRpcRespnse{block.Number(), feeBurned}, nil
}

func (s *StorageImpl) GetTotalSupply(bn rpc.BlockNumber) (*NumericRpcRespnse, error) {
	var block *types.Block
	if bn == rpc.LatestBlockNumber {
		block = s.bc.CurrentBlock()
	} else {
		block = s.bc.GetBlockByNumber(uint64(bn.Int64()))
	}
	statedb, err := s.bc.StateAt(block.Root())
	if err != nil {
		return nil, xerrors.Errorf("Block (%v) truncated, we only support archive mode.", err)
	}
	// totalSupply = initialSupply + inflation - gasBurned
	inflation := reward.GetTotalInflation(statedb)
	gasBurned := reward.GetTotalFeeBurned(statedb)
	supply := new(big.Int).Add(InitialSupply, inflation)
	supply = supply.Sub(supply, gasBurned)
	return &NumericRpcRespnse{block.Number(), supply}, nil
}

type SessionParams struct {
	StopBlockSessionOffset int64
	K                      uint32
}

// GetSessionParams contain StopBlockSessionOffset, K
func (s *StorageImpl) GetSessionParams(session uint32) *SessionParams {
	return &SessionParams{
		StopBlockSessionOffset: s.bc.Config().Thunder.ElectionStopBlockSessionOffset.GetValueAtSession(int64(session)),
		K:                      uint32(s.k.GetValueAtSession(int64(session))),
	}
}

// end of chain status rpc

func (s *StorageImpl) stateAtTransaction(block *types.Block, txIndex int) (core.Message, vm.BlockContext, *state.StateDB, error) {
	// Short circuit if it's genesis block.
	if block.NumberU64() == 0 {
		return nil, vm.BlockContext{}, nil, xerrors.New("no transaction in genesis")
	}
	// Create the parent state database
	parent := s.bc.GetBlockByHash(block.ParentHash())
	if parent == nil {
		return nil, vm.BlockContext{}, nil, fmt.Errorf("parent %#x not found", block.ParentHash())
	}
	// Lookup the statedb of parent block from the live database,
	// otherwise regenerate it on the flight.
	statedb, err := s.bc.StateAt(parent.Root())
	if err != nil {
		return nil, vm.BlockContext{}, nil, err
	}
	if txIndex == 0 && len(block.Transactions()) == 0 {
		return nil, vm.BlockContext{}, statedb, nil
	}
	// // Recompute transactions up to the target index.
	// thunder_patch begin
	header := block.Header()
	blockSn := GetBlockSnFromDifficulty(header.Difficulty, header.Number, s.bc.Config().Thunder)
	signer := types.MakeSigner(s.bc.Config(), block.Number(), uint32(blockSn.Epoch.Session))
	// thunder_patch original
	// signer := types.MakeSigner(eth.blockchain.Config(), block.Number())
	// thunder_patch end
	for idx, tx := range block.Transactions() {
		// Assemble the transaction call message and return if the requested offset
		msg, _ := tx.AsMessage(signer, block.BaseFee())
		txContext := core.NewEVMTxContext(msg)
		context := core.NewEVMBlockContext(block.Header(), s.bc, nil)
		if idx == txIndex {
			return msg, context, statedb, nil
		}
		// Not yet the searched for transaction, execute on top of the current state
		vmenv := vm.NewEVM(context, txContext, statedb, s.bc.Config(), vm.Config{})
		statedb.Prepare(tx.Hash(), idx)
		if _, err := core.ApplyMessage(vmenv, msg, new(core.GasPool).AddGas(tx.Gas())); err != nil {
			return nil, vm.BlockContext{}, nil, fmt.Errorf("transaction %#x failed: %v", tx.Hash(), err)
		}
		// Ensure any modifications are committed to the state
		// Only delete empty objects if EIP158/161 (a.k.a Spurious Dragon) is in effect
		// thunder_patch begin
		statedb.IntermediateRoot(vmenv.ChainConfig().IsEIP158(block.Number()))
		// thunder_patch original
		// statedb.Finalise(vmenv.ChainConfig().IsEIP158(block.Number()))
		// thunder_patch end
	}
	return nil, vm.BlockContext{}, nil, fmt.Errorf("transaction index %d out of range for block %#x", txIndex, block.Hash())
}

func (s *StorageImpl) TraceTransaction(txHash common.Hash) ([]*TraceTransactionResult, error) {
	_, blockHash, blockNumber, index := rawdb.ReadTransaction(s.db, txHash)
	if blockNumber == 0 {
		return nil, xerrors.Errorf("transaction not found")
	}

	block := s.bc.GetBlockByHash(blockHash)
	if block == nil {
		return nil, ErrBlockNotFound
	}

	msg, vmctx, statedb, err := s.stateAtTransaction(block, int(index))
	if err != nil {
		return nil, xerrors.Errorf("failed to get state at transaction: %w", err)
	}

	// Assemble the structured logger or the JavaScript tracer
	txContext := core.NewEVMTxContext(msg)
	tracer := NewScanTracer()

	// Run the transaction with tracing enabled.
	vmenv := vm.NewEVM(vmctx, txContext, statedb, s.bc.Config(), vm.Config{Debug: true, Tracer: tracer, NoBaseFee: true})

	// Call Prepare to clear out the statedb access list
	statedb.Prepare(common.Hash{}, 0)

	_, err = core.ApplyMessage(vmenv, msg, new(core.GasPool).AddGas(msg.Gas()))
	if err != nil {
		return nil, fmt.Errorf("tracing failed: %w", err)
	}

	return tracer.GetResults(), nil
}

type BidStatus struct {
	committee.MemberInfo
	ConsensusId ConsensusId
}

func (s *StorageImpl) GetBidStatus(bn rpc.BlockNumber) ([]*BidStatus, error) {
	var block *types.Block
	if bn == rpc.LatestBlockNumber {
		block = s.bc.CurrentBlock()
	} else {
		block = s.bc.GetBlockByNumber(uint64(bn.Int64()))
	}
	statedb, err := s.bc.StateAt(block.Root())
	if err != nil {
		return nil, xerrors.Errorf("Block (%v) truncated, we only support archive mode.", err)
	}

	bids, err := thundervm.GetCurrentBids(statedb)
	if err != nil {
		return nil, xerrors.Errorf("failed to get bids", err)
	}

	ret := []*BidStatus{}
	for _, bid := range bids {
		memInfo := bid.ToMemberInfo()
		ret = append(ret, &BidStatus{
			*memInfo,
			ConsensusIdFromPubKey(memInfo.PubVoteKey),
		})
	}
	return ret, nil
}
