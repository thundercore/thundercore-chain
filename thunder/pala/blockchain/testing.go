// Put the fake implementations used by the production code for the integration test.
package blockchain

import (
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/metrics"
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chainconfig"
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/consensus/thunder"
	"github.com/ethereum/go-ethereum/thunder/thunderella/election"
	"github.com/ethereum/go-ethereum/thunder/thunderella/keymanager"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/testutils"
	"github.com/ethereum/go-ethereum/thunder/thunderella/thundervm"
	"github.com/ethereum/go-ethereum/thunder/thunderella/thundervm/reward"
	"github.com/ethereum/go-ethereum/thunder/thunderella/txutils"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"
)

type useNotarization int

const (
	useNotarizationNone     = useNotarization(0)
	useNotarizationInAll    = useNotarization(1)
	useNotarizationInBlocks = useNotarization(2)
)

type BlockFake struct {
	sn       BlockSn
	parentSn BlockSn
	nBlock   uint64
	notas    []Notarization
	cNota    ClockMsgNota
	body     string
	// For special usage. It's not included in the serialization.
	hash       *Hash
	parentHash *Hash
}

// TODO(sonic): embed header in block
type HeaderFake struct {
	BlockFake
}

type NotarizationFake struct {
	sn       BlockSn
	voterIds []ConsensusId
}

type VerifierFake struct {
	mutex         utils.CheckedLock
	myId          ConsensusId
	proposerLists []*ElectionResultFake // history of elected proposers
	voterLists    []*ElectionResultFake // history of elected voters
}

// VerifierFakeBad votes for everything using correct voterId if it is a valid voter or using badVoterId if it is not
// the empty string otherwise. It does the same for clock messages.
// It proposes at every BlockSn using correct proposerId if it is a valid proposer or using bad proposer if it is not
// the empty string otherwise.
// If alwaysBad is true, it will always use badVoterId and badProposerId unless they are the empty string in which
// case it behaves the same as VerifierFake.
// Note that VerifierFakeBad will still verify proposals and voters correctly i.e. it will not verify using
// badVoterId or badProposalId.
type VerifierFakeBad struct {
	VerifierFake
	badVoterId    ConsensusId
	badProposerId ConsensusId
	alwaysBad     bool
}

type ProposalFake struct {
	proposerId ConsensusId
	block      Block
}

type VoteFake struct {
	sn      BlockSn
	voterId ConsensusId
}

type ClockMsgFake struct {
	epoch   Epoch
	voterId ConsensusId
}

type ClockMsgNotaFake struct {
	epoch    Epoch
	voterIds []ConsensusId
}

type DataUnmarshallerFake struct {
}

// All data are immutable after being set.
type ElectionResultFake struct {
	consensusIds []ConsensusId
	// Included.
	begin Session
	// Included. Each session will have an election result in the real implementation.
	end Session
}

//--------------------------------------------------------------------

type StorageFake struct {
	blocks         map[BlockSn]Block
	canonicalChain map[uint64]Block
	hashToBlock    map[Hash]Block
	genesis        Block
	// The last block of the freshest notarized chain.
	freshestNotarizedHeadSn                  BlockSn
	freshestNotarizedChainUsingNotasInBlocks Block
	finalizedHead                            Block
	notas                                    map[BlockSn]Notarization
	proposerAddressesMap                     map[Session]map[ConsensusId]string
	commInfos                                map[Session]*committee.CommInfo
	// The (1+stopBlockSessionOffset) block in each session is the stop block which also stores
	// the election result.
	stopBlockSessionOffset uint64
	k                      *config.Int64HardforkConfig
	config                 *params.ThunderConfig
}

func (s *StorageFake) GetThunderConfig() *params.ThunderConfig {
	return s.config
}

func (s *StorageFake) GetBlock(sn BlockSn) Block {
	return s.blocks[sn]
}

func (s *StorageFake) GetHeader(sn BlockSn) Header {
	b := s.GetBlock(sn)
	if b == nil {
		return nil
	}
	return &HeaderFake{*b.(*BlockFake)}
}

func (s *StorageFake) GetNotarization(sn BlockSn) Notarization {
	if n, ok := s.notas[sn]; ok {
		return n
	}
	return nil
}

func (s *StorageFake) GetHeaderByNumber(number uint64) Header {
	b := s.GetBlockByNumber(number)
	if b == nil {
		return nil
	}
	return &HeaderFake{*b.(*BlockFake)}
}

func (s *StorageFake) GetRawBlockBody(hash Hash) []byte {
	block, ok := s.hashToBlock[hash]
	if !ok {
		return nil
	}

	body := block.(*BlockFake).GetBodyString()
	var out [][]byte
	out = append(out, utils.Uint32ToBytes(uint32(len(body))))
	out = append(out, []byte(body))
	return utils.ConcatCopyPreAllocate(out)
}

func (s *StorageFake) GetRawNotarization(sn BlockSn) []byte {
	if n, ok := s.notas[sn]; ok {
		return n.GetBody()
	}
	return nil
}

func (s *StorageFake) InsertBlock(block Block) error {
	s.blocks[block.GetBlockSn()] = block
	s.hashToBlock[block.GetHash()] = block

	return nil
}

func (s *StorageFake) AddNotarization(nota Notarization) (BlockSn, BlockSn, error) {
	var notaExt, finalExt BlockSn
	s.notas[nota.GetBlockSn()] = nota
	sn := nota.GetBlockSn()
	k := uint32(s.k.GetValueAtSession(int64(sn.Epoch.Session)))

	if sn.Compare(s.GetFreshestNotarizedHeadSn()) > 0 {
		s.SetFreshestNotarizedHeadSn(sn)
		notaExt = sn

		if sn.S > k {
			candidate := sn
			candidate.S -= k
			if candidate.Compare(s.GetFinalizedHeadSn()) > 0 {
				s.SetFinalizedHeadSn(candidate)
				finalExt = candidate
			}
		}
	}

	return notaExt, finalExt, nil
}

func (s *StorageFake) GetFreshestNotarizedHeadSn() BlockSn {
	return s.freshestNotarizedHeadSn
}

func (s *StorageFake) GetFreshestNotarizedHeadInfo() BlockInfo {
	b := s.GetBlock(s.freshestNotarizedHeadSn)
	return BlockInfo{
		Sn:     b.GetBlockSn(),
		Number: b.GetNumber(),
		Hash:   b.GetHash(),
	}
}

func (s *StorageFake) SetFreshestNotarizedHeadSn(sn BlockSn) error {
	s.freshestNotarizedHeadSn = sn

	// Update the canonical chain.
	// This is similar to geth's core.BlockChain.reorg(): Update the mapping number-to-block
	// from the new head to the common ancestor of the new and old heads.
	b := s.GetBlock(sn)
	for b != nil && b.GetNumber() > 0 {
		cb, ok := s.canonicalChain[b.GetNumber()]
		if ok && cb == b {
			break
		}

		s.canonicalChain[b.GetNumber()] = b
		b = s.GetBlock(b.GetParentBlockSn())
	}
	return nil
}

func (s *StorageFake) GetGenesisBlock() Block {
	return s.genesis
}

// Note that genesis block or the last block in thunder 0.5
// is not a finalized stop block.
func (s *StorageFake) GetLatestFinalizedStopBlock() Block {
	if s.finalizedHead == nil || s.finalizedHead.GetNumber() <= s.stopBlockSessionOffset {
		return nil
	}
	b := s.finalizedHead
	for {
		if s.IsStopBlock(b) {
			return b
		}
		ancestor := s.GetBlockByNumber(b.GetNumber() - s.stopBlockSessionOffset)
		if ancestor.GetBlockSn().Epoch.Session == b.GetBlockSn().Epoch.Session {
			b = s.GetBlock(b.GetParentBlockSn())
		} else {
			// Skip more blocks.
			sn := b.GetBlockSn()
			sn.S = 1
			ancestor = s.GetBlock(sn)
			b = s.GetBlock(ancestor.GetParentBlockSn())
		}
	}
	return nil
}

func (s *StorageFake) GetBlockByNumber(number uint64) Block {
	return s.canonicalChain[number]
}

func (s *StorageFake) GetLongestChain() Block {
	return s.getLongestChain(useNotarizationNone)
}

func (s *StorageFake) SetFinalizedHeadSn(sn BlockSn) error {
	s.finalizedHead = s.GetBlock(sn)
	return nil
}

func (s *StorageFake) GetFinalizedHeadSn() BlockSn {
	if s.finalizedHead == nil {
		return GetGenesisBlockSn()
	} else {
		return s.finalizedHead.GetBlockSn()
	}
}

func (s *StorageFake) GetReward(number uint64) (*reward.Results, error) {
	return nil, xerrors.New("not implemented")
}

// If useNota is useNotarizationNone, return the last block of the longest chain.
// If useNota is useNotarizationInAll, return the last block of the freshest notarized chain.
// If useNota is useNotarizationInBlocks, return the last block of the freshest notarized chain
// using notarizations in blocks only.
func (s *StorageFake) getLongestChain(useNota useNotarization) Block {
	depths := make(map[BlockSn]int)
	var ms BlockSn
	md := 0
	for sn := range s.blocks {
		t := s.getDepth(sn, depths, useNota)
		if useNota != useNotarizationNone {
			if t > 0 && ms.Compare(sn) < 0 {
				ms = sn
			}
		} else {
			if md < t {
				md = t
				ms = sn
			}
		}
	}
	return s.blocks[ms]
}

func (s *StorageFake) getDepth(
	sn BlockSn, depths map[BlockSn]int, useNota useNotarization) int {

	if useNota != useNotarizationNone {
		if !sn.IsPala() {
			// There is no notarization of the genesis block. No check.
		} else {
			nota := s.GetNotarization(sn)
			if nota == nil {
				return -1
			}
		}
	}

	if d, ok := depths[sn]; ok {
		return d
	} else {
		b := s.GetBlock(sn)
		if p := getParentBlock(s, b); p != nil {
			parentDepth := s.getDepth(p.GetBlockSn(), depths, useNota)
			if parentDepth < 0 {
				depths[sn] = -1
			} else {
				depths[sn] = parentDepth + 1
			}
		} else {
			depths[sn] = 1
		}
		return depths[sn]
	}
}

// ComputeFreshestNotarizedChain is the baseline for correctness.
// The time complexity is O(N).
func (s *StorageFake) ComputeFreshestNotarizedChain() Block {
	return s.getLongestChain(useNotarizationInAll)
}

// ComputeFinalizedChain is the baseline for correctness.
// The time complexity is O(N).
func (s *StorageFake) ComputeFinalizedChain(k uint32) Block {
	b := s.computeFinalizingChain()
	sn := b.GetBlockSn()
	// Ensure there are k normal blocks after the finalizing block.
	if !(sn.S > k && s.GetBlock(BlockSn{sn.Epoch, sn.S + k}) != nil) ||
		sn.IsGenesis() {
		return s.GetGenesisBlock()
	}
	// Chop off the last k normal blocks.
	return s.GetBlock(BlockSn{sn.Epoch, sn.S - k})
}

// TODO(thunder): match the definition of stopBlockSessionOffset to StorageImpl
// since 2d3efc769c5ba1587bd88c1a918a8a559e6586f8.
// Note that genesis block or the last block in thunder 0.5
// is not a finalized stop block.
func (s *StorageFake) IsStopBlock(block Block) bool {
	number := block.GetNumber()
	if number <= s.stopBlockSessionOffset {
		return false
	}

	b := s.GetBlockByNumber(number - s.stopBlockSessionOffset)
	return b.GetBlockSn().Epoch.Session == b.GetParentBlockSn().Epoch.Session+1
}

func (s *StorageFake) IsAfterStopBlock(block Block, includingStopBlock bool) bool {
	number := block.GetNumber()
	if number <= s.stopBlockSessionOffset {
		return false
	}

	b := s.GetBlockByNumber(number - s.stopBlockSessionOffset)
	if includingStopBlock {
		return b.GetBlockSn().Epoch.Session >= b.GetParentBlockSn().Epoch.Session+1
	}
	return b.GetBlockSn().Epoch.Session > b.GetParentBlockSn().Epoch.Session+1
}

// Return the last block of the freshest notarized chain only using notarizations in blocks.
func (s *StorageFake) computeFinalizingChain() Block {
	return s.getLongestChain(useNotarizationInAll)
}

func (s *StorageFake) AddCommInfo(session Session, cInfo *committee.CommInfo) {
	s.commInfos[session] = cInfo
}

func (s *StorageFake) GetCommInfo(session Session) *committee.CommInfo {
	cInfo, ok := s.commInfos[session]
	if !ok {
		return nil
	}
	return cInfo
}

func (s *StorageFake) GetClearingGasPrice(session Session) *big.Int {
	// StorageFake doesn't use TxPool, so the price doesn't matter.
	return big.NewInt(1)
}

func (s *StorageFake) GetProposerAddresses(session Session) map[ConsensusId]string {
	if addrs, ok := s.proposerAddressesMap[session]; ok {
		// Return the copy.
		m := make(map[ConsensusId]string)
		for k, v := range addrs {
			m[k] = v
		}
		return m
	}
	return nil
}

func (s *StorageFake) SetProposerAddresses(session Session, addresses map[ConsensusId]string) {
	m := make(map[ConsensusId]string)
	for k, v := range addresses {
		m[k] = v
	}
	s.proposerAddressesMap[session] = m
}

func NewStorageFake(k *config.Int64HardforkConfig, stopBlockSessionOffset uint64, thunderConfig *params.ThunderConfig) Storage {
	if thunderConfig == nil {
		thunderConfig := newThunderConfig()
		thunderConfig.GetSessionFromDifficulty = func(_, _ *big.Int, _ *params.ThunderConfig) uint32 { return 0 }
		thunderConfig.GetBlockSnFromDifficulty = func(_, _ *big.Int, _ *params.ThunderConfig) (uint32, uint32, uint32) { return 0, 0, 0 }
	}

	sn := GetGenesisBlockSn()
	genesis := NewBlockFake(sn, BlockSn{}, 0, nil, nil, "0")
	sf := &StorageFake{
		blocks:                                   make(map[BlockSn]Block),
		canonicalChain:                           make(map[uint64]Block),
		hashToBlock:                              make(map[Hash]Block),
		genesis:                                  genesis,
		freshestNotarizedHeadSn:                  sn,
		freshestNotarizedChainUsingNotasInBlocks: genesis,
		notas:                                    make(map[BlockSn]Notarization),
		proposerAddressesMap:                     make(map[Session]map[ConsensusId]string),
		commInfos:                                make(map[Session]*committee.CommInfo),
		stopBlockSessionOffset:                   stopBlockSessionOffset,
		k:                                        k,
		config:                                   thunderConfig,
	}

	_ = sf.InsertBlock(genesis)
	sf.canonicalChain[0] = genesis
	return sf
}

func NewBlockChainFake(k *config.Int64HardforkConfig) (BlockChain, error) {
	return NewBlockChainImpl(
		k, NewStorageFake(k, 10000, nil), NewBlockMakerFake(k, 0), &BlockFakeDecoder{}, nil, metrics.PalaMetrics{})
}

func NewBlockChainFakeWithDelay(k *config.Int64HardforkConfig, delay time.Duration, stopBlockSessionOffset uint64) (BlockChain, error) {
	return NewBlockChainImpl(
		k, NewStorageFake(k, stopBlockSessionOffset, nil), NewBlockMakerFake(k, delay), &BlockFakeDecoder{}, nil, metrics.PalaMetrics{})
}

func NewBlockChainWithFakeNota(k *config.Int64HardforkConfig, db ethdb.Database, chain *core.BlockChain, pool *core.TxPool,
	stopBlockOffset *config.Int64HardforkConfig, blockTime time.Duration) (BlockChain, error) {

	if chain.Config().Thunder == nil {
		hardConfig := InitHardforkValueForTest()

		chain.Config().Thunder = NewThunderConfig(hardConfig)
	}
	if stopBlockOffset != nil {
		chain.Config().Thunder.ElectionStopBlockSessionOffset = stopBlockOffset
	}

	cInfo := testutils.TestingCommInfo
	storage := NewStorage(StorageConfig{
		Db:                db,
		Bc:                chain,
		Marshaller:        &DataUnmarshallerOnlyBlock{config: chain.Config().Thunder},
		PalaFromGenesis:   true,
		Info:              &cInfo,
		UnnotarizedWindow: k,
	})

	return NewBlockChainImpl(
		k,
		storage,
		NewBlockMaker(storage, k, blockTime, pool, metrics.PalaMetrics{}),
		NewBlockImplDecoder(k, &DataUnmarshallerOnlyBlock{config: chain.Config().Thunder}, pool),
		nil,
		metrics.PalaMetrics{},
	)
}

//--------------------------------------------------------------------

func NewNotarizationFake(sn BlockSn, voterIds []ConsensusId) Notarization {
	var tmp []ConsensusId
	if len(voterIds) > 0 {
		tmp = append(tmp, voterIds...)
	}
	ConsensusIds(tmp).Sort()
	return &NotarizationFake{sn, tmp}
}

func (n *NotarizationFake) GetBlockSn() BlockSn {
	return n.sn
}

func (n *NotarizationFake) GetDebugString() string {
	return fmt.Sprintf("nota{%s, %d}", n.sn, n.GetNVote())
}

func (n *NotarizationFake) Verify() bool {
	return true
}

func (n *NotarizationFake) ImplementsNotarization() {
}

func (n *NotarizationFake) GetNVote() uint16 {
	return uint16(len(n.voterIds))
}

func (n *NotarizationFake) GetMissingVoterIdxs() []uint16 {
	// Always return empty array
	return []uint16{}
}

func (n *NotarizationFake) GetBlockHash() Hash {
	// Same as BlockFake.GetBlockHash().
	var h Hash
	b := n.sn.ToBytes()
	copy(h[HashLength-len(b):], b)
	return h
}

func (n *NotarizationFake) GetVoterIds() []ConsensusId {
	return n.voterIds
}

func (n *NotarizationFake) GetType() Type {
	return TypeNotarization
}

func (n *NotarizationFake) GetBody() []byte {
	var out [][]byte
	out = append(out, n.sn.ToBytes())
	out = append(out, utils.Uint16ToBytes(n.GetNVote()))
	for _, v := range n.voterIds {
		out = append(out, utils.StringToBytes(string(v)))
	}
	return utils.ConcatCopyPreAllocate(out)
}

//--------------------------------------------------------------------

func NewClockMsgNotaFake(epoch Epoch, voterIds []ConsensusId) ClockMsgNota {
	tmp := make([]ConsensusId, len(voterIds))
	copy(tmp, voterIds)
	ConsensusIds(tmp).Sort()
	return &ClockMsgNotaFake{epoch, tmp}
}

func (n *ClockMsgNotaFake) GetBlockSn() BlockSn {
	return BlockSn{n.epoch, 1}
}

func (n *ClockMsgNotaFake) GetDebugString() string {
	return fmt.Sprintf("nota{%d, %d}", n.epoch, n.GetNVote())
}

func (n *ClockMsgNotaFake) Verify() bool {
	return true
}

func (n *ClockMsgNotaFake) ImplementsClockMsgNota() {
}

func (n *ClockMsgNotaFake) GetEpoch() Epoch {
	return n.epoch
}

func (n *ClockMsgNotaFake) GetNVote() uint16 {
	return uint16(len(n.voterIds))
}

func (n *ClockMsgNotaFake) GetVoterIds() []ConsensusId {
	return n.voterIds
}

func (n *ClockMsgNotaFake) GetType() Type {
	return TypeClockMsgNota
}

func (n *ClockMsgNotaFake) GetBody() []byte {
	var out [][]byte
	out = append(out, n.epoch.ToBytes())
	out = append(out, utils.Uint16ToBytes(n.GetNVote()))
	for _, v := range n.voterIds {
		out = append(out, utils.StringToBytes(string(v)))
	}
	return utils.ConcatCopyPreAllocate(out)
}

//--------------------------------------------------------------------

func (b *BlockFake) ImplementsBlock() {
}

func (b *BlockFake) GetBlockSn() BlockSn {
	return b.sn
}

func (b *BlockFake) GetDebugString() string {
	return fmt.Sprintf("block{%s, %d}", b.sn, len(b.notas))
}

func (b *BlockFake) GetParentBlockSn() BlockSn {
	return b.parentSn
}

func (b *BlockFake) GetHash() Hash {
	if b.hash != nil {
		return *b.hash
	}

	// Same as NotarizationFake.GetBlockHash().
	var h Hash
	by := b.sn.ToBytes()
	copy(h[HashLength-len(by):], by)
	return h
}

func (b *BlockFake) GetParentHash() Hash {
	if b.parentHash != nil {
		return *b.parentHash
	}

	// Same as NotarizationFake.GetBlockHash().
	var h Hash
	by := b.parentSn.ToBytes()
	copy(h[HashLength-len(by):], by)
	return h
}

// Used for special tests. Usually you don't want to set this because this breaks
// the assumption of NotarizationFake.GetBlockHash().
func (b *BlockFake) SetHash(h Hash) {
	b.hash = &h
}

// Used for special tests. Usually you don't want to set this because this breaks
// the assumption of NotarizationFake.GetBlockHash().
func (b *BlockFake) SetParentHash(h Hash) {
	b.parentHash = &h
}

func (b *BlockFake) GetNumber() uint64 {
	return b.nBlock
}

func (b *BlockFake) GetBodyString() string {
	return b.body
}

func (b *BlockFake) GetType() Type {
	return TypeBlock
}

func (b *BlockFake) GetBody() []byte {
	var out [][]byte
	// sn
	out = append(out, b.sn.ToBytes())
	// parent
	out = append(out, b.GetParentBlockSn().ToBytes())
	// nBlock
	out = append(out, utils.Uint64ToBytes(b.GetNumber()))
	// notas
	out = append(out, utils.Uint16ToBytes(uint16(len(b.notas))))
	for _, n := range b.notas {
		out = append(out, n.GetBody())
	}
	// cNota
	if b.cNota != nil {
		out = append(out, []byte{1})
		out = append(out, b.cNota.GetBody())
	} else {
		out = append(out, []byte{0})
	}
	// body
	out = append(out, utils.Uint32ToBytes(uint32(len(b.body))))
	out = append(out, []byte(b.body))
	return utils.ConcatCopyPreAllocate(out)
}

func (h *HeaderFake) ImplementsHeader() {}

func (h *HeaderFake) GetType() Type { return TypeHeader }

func (h *HeaderFake) GetBody() []byte {
	var out [][]byte
	// sn
	out = append(out, h.sn.ToBytes())
	// parent
	out = append(out, h.GetParentBlockSn().ToBytes())
	// nBlock
	out = append(out, utils.Uint64ToBytes(h.GetNumber()))
	// notas
	out = append(out, utils.Uint16ToBytes(uint16(len(h.notas))))
	for _, n := range h.notas {
		out = append(out, n.GetBody())
	}
	// cNota
	if h.cNota != nil {
		out = append(out, []byte{1})
		out = append(out, h.cNota.GetBody())
	} else {
		out = append(out, []byte{0})
	}
	return utils.ConcatCopyPreAllocate(out)
}

type BlockFakeDecoder struct {
}

func NewBlockFakeDecoder() *BlockFakeDecoder {
	return &BlockFakeDecoder{}
}

func (b *BlockFakeDecoder) PrehandleBlock(block Block) {

}

func (b *BlockFakeDecoder) ToRawBlock(header []byte, body []byte) ([]byte, error) {
	return utils.ConcatCopyPreAllocate([][]byte{header, body}), nil
}

func (b *BlockFakeDecoder) GetNotarizations(block Block, _ *params.ThunderConfig) []Notarization {
	return block.(*BlockFake).notas
}

func (b *BlockFakeDecoder) GetClockMsgNota(block Block, _ *params.ThunderConfig) ClockMsgNota {
	return block.(*BlockFake).cNota
}

//--------------------------------------------------------------------

// PrepareFakeChain adds blocks to the existing fake chain.
// Assume using the stability-favoring approach.
// k affects how to add the notarization in the block. For (e,s)
// * s=1       : contain the notarizations of the previous k blocks.
// * s in [2,k]: contain no notarization.
// * s>k       : contain the notarization of (e,s-k).
func PrepareFakeChain(
	req *require.Assertions, bc BlockChain, base BlockSn, epoch Epoch, K *config.Int64HardforkConfig,
	voters []ConsensusId, newBlockBodies []string) {
	req.NotEqual(nil, K)

	p := bc.GetBlock(base)
	req.NotNil(p)
	k := uint32(K.GetValueAtSession(int64(epoch.Session)))
	for i, s := range newBlockBodies {
		notas := make([]Notarization, 0)
		var cNota ClockMsgNota
		np := p
		if i == 0 {
			for j := uint32(0); j < k && np != nil && !np.GetBlockSn().Epoch.IsNil(); j++ {
				notas = append(notas,
					NewNotarizationFake(np.GetBlockSn(), voters))
				np = GetParentBlock(bc, np)
			}
			reverse(notas)
			if epoch.E > 1 {
				cNota = NewClockMsgNotaFake(epoch, voters)
			}
		} else {
			for j := uint32(0); j < k-1 && np != nil; j++ {
				np = GetParentBlock(bc, np)
			}
			if np.GetBlockSn().Epoch == epoch {
				notas = append(notas, NewNotarizationFake(np.GetBlockSn(), voters))
			}
		}
		nb := NewBlockFake(
			BlockSn{epoch, uint32(i + 1)}, p.GetBlockSn(), p.GetNumber()+1, notas, cNota, s)
		err := bc.InsertBlock(nb, false)
		req.NoError(err)
		p = nb
	}
}

func NewBlockFake(
	sn BlockSn, parentSn BlockSn, nBlock uint64,
	notas []Notarization, cNota ClockMsgNota, body string,
) Block {
	return &BlockFake{
		sn:       sn,
		parentSn: parentSn,
		nBlock:   nBlock,
		notas:    notas,
		cNota:    cNota,
		body:     body,
	}
}

func DumpFakeChain(bc BlockChain, b Block, showNota bool) string {
	bs := make([]Block, 0)
	for {
		bs = append(bs, b)
		b = GetParentBlock(bc, b)
		if b == nil {
			break
		}
	}

	var sb strings.Builder
	_, _ = sb.WriteString(bs[len(bs)-1].GetBodyString())
	blockDecoder := &BlockFakeDecoder{}
	if showNota {
		ns := blockDecoder.GetNotarizations(bs[len(bs)-1], nil)
		_, _ = sb.WriteString("[" + notarizationsToString(bc, ns) + "]")
	}
	for i := len(bs) - 2; i >= 0; i-- {
		_, _ = sb.WriteString("->")
		_, _ = sb.WriteString(bs[i].GetBodyString())
		if showNota {
			ns := blockDecoder.GetNotarizations(bs[i], nil)
			_, _ = sb.WriteString("[" + notarizationsToString(bc, ns) + "]")
		}
	}
	return sb.String()
}

func notarizationsToString(bc BlockChain, notas []Notarization) string {
	var sb strings.Builder
	for i, n := range notas {
		if i > 0 {
			_, _ = sb.WriteString(",")
		}
		s := n.GetBlockSn()
		_, _ = sb.WriteString(bc.GetBlock(s).GetBodyString())
	}
	return sb.String()
}

//--------------------------------------------------------------------

func NewVerifierFake(
	id ConsensusId, proposers ElectionResultFake, voters ElectionResultFake) *VerifierFake {
	v := &VerifierFake{
		myId: id,
	}
	v.AddElectionResult(proposers, voters)
	return v
}

func (v *VerifierFake) AddElectionResult(proposers ElectionResultFake, voters ElectionResultFake) {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	v.proposerLists = append(v.proposerLists, &proposers)
	v.voterLists = append(v.voterLists, &voters)
}

func (v *VerifierFake) Propose(b Block) (Proposal, error) {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	proposerId := v.getProposerId(b.GetBlockSn().Epoch.Session)
	if proposerId == "" {
		return nil, xerrors.New("have no valid proposer id")
	}
	return &ProposalFake{proposerId, b}, nil
}

func (v *VerifierFake) IsReadyToPropose(ids []ConsensusId, session Session) bool {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	return len(ids) >= seatBasedVotingThreshold(len(v.findVoters(session)))
}

func (v *VerifierFake) VerifyProposal(p Proposal) error {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	proposerIds := v.findProposers(p.GetBlockSn().Epoch.Session)
	ppIdx := PrimaryProposerIndexer(p.GetBlockSn().Epoch, uint32(len(proposerIds)))
	for idx, pid := range proposerIds {
		if pid == p.GetProposerId() {
			if uint32(idx) != ppIdx {
				return xerrors.Errorf("proposer [%s] is not the right primary proposer %s at %s",
					p.GetProposerId(), proposerIds[ppIdx], p.GetBlockSn())
			}
			return nil
		}
	}
	return xerrors.Errorf("invalid proposer id=%s at %s", p.GetProposerId(), p.GetBlockSn())
}

func (v *VerifierFake) Vote(p Proposal) (Vote, error) {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	if voterId := v.getVoterId(p.GetBlockSn().Epoch.Session); voterId == "" {
		return nil, xerrors.Errorf("not a voter at %s", p.GetBlockSn())
	} else {
		return &VoteFake{p.GetBlock().GetBlockSn(), voterId}, nil
	}
}

func (v *VerifierFake) getProposerId(session Session) ConsensusId {
	v.mutex.CheckIsLocked("")

	for i := 0; i < len(v.proposerLists); i++ {
		if v.proposerLists[i].Contain(v.myId, session) {
			return v.myId
		}
	}
	return ""
}

func (v *VerifierFake) getVoterId(session Session) ConsensusId {
	v.mutex.CheckIsLocked("")

	for i := 0; i < len(v.voterLists); i++ {
		if v.voterLists[i].Contain(v.myId, session) {
			return v.myId
		}
	}
	return ""
}

func (v *VerifierFake) VerifyVote(vote Vote, r ChainReader) error {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	return v.verifyVote(vote, r)
}

func (v *VerifierFake) verifyVote(vote Vote, r ChainReader) error {
	v.mutex.CheckIsLocked("")

	for _, id := range v.findVoters(vote.GetBlockSn().Epoch.Session) {
		if id == vote.GetVoterId() {
			return nil
		}
	}
	return xerrors.Errorf("invalid voter id=%s at %s", vote.GetVoterId(), vote.GetBlockSn())
}

func (v *VerifierFake) Notarize(votes []Vote, r ChainReader) (Notarization, error) {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	if len(votes) == 0 {
		return nil, xerrors.New("not enough votes")
	}

	for i := 1; i < len(votes); i++ {
		if votes[i].GetBlockSn() != votes[0].GetBlockSn() {
			return nil, xerrors.New("votes have different block sequence number")
		}
	}

	nVoter := len(v.findVoters(votes[0].GetBlockSn().Epoch.Session))
	if len(votes) < seatBasedVotingThreshold(nVoter) {
		return nil, xerrors.New("not enough votes")
	}
	s := votes[0].GetBlockSn()
	var voterIds []ConsensusId
	for _, vote := range votes {
		if v.verifyVote(vote, r) == nil {
			voterIds = append(voterIds, vote.GetVoterId())
		}
	}
	if len(voterIds) < seatBasedVotingThreshold(nVoter) {
		return nil, xerrors.New("not enough votes")
	}
	return NewNotarizationFake(s, voterIds), nil
}

func (v *VerifierFake) findProposers(session Session) []ConsensusId {
	v.mutex.CheckIsLocked("")

	for i := 0; i < len(v.proposerLists); i++ {
		if v.proposerLists[i].Contain("", session) {
			return v.proposerLists[i].GetConsensusIds()
		}
	}
	return []ConsensusId{}
}

func (v *VerifierFake) findVoters(session Session) []ConsensusId {
	v.mutex.CheckIsLocked("")

	for i := 0; i < len(v.voterLists); i++ {
		if v.voterLists[i].Contain("", session) {
			return v.voterLists[i].GetConsensusIds()
		}
	}
	return []ConsensusId{}
}

func (v *VerifierFake) VerifyNotarization(n Notarization, r ChainReader) error {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	// Do the minimal verification. Skip the block hash check
	return v.verifyNotarization(n)
}

func (v *VerifierFake) verifyNotarization(n Notarization) error {
	v.mutex.CheckIsLocked("")

	// Do the minimal verification.
	voters := v.findVoters(n.GetBlockSn().Epoch.Session)
	if len(voters) == 0 {
		return ErrMissingElectionResult
	}
	if int(n.GetNVote()) < seatBasedVotingThreshold(len(voters)) {
		return ErrNotEnoughVotes
	}
	for _, vid := range n.(*NotarizationFake).GetVoterIds() {
		ok := false
		for _, id := range voters {
			if vid == id {
				ok = true
				break
			}
		}
		if !ok {
			return ErrBadSig
		}
	}

	return nil
}

func (v *VerifierFake) VerifyNotarizationWithBlock(n Notarization, b Block) error {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	// Do the minimal verification. Skip the check of block hash.
	return v.verifyNotarization(n)
}

func (v *VerifierFake) NewClockMsg(e Epoch) (ClockMsg, error) {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	pe, err := e.PreviousEpoch()
	if err != nil {
		return nil, err
	}
	if voterId := v.getVoterId(pe.Session); voterId == "" {
		return nil, xerrors.Errorf("not a voter at e=%s", pe)
	} else {
		return &ClockMsgFake{e, voterId}, nil
	}
}

func (v *VerifierFake) VerifyClockMsg(c ClockMsg) error {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	for _, id := range v.findVoters(c.GetEpoch().Session) {
		if id == c.GetVoterId() {
			return nil
		}
	}
	return xerrors.Errorf("invalid voter id=%s at epoch=%s", c.GetVoterId(), c.GetEpoch())
}

func (v *VerifierFake) NewClockMsgNota(clocks []ClockMsg) (ClockMsgNota, error) {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	if len(clocks) == 0 {
		return nil, ErrNotEnoughVotes
	}

	for i := 1; i < len(clocks); i++ {
		if clocks[i].GetEpoch() != clocks[0].GetEpoch() {
			return nil, xerrors.New("clocks have different epoch")
		}
	}

	e := clocks[0].GetEpoch()
	nVoter := float64(len(v.findVoters(e.Session)))
	if float64(len(clocks)) < math.Ceil(nVoter*2.0/3.0) {
		return nil, ErrNotEnoughVotes
	}
	var voterIds []ConsensusId
	for _, v := range clocks {
		voterIds = append(voterIds, v.GetVoterId())
	}
	return NewClockMsgNotaFake(e, voterIds), nil
}

func (v *VerifierFake) VerifyClockMsgNota(cn ClockMsgNota) error {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	// Skip the verification in the fake implementation.
	return nil
}

func (v *VerifierFake) Sign(bytes []byte) (ConsensusId, []byte, error) {
	s := []byte{fakeSignature}
	return v.myId, append(append(s, utils.StringToBytes(string(v.myId))...), bytes...), nil
}

func (v *VerifierFake) VerifySignature(
	signature []byte, expected []byte,
) (ConsensusId, bool, error) {
	if len(signature) < 2 {
		return "", false, xerrors.New("signature length is too short")
	}

	if signature[0] != fakeSignature {
		return "", false, xerrors.Errorf("wrong signature scheme: %d", signature[0])
	}

	tmp, bytes, err := utils.BytesToString(signature[1:])
	if err != nil {
		return "", false, err
	}
	targetId := ConsensusId(tmp)

	if string(bytes) != string(expected) {
		return "", false, xerrors.Errorf("wrong signature: signature mismatched: %v != %v", expected, bytes)
	}

	var isConsensusNode bool
	n := len(v.proposerLists)
	lists := make([]*ElectionResultFake, n+len(v.voterLists))
	copy(lists[:n], v.proposerLists)
	copy(lists[n:], v.voterLists)
	for i := 0; i < len(lists); i++ {
		if lists[i].Contain(targetId, lists[i].end) {
			isConsensusNode = true
			break
		}
	}

	return targetId, isConsensusNode, nil
}

func (v *VerifierFake) doesIdExist(targetId ConsensusId) bool {
	for i := 0; i < len(v.proposerLists); i++ {
		for _, id := range v.proposerLists[i].GetConsensusIds() {
			if id == targetId {
				return true
			}
		}
	}

	for i := 0; i < len(v.voterLists); i++ {
		for _, id := range v.voterLists[i].GetConsensusIds() {
			if id == targetId {
				return true
			}
		}
	}

	return false
}

//--------------------------------------------------------------------

func NewVerifierFakeBad(
	id ConsensusId, proposers ElectionResultFake, voters ElectionResultFake, badProposerId, badVoterId ConsensusId, alwaysBad bool,
) *VerifierFakeBad {
	v := &VerifierFakeBad{
		VerifierFake:  VerifierFake{myId: id},
		badProposerId: badProposerId,
		badVoterId:    badVoterId,
		alwaysBad:     alwaysBad,
	}
	v.VerifierFake.AddElectionResult(proposers, voters)
	return v
}

func (v *VerifierFakeBad) Vote(p Proposal) (Vote, error) {
	var vote Vote
	var err error
	if v.alwaysBad && v.badVoterId != "" {
		vote = &VoteFake{p.GetBlock().GetBlockSn(), v.badVoterId}
	} else {
		vote, err = v.VerifierFake.Vote(p)
		if err != nil && v.badVoterId != "" {
			vote = &VoteFake{p.GetBlock().GetBlockSn(), v.badVoterId}
			err = nil
		}

	}
	return vote, err
}

func (v *VerifierFakeBad) Propose(b Block) (Proposal, error) {
	var proposal Proposal
	var err error
	if v.alwaysBad && v.badProposerId != "" {
		proposal = &ProposalFake{v.badProposerId, b}
	} else {
		proposal, err = v.VerifierFake.Propose(b)
		if err != nil && v.badProposerId != "" {
			proposal = &ProposalFake{v.badProposerId, b}
			err = nil
		}
	}
	return proposal, err
}

func (v *VerifierFakeBad) NewClockMsg(e Epoch) (ClockMsg, error) {
	var cm ClockMsg
	var err error
	if v.alwaysBad && v.badVoterId != "" {
		cm = &ClockMsgFake{e, v.badVoterId}
	} else {
		cm, err = v.VerifierFake.NewClockMsg(e)
		if err != nil && v.badVoterId != "" {
			cm = &ClockMsgFake{e, v.badVoterId}
			err = nil
		}

	}
	return cm, err
}

//--------------------------------------------------------------------

func NewProposalFake(id ConsensusId, b Block) Proposal {
	return &ProposalFake{id, b}
}

func (p *ProposalFake) ImplementsProposal() {
}

func (p *ProposalFake) GetBlockSn() BlockSn {
	return p.block.GetBlockSn()
}

func (p *ProposalFake) GetDebugString() string {
	return fmt.Sprintf("proposal{%s}", p.GetBlockSn())
}

func (p *ProposalFake) GetBlock() Block {
	return p.block
}

func (p *ProposalFake) GetProposerId() ConsensusId {
	return p.proposerId
}

func (p *ProposalFake) GetType() Type {
	return TypeProposal
}

func (p *ProposalFake) GetBody() []byte {
	bytes := utils.StringToBytes(string(p.proposerId))
	return append(bytes, p.block.GetBody()...)
}

//--------------------------------------------------------------------

func NewVoteFake(sn BlockSn, id ConsensusId) Vote {
	return &VoteFake{sn, id}
}

func (v *VoteFake) ImplementsVote() {
}

func (v *VoteFake) GetBlockSn() BlockSn {
	return v.sn
}

func (v *VoteFake) GetDebugString() string {
	return fmt.Sprintf("vote{%s}", v.sn)
}

func (v *VoteFake) GetType() Type {
	return TypeVote
}

func (v *VoteFake) GetBody() []byte {
	return append(v.sn.ToBytes(), utils.StringToBytes(string(v.voterId))...)
}

func (v *VoteFake) GetVoterId() ConsensusId {
	return v.voterId
}

func reverse(notas []Notarization) {
	for i, j := 0, len(notas)-1; i < j; i, j = i+1, j-1 {
		n := notas[i]
		notas[i] = notas[j]
		notas[j] = n
	}
}

//--------------------------------------------------------------------

func (c *ClockMsgFake) ImplementsClockMsg() {
}

// A helper function for logging.
func (c *ClockMsgFake) GetBlockSn() BlockSn {
	return BlockSn{c.epoch, 1}
}

func (c *ClockMsgFake) GetEpoch() Epoch {
	return c.epoch
}

func (c *ClockMsgFake) GetDebugString() string {
	return fmt.Sprintf("clock{%d}", c.epoch)
}

func (c *ClockMsgFake) GetType() Type {
	return TypeClockMsg
}

func (c *ClockMsgFake) GetBody() []byte {
	return append(c.epoch.ToBytes(), utils.StringToBytes(string(c.voterId))...)
}

func (c *ClockMsgFake) GetVoterId() ConsensusId {
	return c.voterId
}

//--------------------------------------------------------------------

// UnmarshalProposal unmarshal the output of ProposalFake.GetBody().
func (du *DataUnmarshallerFake) UnmarshalProposal(bytes []byte) (Proposal, []byte, error) {
	idStr, bytes, err := utils.BytesToString(bytes)
	if err != nil {
		return nil, nil, err
	}
	id := ConsensusId(idStr)
	if block, bytes, err := du.UnmarshalBlock(bytes); err != nil {
		return nil, nil, err
	} else {
		return &ProposalFake{id, block}, bytes, nil
	}
}

// UnmarshalBlock unmarshal the output of BlockFake.GetBody().
func (du *DataUnmarshallerFake) UnmarshalBlock(bytes []byte) (Block, []byte, error) {
	sn, bytes, err := NewBlockSnFromBytes(bytes)
	if err != nil {
		return nil, nil, err
	}

	psn, bytes, err := NewBlockSnFromBytes(bytes)
	if err != nil {
		return nil, nil, err
	}

	nBlock, bytes, err := utils.BytesToUint64(bytes)
	if err != nil {
		return nil, nil, err
	}

	notas := make([]Notarization, 0)
	n, bytes, err := utils.BytesToUint16(bytes)
	if err != nil {
		return nil, nil, err
	}
	for i := 0; i < int(n); i++ {
		var n Notarization
		var err error
		if n, bytes, err = du.UnmarshalNotarization(bytes); err != nil {
			return nil, nil, err
		}
		notas = append(notas, n)
	}

	var cNota ClockMsgNota
	haveCNota := bytes[0] == 1
	bytes = bytes[1:]
	if haveCNota {
		cNota, bytes, err = du.UnmarshalClockMsgNota(bytes)
		if err != nil {
			return nil, nil, err
		}
	}

	bn, bytes, err := utils.BytesToUint32(bytes)
	if err != nil {
		return nil, nil, err
	}
	body := string(bytes[:bn])
	bytes = bytes[bn:]
	return NewBlockFake(sn, psn, nBlock, notas, cNota, body), bytes, nil
}

// UnmarshalVote unmarshal the output of VoteFake.GetBody().
func (du *DataUnmarshallerFake) UnmarshalVote(bytes []byte) (Vote, []byte, error) {
	sn, bytes, err := NewBlockSnFromBytes(bytes)
	if err != nil {
		return nil, nil, err
	}
	voterIdStr, bytes, err := utils.BytesToString(bytes)
	if err != nil {
		return nil, nil, err
	}
	voterId := ConsensusId(voterIdStr)
	return &VoteFake{sn, voterId}, bytes, nil
}

// UnmarshalNotarization unmarshal the output of NotarizationFake.GetBody().
func (du *DataUnmarshallerFake) UnmarshalNotarization(bytes []byte) (Notarization, []byte, error) {
	var voterIds []ConsensusId
	sn, bytes, err := NewBlockSnFromBytes(bytes)
	if err != nil {
		return nil, nil, err
	}
	nVote, bytes, err := utils.BytesToUint16(bytes)
	if err != nil {
		return nil, nil, err
	}
	for i := 0; i < int(nVote); i++ {
		var v string
		var err error
		v, bytes, err = utils.BytesToString(bytes)
		if err != nil {
			return nil, nil, err
		}
		voterIds = append(voterIds, ConsensusId(v))
	}
	return &NotarizationFake{sn, voterIds}, bytes, nil
}

// UnmarshalClockMsg unmarshal the output of ClockMsgFake.GetBody().
func (du *DataUnmarshallerFake) UnmarshalClockMsg(bytes []byte) (ClockMsg, []byte, error) {
	epoch, bytes, err := NewEpochFromBytes(bytes)
	if err != nil {
		return nil, nil, err
	}
	voterIdStr, bytes, err := utils.BytesToString(bytes)
	if err != nil {
		return nil, nil, err
	}
	voterId := ConsensusId(voterIdStr)
	return &ClockMsgFake{epoch, voterId}, bytes, nil
}

// UnmarshalClockMsgNota unmarshal the output of ClockMsgNotaFake.GetBody().
func (du *DataUnmarshallerFake) UnmarshalClockMsgNota(
	bytes []byte) (ClockMsgNota, []byte, error) {
	var voterIds []ConsensusId
	epoch, bytes, err := NewEpochFromBytes(bytes)
	if err != nil {
		return nil, nil, err
	}
	nVote, bytes, err := utils.BytesToUint16(bytes)
	if err != nil {
		return nil, nil, err
	}
	for i := 0; i < int(nVote); i++ {
		var v string
		var err error
		v, bytes, err = utils.BytesToString(bytes)
		if err != nil {
			return nil, nil, err
		}
		voterIds = append(voterIds, ConsensusId(v))
	}
	return &ClockMsgNotaFake{epoch, voterIds}, bytes, nil
}

type DataUnmarshallerOnlyBlock struct {
	DataUnmarshallerFake
	config *params.ThunderConfig
}

func (duo *DataUnmarshallerOnlyBlock) UnmarshalBlock(bytes []byte) (Block, []byte, error) {
	if duo.config == nil {
		debug.Bug("Didn't set ThunderConfig")
	}
	b := new(types.Block)

	if err := rlp.DecodeBytes(bytes, b); err != nil {
		return nil, bytes, err
	}

	bi := newBlock(b, duo.config)

	return bi, []byte{}, nil
}

// UnmarshalProposal unmarshal the output of ProposalFake.GetBody().
func (duo *DataUnmarshallerOnlyBlock) UnmarshalProposal(bytes []byte) (Proposal, []byte, error) {
	idStr, bytes, err := utils.BytesToString(bytes)
	if err != nil {
		return nil, nil, err
	}
	id := ConsensusId(idStr)
	if block, bytes, err := duo.UnmarshalBlock(bytes); err != nil {
		return nil, nil, err
	} else {
		return &ProposalFake{id, block}, bytes, nil
	}
}

// UnmarshalVote unmarshal the output of VoteFake.GetBody().
func (duo *DataUnmarshallerOnlyBlock) UnmarshalVote(bytes []byte) (Vote, []byte, error) {
	sn, bytes, err := NewBlockSnFromBytes(bytes)
	if err != nil {
		return nil, nil, err
	}
	voterIdStr, bytes, err := utils.BytesToString(bytes)
	if err != nil {
		return nil, nil, err
	}
	voterId := ConsensusId(voterIdStr)
	return &VoteFake{sn, voterId}, bytes, nil
}

// UnmarshalNotarization unmarshal the output of NotarizationFake.GetBody().
func (duo *DataUnmarshallerOnlyBlock) UnmarshalNotarization(bytes []byte) (Notarization, []byte, error) {
	var voterIds []ConsensusId
	sn, bytes, err := NewBlockSnFromBytes(bytes)
	if err != nil {
		return nil, nil, err
	}
	nVote, bytes, err := utils.BytesToUint16(bytes)
	if err != nil {
		return nil, nil, err
	}
	for i := 0; i < int(nVote); i++ {
		var v string
		var err error
		v, bytes, err = utils.BytesToString(bytes)
		if err != nil {
			return nil, nil, err
		}
		voterIds = append(voterIds, ConsensusId(v))
	}
	return &NotarizationFake{sn, voterIds}, bytes, nil
}

// UnmarshalClockMsg unmarshal the output of ClockMsgFake.GetBody().
func (duo *DataUnmarshallerOnlyBlock) UnmarshalClockMsg(bytes []byte) (ClockMsg, []byte, error) {
	epoch, bytes, err := NewEpochFromBytes(bytes)
	if err != nil {
		return nil, nil, err
	}
	voterIdStr, bytes, err := utils.BytesToString(bytes)
	if err != nil {
		return nil, nil, err
	}
	voterId := ConsensusId(voterIdStr)
	return &ClockMsgFake{epoch, voterId}, bytes, nil
}

// UnmarshalClockMsgNota unmarshal the output of ClockMsgNotaFake.GetBody().
func (duo *DataUnmarshallerOnlyBlock) UnmarshalClockMsgNota(
	bytes []byte) (ClockMsgNota, []byte, error) {
	var voterIds []ConsensusId
	epoch, bytes, err := NewEpochFromBytes(bytes)
	if err != nil {
		return nil, nil, err
	}
	nVote, bytes, err := utils.BytesToUint16(bytes)
	if err != nil {
		return nil, nil, err
	}
	for i := 0; i < int(nVote); i++ {
		var v string
		var err error
		v, bytes, err = utils.BytesToString(bytes)
		if err != nil {
			return nil, nil, err
		}
		voterIds = append(voterIds, ConsensusId(v))
	}
	return &ClockMsgNotaFake{epoch, voterIds}, bytes, nil
}

//--------------------------------------------------------------------

func NewElectionResultFake(consensusId []ConsensusId, begin Session, end Session) ElectionResultFake {
	return ElectionResultFake{consensusId, begin, end}
}

func (t ElectionResultFake) Contain(targetId ConsensusId, session Session) bool {
	if session < t.begin || session > t.end {
		return false
	}

	if targetId == "" {
		return true
	}

	for _, id := range t.consensusIds {
		if id == targetId {
			return true
		}
	}
	return false
}

func (t ElectionResultFake) IsNil() bool {
	return len(t.consensusIds) == 0 || t.begin > t.end
}

func (t ElectionResultFake) GetConsensusIds() []ConsensusId {
	return t.consensusIds
}

func (t ElectionResultFake) GetRange() (begin, end Session) {
	return t.begin, t.end
}

func idToStringSlice(ids []ConsensusId) []string {
	out := make([]string, len(ids))
	for i, x := range ids {
		out[i] = string(x)
	}
	return out
}

func (t ElectionResultFake) String() string {
	var b strings.Builder
	_, _ = b.WriteString("[(")
	_, _ = b.WriteString(strings.Join(ConsensusIds(t.consensusIds).StringSlice(), ","))
	_, _ = b.WriteString("):")
	_, _ = b.WriteString(fmt.Sprintf("%d", t.begin))
	_, _ = b.WriteString("-")
	_, _ = b.WriteString(fmt.Sprintf("%d", t.end))
	_, _ = b.WriteString("]")
	return b.String()
}

//--------------------------------------------------------------------

func NewPalaStorageWithMemoryDB(k *config.Int64HardforkConfig) Storage {
	memdb, chain, err := core.NewThunderCanonical(ethash.NewFaker(), 0, true)

	if err != nil {
		return nil
	}

	// In this test case, we don't care about the stop block.
	stopBlockOffset := config.NewInt64HardforkConfig("blockchain.unused.value", "")
	stopBlockOffset.SetTestValueAt(10000, 0)
	chain.Config().Thunder.ElectionStopBlockSessionOffset = stopBlockOffset
	return NewStorage(StorageConfig{
		Db:                memdb,
		Bc:                chain,
		Marshaller:        &DataUnmarshallerFake{},
		PalaFromGenesis:   true,
		Info:              &testutils.TestingCommInfo,
		UnnotarizedWindow: k,
	})
}

type TestingKeys struct {
	ProposerPrivPropKeys []*bls.SigningKey
	ProposerPubPropKeys  []*bls.PublicKey
	VoterPrivVoteKeys    []*bls.SigningKey
	ElectionResult       *ElectionResultImpl
	KeyIds               map[string][]string
	KeyMgr               *keymanager.KeyManager
}

// testKeyCache: proposer and voter numbers -> testingKeys
// cache the keys to speedup unit testing
var testKeyCache = make(map[string]*TestingKeys)
var testKeyCacheLock sync.Mutex

var cacheKeyFunc = func(voters, proposers int) string {
	return fmt.Sprintf("%dp%dv", proposers, voters)
}

func GetCachedkey(voters, proposers int) *TestingKeys {
	utils.EnsureRunningInTestCode()
	testKeyCacheLock.Lock()
	defer testKeyCacheLock.Unlock()
	testKeys, ok := testKeyCache[cacheKeyFunc(voters, proposers)]
	if ok {
		return testKeys
	}
	return nil
}

// NOTE: Assume proposers are also voters.
func SetupKeys(voters, proposers int) (*TestingKeys, error) {
	utils.EnsureRunningInTestCode()
	testKeyCacheLock.Lock()
	defer testKeyCacheLock.Unlock()

	cacheKey := cacheKeyFunc(voters, proposers)
	testKeys, ok := testKeyCache[cacheKey]
	if ok {
		return testKeys, nil
	}

	votingKeyIds := keymanager.GetKeyIDsForFS(uint(voters), "vote", 0)
	proposingKeyIds := votingKeyIds[:proposers]
	accountKeyIds := keymanager.GetKeyIDsForFS(uint(voters), "account", 0)
	keyIds := map[string][]string{
		"proposingKeyIds": proposingKeyIds,
		"votingKeyIds":    votingKeyIds,
		"accountKeyIds":   accountKeyIds,
	}
	memKeystore := keymanager.SetupTestingKeystore(
		keymanager.MemKeyStoreConfig{
			AccelIDs:      proposingKeyIds,
			VoteKeyIDs:    votingKeyIds,
			AccountKeyIDs: accountKeyIds,
		})
	keymgr := keymanager.NewKeyManagerFromMemKeystore(memKeystore)
	commInfo, err := committee.NewCommInfoFromKeyManager(keymgr, proposingKeyIds, votingKeyIds)
	if err != nil {
		return nil, xerrors.New("connat load committee info")
	}
	electionResult := NewElectionResultImpl(commInfo, 1)

	accelPrivPropKeys := make([]*bls.SigningKey, proposers)
	for i := 0; i < proposers; i++ {
		accelPrivPropKeys[i], err = keymgr.GetCommPrivateVoteKey(proposingKeyIds[i], "")
		if err != nil {
			return nil, xerrors.Errorf("cannot load private proposing key for Accel No. %d", i)
		}
	}

	accelPubPropKeys, err := keymgr.GetCommPublicVoteKeys(proposingKeyIds, nil)
	if err != nil {
		return nil, xerrors.New("cannot load Accel Public Proposing key")
	}

	commPrivVoteKeys := make([]*bls.SigningKey, voters)
	for i := 0; i < voters; i++ {
		commPrivVoteKeys[i], err = keymgr.GetCommPrivateVoteKey(votingKeyIds[i], "")
		if err != nil {
			return nil, xerrors.Errorf("cannot load private voting key for Comm No. %d", i)
		}
	}
	testKeys = &TestingKeys{
		ProposerPrivPropKeys: accelPrivPropKeys,
		ProposerPubPropKeys:  accelPubPropKeys,
		VoterPrivVoteKeys:    commPrivVoteKeys,
		ElectionResult:       electionResult,
		KeyIds:               keyIds,
		KeyMgr:               keymgr,
	}
	testKeyCache[cacheKey] = testKeys
	return testKeys, nil
}

func CreateVerifierForTest(
	loggingId string, electionResult *ElectionResultImpl, signer bls.BlsSigner,
) Verifier {
	utils.EnsureRunningInTestCode()
	cfg := &VerifierImplCfg{
		ElectionResult:     electionResult,
		LoggingId:          loggingId,
		VoteCountingScheme: config.NewStringHardforkConfig("test-voting-scheme", ""),
	}
	cfg.Signer = signer
	cfg.VoteCountingScheme.SetTestValueAtSession("Seat", 1)
	return NewVerifierImpl(cfg)
}

func MsgToProposal(m Message, fake bool) Proposal {
	utils.EnsureRunningInTestCode()
	var ok bool
	var b Proposal

	if fake {
		b, ok = m.(*ProposalFake)
	} else {
		b, ok = m.(*proposalImpl)
	}

	if !ok {
		return nil
	}
	return b
}

func MsgToVote(m Message, fake bool) Vote {
	utils.EnsureRunningInTestCode()
	var ok bool
	var b Vote

	if fake {
		b, ok = m.(*VoteFake)
	} else {
		b, ok = m.(*voteImpl)
	}

	if !ok {
		return nil
	}
	return b
}

func MsgToNotarization(m Message, fake bool) Notarization {
	utils.EnsureRunningInTestCode()
	var ok bool
	var b Notarization

	if fake {
		b, ok = m.(*NotarizationFake)
	} else {
		b, ok = m.(*notarizationImpl)
	}

	if !ok {
		return nil
	}
	return b
}

func MsgToClockMsg(m Message, fake bool) ClockMsg {
	utils.EnsureRunningInTestCode()
	var ok bool
	var b ClockMsg

	if fake {
		b, ok = m.(*ClockMsgFake)
	} else {
		b, ok = m.(*clockMsgImpl)
	}

	if !ok {
		return nil
	}
	return b
}

func MsgToClockMsgNota(m Message, fake bool) ClockMsgNota {
	utils.EnsureRunningInTestCode()
	var ok bool
	var b ClockMsgNota

	if fake {
		b, ok = m.(*ClockMsgNotaFake)
	} else {
		b, ok = m.(*clockMsgNotaImpl)
	}

	if !ok {
		return nil
	}
	return b
}

func NewInvalidVote(sn BlockSn, hash Hash, id ConsensusId, signer bls.BlsSigner) Vote {
	return &voteImpl{
		blockHash: hash,
		sn:        sn,
		signature: signer.Sign(hash.Bytes()),
		voterId:   id,
	}
}

// WithSimpleTransactionsForTest is the gen callback for core.GenerateChain or blockchain.GeneratePalaChain
func WithSimpleTransactionAndRandomBidForTest(numTx int, chain *core.BlockChain) func(int, *core.BlockGen) {
	return func(number int, block *core.BlockGen) {
		nonce := block.TxNonce(testutils.TestingAddr)
		for i := 0; i < numTx; i++ {
			toAddr := common.HexToAddress("0x0000000000000000000000000000000000000000")
			tx := testutils.MakeTxactSimple(testutils.TestingKey, &toAddr, nonce)
			block.AddTxWithChain(chain, tx)
			nonce++
		}

		stake, _ := new(big.Int).SetString("100000000000000000000000", 10)
		gasBidPrice := new(big.Int).SetUint64(10000100)
		gasLimit := uint64(1000000)
		key, _ := bls.NewSigningKey()
		stakeInfo := &election.StakeInfo{
			StakeMsg: election.StakeMsg{
				Stake:      stake,
				PubVoteKey: key.GetPublicKey(),
				Coinbase:   testutils.TestingAddr,
				GasPrice:   gasBidPrice,
			},
		}
		bidData, _ := thundervm.StakeMsgToBidCall(stakeInfo)
		tx := types.NewTransaction(nonce, chainconfig.CommElectionTPCAddress, stake, gasLimit, gasBidPrice, bidData)
		chainId := params.ThunderChainConfig().ChainID
		signer := types.NewEIP155Signer(chainId)
		signedTx, _ := types.SignTx(tx, signer, testutils.TestingKey)
		block.AddTxWithChain(chain, signedTx)

	}
}

// BlockGenWithConsensusTransaction is the gen callback for core.GenerateChain or blockchain.GeneratePalaChain
func BlockGenWithConsensusTransaction(
	chain *core.BlockChain,
	blockSns []BlockSn,
	K *config.Int64HardforkConfig,
	gen func(int, *core.BlockGen),
	withNonce bool,
	voters []ConsensusId,
) func(int, *core.BlockGen) {
	utils.EnsureRunningInTestCode()

	return func(number int, block *core.BlockGen) {
		var parentSn BlockSn
		block.SetCoinbase(chainconfig.TestnetTxnFeeAddr)
		parentBlock := newBlock(block.PrevBlock(-1), chain.Config().Thunder)
		if number == 0 {

			parentSn = parentBlock.GetBlockSn()
		} else {
			parentSn = blockSns[number-1]
		}
		if withNonce {
			if parentSn.Epoch.Session == blockSns[number].Epoch.Session {
				nonce := types.EncodeNonce(parentBlock.(*blockImpl).B.Nonce() + 1)
				block.SetNonce(nonce)
			} else {
				block.SetNonce(types.EncodeNonce(1))
			}
		}
		block.SetDifficulty(EncodeBlockSnToNumber(parentSn, blockSns[number]))

		if gen != nil {
			gen(number, block)
		}

		k := uint32(K.GetValueAtSession(int64(blockSns[number].Epoch.Session)))

		// Generating consensus transaction, this should be the last transaction in the block.
		if parentSn.IsPala() && blockSns[number].S == 1 {
			ci := new(consensusInfo)
			ci.clockNota = NewClockMsgNotaFake(blockSns[number].Epoch, []ConsensusId{})
			ci.notas = make([]Notarization, 0)

			for i, s := uint32(0), parentSn.S; i < k && s > 0; i, s = i+1, s-1 {
				ci.notas = append(ci.notas, NewNotarizationFake(
					BlockSn{Epoch: parentSn.Epoch, S: s},
					voters))
			}

			// reverse it
			for i, j := 0, len(ci.notas)-1; i < j; i, j = i+1, j-1 {
				ci.notas[i], ci.notas[j] = ci.notas[j], ci.notas[i]
			}

			tx := txutils.MakeSignedTxWithData(testutils.TestingKey, &testutils.TestingAddr, block.TxNonce(testutils.TestingAddr), big.NewInt(0), chain.Config().ChainID, ci.ToBytes(), nil)
			block.AddTxWithChain(chain, tx)
		}

		if blockSns[number].S > k {
			ci := new(consensusInfo)
			ci.notas = make([]Notarization, 0)
			ci.notas = append(ci.notas, NewNotarizationFake(
				BlockSn{Epoch: blockSns[number].Epoch, S: blockSns[number].S - k},
				voters))

			tx := txutils.MakeSignedTxWithData(testutils.TestingKey, &testutils.TestingAddr, block.TxNonce(testutils.TestingAddr), big.NewInt(0), chain.Config().ChainID, ci.ToBytes(), nil)
			block.AddTxWithChain(chain, tx)
		}
	}
}

// GeneratePalaChain generates a pala chain for testing.
func GeneratePalaChain(chainreader consensus.ChainReader, parent *types.Block, engine consensus.Engine, db ethdb.Database, n int, gen func(int, *core.BlockGen)) []Block {
	blocks, _ := core.GenerateThunderChain(chainreader, parent, engine, db, n, gen)

	ret := make([]Block, 0, len(blocks))

	for _, blk := range blocks {
		ret = append(ret, newBlock(blk, chainreader.Config().Thunder))
	}

	return ret
}

func newThunderConfig() *params.ThunderConfig {
	return NewThunderConfig(NewHardforkConfigForTest())
}

func NewHardforkConfigForTest() *HardforkCfg {
	utils.EnsureRunningInTestCode()
	return InitHardforkValueForTest()
}

func NewThunderSinceGenesisWithDiskDb(dirname string) (ethdb.Database, *core.BlockChain, error) {
	db, err := rawdb.NewLevelDBDatabase(dirname, 512, 256, "", false)
	if err != nil {
		return nil, nil, err
	}
	return newThunderSinceGenesisWithDb(db)
}

func NewThunderSinceGenesisWithMemDb() (ethdb.Database, *core.BlockChain, error) {
	db := rawdb.NewMemoryDatabase()
	return newThunderSinceGenesisWithDb(db)
}

func newThunderSinceGenesisWithDb(db ethdb.Database) (ethdb.Database, *core.BlockChain, error) {
	gen := core.DefaultThunderGenesisBlock()
	_, err := gen.Commit(db)
	if err != nil {
		return nil, nil, err
	}

	config := params.ThunderChainConfig()
	thunderCfg := newThunderConfig()
	config.Thunder = thunderCfg
	engine := thunder.New(thunderCfg)
	cacheConfig := &core.CacheConfig{
		TrieDirtyDisabled: true,
	}

	blockchain, err := core.NewBlockChain(db, cacheConfig, config, engine, vm.Config{}, nil, nil)
	if err != nil {
		return nil, nil, err
	}

	return db, blockchain, nil
}

var seatBasedVotingThreshold = func(numCommMembers int) int {
	return utils.IntDivCeil(numCommMembers*2, 3)
}

func randSuffix(str string) string {
	return fmt.Sprintf("%v.%v", str, rand.Int())
}
func InitHardforkValueForTest() *HardforkCfg {
	utils.EnsureRunningInTestCode()

	var electionOffsetForTest = config.NewInt64HardforkConfig(
		randSuffix("blockchain.election.offset"), "")
	var proposerListNameForTest = config.NewStringHardforkConfig(
		randSuffix("blockchain.proposer.list"), "")
	var maxCodeSizeForTest = config.NewInt64HardforkConfig(
		randSuffix("blockchain.max.codesize"), "")
	var gasTableForTest = config.NewStringHardforkConfig(
		randSuffix("blockchain.gas.table"), "")
	var rewardSchemeForTest = config.NewStringHardforkConfig(
		randSuffix("blockchain.reward.scheme"), "")
	var evmHardforkVersion = config.NewStringHardforkConfig(
		randSuffix("blockchain.evm.version"), "")
	var vaultGasUnlimitedForTest = config.NewBoolHardforkConfig(
		randSuffix("blockchain.vault.gaslimit"), "")
	var isConsensusInfoInHeaderForTest = config.NewBoolHardforkConfig(
		randSuffix("blockchain.is.consensus.inheader"), "")
	var rngVersionForTest = config.NewStringHardforkConfig(
		randSuffix("blockchain.rng.version"), "")
	var baseFeeForTest = config.NewBigIntHardforkConfig(
		randSuffix("blockchain.basefee"), "")
	var inflationForTest = config.NewBigIntHardforkConfig(
		randSuffix("blockchain.inflation"), "")
	var committeeRewardRatioForTest = config.NewInt64HardforkConfig(
		randSuffix("blockchain.committee.reward.ratio"), "")
	var tpcRevertDelegateCallForTest = config.NewBoolHardforkConfig(
		randSuffix("blockchain.revert.delegatecall"), "")

	proposerListNameForTest.SetTestValueAtSession("", 0)
	electionOffsetForTest.SetTestValueAt(100000000, 0)
	electionOffsetForTest.SetTestValueAtSession(100000000, 0)
	rewardSchemeForTest.SetTestValueAtSession("thunderella", 0)
	// Use this value for tests that we don't care about the stop block.
	maxCodeSizeForTest.SetTestValueAt(100000, 0)
	gasTableForTest.SetTestValueAtSession("pala-r2.1", 0)
	evmHardforkVersion.SetTestValueAtSession("", 0)
	isConsensusInfoInHeaderForTest.SetTestValueAtSession(false, 0)
	rngVersionForTest.SetTestValueAtSession("v1", 0)
	thundervm.IsBlockSnGetterActive.SetTestValueAtSession(true, 0)
	baseFeeForTest.SetTestValueAtSession(big.NewInt(0), 0)
	inflationForTest.SetTestValueAtSession(big.NewInt(0), 0)
	committeeRewardRatioForTest.SetTestValueAtSession(50, 0)
	thundervm.IsRNGActive.SetTestValueAt(true, 0)
	tpcRevertDelegateCallForTest.SetTestValueAtSession(true, 0)

	hardConfig := &HardforkCfg{
		PalaBlock:               common.Big1,
		VerifyBidSession:        0,
		ElectionStopBlockOffset: electionOffsetForTest,
		ProposerListName:        proposerListNameForTest,
		MaxCodeSize:             maxCodeSizeForTest,
		GasTable:                gasTableForTest,
		RewardScheme:            rewardSchemeForTest,
		VaultGasUnlimited:       vaultGasUnlimitedForTest,
		IsConsensusInfoInHeader: isConsensusInfoInHeaderForTest,
		RNGVersion:              rngVersionForTest,
		EVMHardforkVersion:      evmHardforkVersion,
		BaseFee:                 baseFeeForTest,
		TokenInflation:          inflationForTest,
		CommitteeRewardRatio:    committeeRewardRatioForTest,
		TPCRevertDelegateCall:   tpcRevertDelegateCallForTest,
	}

	return hardConfig
}
