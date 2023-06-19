package blockchain

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/params"
	"golang.org/x/xerrors"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

type blockSnCache struct {
	parentSn BlockSn
	sn       BlockSn
}

type blockImpl struct {
	cache *blockSnCache
	B     *types.Block
}

func (b *blockImpl) GetType() Type { return TypeBlock }

// GetBlockSn() and GetParentBlockSn() have a hardfork behavior,
// we consider all blocks that made before Pala are in BlockSn{0, 1, Block.Number},
// and the Genesis BlockSn is {0, 0, 1}
// (we reserve {0, 0, 0} for empty BlockSn)
// That makes us able to hardfork from a chain which doesn't have BlockSn.
func (cache *blockSnCache) updateFromBlockNumber(number uint64) {
	if number == 0 {
		cache.parentSn = BlockSn{}
		cache.sn = GetGenesisBlockSn()
	} else if number == 1 {
		cache.parentSn = GetGenesisBlockSn()
		cache.sn = NewBlockSn(0, 1, uint32(number))
	} else {
		cache.parentSn = NewBlockSn(0, 1, uint32(number-1))
		cache.sn = NewBlockSn(0, 1, uint32(number))
	}
}

func (b *blockImpl) GetBlockSn() BlockSn {
	if b.cache == nil {
		debug.Bug("Cannot decode BlockSn from Difficulty")

	}
	return b.cache.sn
}

func (b *blockImpl) GetParentBlockSn() BlockSn {
	if b.cache == nil {
		debug.Bug("Cannot decode BlockSn from Difficulty")

	}

	return b.cache.parentSn
}

func (b *blockImpl) GetDebugString() string { return b.String() }
func (b *blockImpl) GetBody() []byte {
	data, err := rlp.EncodeToBytes(b.B)
	if err != nil {
		return nil
	}

	return data
}

func (b *blockImpl) GetHash() Hash {
	return Hash(b.B.Hash())
}

func (b *blockImpl) GetParentHash() Hash {
	return Hash(b.B.ParentHash())
}

func (b *blockImpl) GetBodyString() string {
	return fmt.Sprintf("(\nBlockSn: %s,\nParentBlockSn: %s,\nHeight: %d,\nNumber Of Transactions: %d\n)", b.GetBlockSn(), b.GetParentBlockSn(), b.B.NumberU64(), len(b.B.Transactions()))
}

func (b *blockImpl) GetNumber() uint64 {
	return b.B.NumberU64()
}

func (b *blockImpl) String() string {
	return fmt.Sprintf("(%s,%x)", b.GetBlockSn(), b.B.Hash())
}

func (b *blockImpl) ImplementsBlock() {

}

func newBlock(b *types.Block, config *params.ThunderConfig) Block {
	cache := &blockSnCache{}
	var err error

	if config.IsPala(b.Number()) {
		if cache.parentSn, cache.sn, err = decodeBlockSnFromNumber(b.Difficulty()); err != nil {
			debug.Bug("Cannot decode BlockSn from Difficulty")
		}
	} else {
		cache.updateFromBlockNumber(b.NumberU64())
	}

	bi := &blockImpl{
		cache: cache,
		B:     b,
	}

	return bi
}

func (b *blockImpl) equals(other *blockImpl) bool {
	return b.GetParentBlockSn().Compare(other.GetParentBlockSn()) == 0 &&
		b.GetBlockSn().Compare(other.GetBlockSn()) == 0 &&
		b.B.Hash() == other.B.Hash()
}

// TODO(sonic): put this in blockImpl
type headerImpl struct {
	cache *blockSnCache
	H     *types.Header
}

func (h *headerImpl) ImplementsHeader() {}

func (h *headerImpl) GetType() Type { return TypeHeader }

func (h *headerImpl) GetBlockSn() BlockSn {
	if h.cache == nil {
		debug.Bug("Cannot decode BlockSn from Difficulty")

	}
	return h.cache.sn
}

func (h *headerImpl) GetParentBlockSn() BlockSn {
	if h.cache == nil {
		debug.Bug("Cannot decode BlockSn from Difficulty")

	}
	return h.cache.parentSn
}

func (h *headerImpl) String() string {
	return fmt.Sprintf("(%s,%x)", h.GetBlockSn(), h.H.Hash())
}

func (h *headerImpl) GetDebugString() string {
	return h.String()
}

func (h *headerImpl) GetBody() []byte {
	data, err := rlp.EncodeToBytes(h.H)
	if err != nil {
		return nil
	}

	return data
}

func (h *headerImpl) GetHash() Hash {
	return Hash(h.H.Hash())
}

func (h *headerImpl) GetNumber() uint64 {
	return h.H.Number.Uint64()
}

func newHeader(h *types.Header, config *params.ThunderConfig) Header {
	cache := &blockSnCache{}
	var err error

	if config.IsPala(h.Number) {
		if cache.parentSn, cache.sn, err = decodeBlockSnFromNumber(h.Difficulty); err != nil {
			debug.Bug("Cannot decode BlockSn from Difficulty")
		}
	} else {
		cache.updateFromBlockNumber(h.Number.Uint64())
	}

	hi := &headerImpl{
		cache: cache,
		H:     h,
	}

	return hi
}

// BlockImplDecoder can decode notarizations and clock message notarization via the DataUnmarshaller
type BlockImplDecoder struct {
	k            *config.Int64HardforkConfig
	unmarshaller DataUnmarshaller
	txpool       *core.TxPool
}

func NewBlockImplDecoder(
	k *config.Int64HardforkConfig,
	unmarshaller DataUnmarshaller, pool *core.TxPool,
) *BlockImplDecoder {
	return &BlockImplDecoder{
		k:            k,
		unmarshaller: unmarshaller,
		txpool:       pool,
	}
}

func (d *BlockImplDecoder) getConsensusInfo(block Block, config *params.ThunderConfig) (*consensusInfo, error) {
	sn := block.GetBlockSn()
	ethBlock := block.(*blockImpl).B

	session := config.GetSessionFromDifficulty(ethBlock.Header().Difficulty, ethBlock.Header().Number, config)

	if config.IsConsensusInfoInHeader.GetValueAtSession(int64(session)) {
		return bytesToConsensusInfo(ethBlock.Extra(), d.unmarshaller)
	}

	k := uint32(d.k.GetValueAtSession(int64(session)))

	txs := block.(*blockImpl).B.Transactions()
	var tx *types.Transaction

	if block.GetParentBlockSn().IsPala() {
		if sn.S == 1 || sn.S > k {
			tx = txs[len(txs)-1]
		}
	}

	if tx == nil {
		return nil, xerrors.Errorf("Cannot find consensus info in %s", block.GetBlockSn())
	}

	return bytesToConsensusInfo(tx.Data(), d.unmarshaller)
}

func (d *BlockImplDecoder) PrehandleBlock(block Block) {
	if d.txpool == nil {
		return
	}

	b := block.(*blockImpl).B

	txs := b.Transactions()
	for i, tx := range txs {
		if t := d.txpool.Get(tx.Hash()); t != nil {
			txs[i] = t
		}
	}
}

func (d *BlockImplDecoder) ToRawBlock(header []byte, body []byte) ([]byte, error) {
	b := struct {
		Transactions rlp.RawValue
		Uncles       rlp.RawValue
	}{}
	if err := rlp.DecodeBytes(body, &b); err != nil {
		return nil, err
	}

	type extBlock struct {
		Header       rlp.RawValue
		Transactions rlp.RawValue
		Uncles       rlp.RawValue
	}

	data, err := rlp.EncodeToBytes(&extBlock{
		Header:       header,
		Transactions: b.Transactions,
		Uncles:       b.Uncles,
	})
	return data, err
}

func (d *BlockImplDecoder) GetNotarizations(block Block, config *params.ThunderConfig) []Notarization {
	if ci, err := d.getConsensusInfo(block, config); err == nil {
		return ci.notas
	}

	return nil
}

func (d *BlockImplDecoder) GetClockMsgNota(block Block, config *params.ThunderConfig) ClockMsgNota {
	if ci, err := d.getConsensusInfo(block, config); err == nil {
		return ci.clockNota
	}

	return nil
}

func encodeBlockSnToBytes(parentSn, sn BlockSn) []byte {
	return append(sn.ToBytes(), parentSn.ToBytes()...)
}

func EncodeBlockSnToNumber(parentSn, sn BlockSn) *big.Int {
	return new(big.Int).SetBytes(encodeBlockSnToBytes(parentSn, sn))
}

func decodeBlockSnFromBytes(data []byte) (parentSn, sn BlockSn, err error) {
	sn, data, err = NewBlockSnFromBytes(data)
	if err != nil {
		return BlockSn{}, BlockSn{}, err
	}

	parentSn, data, err = NewBlockSnFromBytes(data)
	if err != nil {
		return BlockSn{}, BlockSn{}, err
	}

	return parentSn, sn, err
}

func decodeBlockSnFromNumber(number *big.Int) (BlockSn, BlockSn, error) {
	return decodeBlockSnFromBytes(common.LeftPadBytes(number.Bytes(), 24))
}

func GetSessionFromDifficulty(df, bn *big.Int, config *params.ThunderConfig) uint32 {
	sn := GetBlockSnFromDifficulty(df, bn, config)
	return uint32(sn.Epoch.Session)
}

func GetBlockSnFromDifficulty(df, bn *big.Int, config *params.ThunderConfig) BlockSn {
	if config.IsPala(bn) {
		_, sn, err := decodeBlockSnFromNumber(df)
		if err != nil {
			debug.Bug("Cannot decode blocksn from difficulty (%v).", df)
			return BlockSn{}
		}
		return sn
	} else {
		return NewBlockSn(0, 0, uint32(bn.Uint64()))
	}
}

func GetBlockSnFromDifficultySeparately(df, bn *big.Int, config *params.ThunderConfig) (uint32, uint32, uint32) {
	blockSn := GetBlockSnFromDifficulty(df, bn, config)
	return uint32(blockSn.Epoch.Session), blockSn.Epoch.E, blockSn.S
}
