package blockchain

import (
	"errors"

	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
)

var (
	freshestNotarizedHead = []byte("ttFreshestNota")
	finalizedSnKey        = []byte("ttFinalizedSn") // finalized chain is the canonical chain with finalized height

	blockPrefix            = []byte("ttBlock") // blockPrefix + BlockSn -> blockHash
	notarizationPrefix     = []byte("n")       // blockPrefix + BlockSn + notarizationPrefix -> notarization
	sessionStopBlockPrefix = []byte("ttStop")  // sessionStopBlockPrefix + Session -> blockHash

	clockNotarizationPrefix = []byte("ttClockNota") // clockNotarizationPrefix + Epoch -> notarization

	epochStatusKey = []byte("ttEpochStatus") // epoch status -> epochStatus

	schemaVersionKey = []byte("ttSchemaVersion")

	errDataNotFound = errors.New("entry not found")
)

func encodeBlockSn(sn BlockSn) []byte {
	return sn.ToBytes()
}

func blockSnKey(sn BlockSn) []byte {
	return append(blockPrefix, encodeBlockSn(sn)...)
}

func sessionStopKey(session Session) []byte {
	return append(sessionStopBlockPrefix, utils.Uint32ToBytes(uint32(session))...)
}

func notarizationKey(sn BlockSn) []byte {
	return append(blockSnKey(sn), notarizationPrefix...)
}

func writeNotarization(w ethdb.KeyValueWriter, sn BlockSn, nota Notarization) error {
	return w.Put(notarizationKey(sn), nota.GetBody())
}

func deleteNotarization(d DatabaseDeleter, sn BlockSn) error {
	return d.Delete(notarizationKey(sn))
}

func readHistoryDatabase(r ethdb.Reader, key []byte) ([]byte, error) {
	// retrieves the given key in the default store.
	data, err := r.Get(key)
	if len(data) != 0 {
		return data, nil
	}

	// Then try to look up the history data in the history store.
	data, _ = r.HistoryGet(key)
	if len(data) != 0 {
		return data, nil
	}

	if err != nil {
		return nil, err
	}

	return nil, errDataNotFound
}

func readNotarization(r ethdb.Reader, marshaller DataUnmarshaller, sn BlockSn) Notarization {
	data, err := readHistoryDatabase(r, notarizationKey(sn))
	if err != nil {
		return nil
	}

	nota, _, err := marshaller.UnmarshalNotarization(data)
	if err != nil {
		return nil
	}

	return nota
}

func readRawNotarization(r ethdb.Reader, sn BlockSn) []byte {
	data, err := readHistoryDatabase(r, notarizationKey(sn))
	if err != nil {
		return nil
	}
	return data
}
func writeRawNotarization(r ethdb.KeyValueWriter, sn BlockSn, rawNota []byte) error {
	return r.Put(notarizationKey(sn), rawNota)
}

func readFinalizedBlockSn(r ethdb.Reader) BlockSn {
	var (
		sn   BlockSn
		data []byte
		err  error
	)
	if data, err = readHistoryDatabase(r, finalizedSnKey); err != nil {
		return BlockSn{}
	}

	if sn, _, err = NewBlockSnFromBytes(data); err != nil {
		return BlockSn{}
	}

	return sn
}

func writeFinalizeBlockSn(w ethdb.KeyValueWriter, sn BlockSn) error {
	return w.Put(finalizedSnKey, sn.ToBytes())
}

func readHashAndNumber(r ethdb.Reader, sn BlockSn, bc *core.BlockChain) (*common.Hash, uint64) {
	var (
		hash   common.Hash
		number uint64
	)

	if sn.IsGenesis() {
		number = uint64(0)
		hash = rawdb.ReadCanonicalHash(r, number)
	} else if !sn.IsPala() {
		// this means we are getting block from old chain (without difficulty encoded)
		// we consider all blocks that made before Pala are in BlockSn{0, 1, Block.Number}
		number = uint64(sn.S)
		hash = rawdb.ReadCanonicalHash(r, number)
	} else {
		var (
			data []byte
			err  error
		)

		if data, err = readHistoryDatabase(r, blockSnKey(sn)); err != nil {
			return nil, 0
		}

		numberPtr := rawdb.ReadHeaderNumber(r, common.BytesToHash(data))
		if numberPtr == nil {
			return nil, 0
		}
		number = *numberPtr
		hash = common.BytesToHash(data)
	}

	return &hash, number
}

func readBlock(r ethdb.Reader, sn BlockSn, bc *core.BlockChain) Block {
	hash, number := readHashAndNumber(r, sn, bc)
	if hash == nil {
		return nil
	}

	if block := bc.GetBlock(*hash, number); block != nil {
		return newBlock(block, bc.Config().Thunder)
	}

	return nil
}

func readHeader(r ethdb.Reader, sn BlockSn, bc *core.BlockChain) *types.Header {
	hash, number := readHashAndNumber(r, sn, bc)
	if hash == nil {
		return nil
	}
	return bc.GetHeader(*hash, number)
}

func writeBlockMeta(w ethdb.KeyValueWriter, block Block) error {
	hash := block.GetHash()
	return w.Put(blockSnKey(block.GetBlockSn()), hash[:])
}

func WriteSnapshotBlock(w ethdb.KeyValueWriter, sn BlockSn, meta, nota, sessionStopBlock []byte) error {
	if err := w.Put(blockSnKey(sn), meta); err != nil {
		return err
	}

	if err := writeRawNotarization(w, sn, nota); err != nil {
		return err
	}

	if len(sessionStopBlock) > 0 {
		if err := w.Put(sessionStopKey(sn.Epoch.Session), sessionStopBlock); err != nil {
			return err
		}
	}

	return nil
}

func deleteBlockMeta(d DatabaseDeleter, sn BlockSn) error {
	return d.Delete(blockSnKey(sn))
}

func readFreshestNotarization(r ethdb.Reader) BlockSn {
	var (
		data []byte
		err  error
	)
	if data, err = readHistoryDatabase(r, freshestNotarizedHead); err != nil {
		return GetGenesisBlockSn()
	}
	sn, _, err := NewBlockSnFromBytes(data)
	if err != nil {
		return GetGenesisBlockSn()
	}

	return sn
}

func writeFreshestNotarization(w ethdb.KeyValueWriter, sn BlockSn) error {
	return w.Put(freshestNotarizedHead, encodeBlockSn(sn))
}

func clockMsgNotaKey(e Epoch) []byte {
	return append(clockNotarizationPrefix, e.ToBytes()...)
}

func writeClockMsgNotarization(w ethdb.KeyValueWriter, cNota ClockMsgNota) error {
	return w.Put(clockMsgNotaKey(cNota.GetEpoch()), cNota.GetBody())
}

func readClockMsgNotarization(r ethdb.Reader, marshaller DataUnmarshaller, e Epoch) ClockMsgNota {
	var (
		data []byte
		err  error
	)

	if data, err = readHistoryDatabase(r, clockMsgNotaKey(e)); err != nil {
		return nil
	}

	nota, _, err := marshaller.UnmarshalClockMsgNota(data)
	if err != nil {
		return nil
	}

	return nota
}

func writeSessionStopBlockNumber(w ethdb.KeyValueWriter, session Session, number uint64) error {
	return w.Put(sessionStopKey(session), utils.Uint64ToBytes(number))
}

func readSessionStopHeader(r ethdb.Reader, session Session) (*types.Header, BlockSn) {
	var (
		hash   common.Hash
		number uint64
	)

	var (
		data []byte
		err  error
	)

	if data, err = readHistoryDatabase(r, sessionStopKey(session)); err != nil {
		return nil, BlockSn{}
	}

	number, _, err = utils.BytesToUint64(data)
	if err != nil {
		return nil, BlockSn{}
	}

	hash = rawdb.ReadCanonicalHash(r, number)
	if hash == (common.Hash{}) {
		return nil, BlockSn{}
	}

	header := rawdb.ReadHeader(r, hash, number)
	if session == 0 {
		if number == 0 {
			return header, GetGenesisBlockSn()
		} else {
			return header, NewBlockSn(0, 1, uint32(number))
		}
	} else {
		_, sn, err := decodeBlockSnFromNumber(header.Difficulty)
		if err != nil {
			return nil, BlockSn{}
		}
		return header, sn
	}
}

func writeEpochStatus(w ethdb.KeyValueWriter, es *epochStatus) error {
	return w.Put(epochStatusKey, es.epoch.ToBytes())
}

func readEpochStatus(r ethdb.Reader, marshaller DataUnmarshaller) *epochStatus {
	var (
		e    Epoch
		data []byte
		err  error
	)

	if data, err = readHistoryDatabase(r, epochStatusKey); err != nil {
		return nil
	}

	e, data, err = NewEpochFromBytes(data)
	if err != nil {
		return nil
	}

	cn := readClockMsgNotarization(r, marshaller, e)

	return &epochStatus{
		epoch:     e,
		clockNota: cn,
	}
}

func writeSchemaVersion(w ethdb.KeyValueWriter, version string) error {
	return w.Put(schemaVersionKey, []byte(version))
}

func readSchemaVersion(r ethdb.Reader) (string, error) {
	var (
		data []byte
		err  error
	)

	if data, err = readHistoryDatabase(r, schemaVersionKey); err != nil {
		return "", err
	}

	return string(data), nil
}
