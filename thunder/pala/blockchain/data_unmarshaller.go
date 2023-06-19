package blockchain

import (
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/xerrors"
)

const blsSigBytes = 256 / 8 * 2

func bytesToBlsSig(bytes []byte) (*bls.Signature, []byte, error) {
	if len(bytes) < blsSigBytes {
		return nil, nil, xerrors.Errorf("invalid sig bytes: len(bytes) = %d < %d", len(bytes), blsSigBytes)
	}

	if sig, err := bls.SignatureFromBytes(bytes[:blsSigBytes]); err != nil {
		return nil, nil, err
	} else {
		return sig, bytes[blsSigBytes:], nil
	}
}

func bytesToHash(bytes []byte) (Hash, []byte, error) {
	if len(bytes) < HashLength {
		return Hash{}, nil, xerrors.Errorf("invalid hash bytes: len(bytes) = %d < %d", len(bytes), HashLength)
	}
	return BytesToHash(bytes[:HashLength]), bytes[HashLength:], nil
}

type DataUnmarshallerImpl struct {
	Config *params.ThunderConfig
}

func (d *DataUnmarshallerImpl) UnmarshalBlock(bytes []byte) (Block, []byte, error) {
	logger.Debug("UnmarshalBlock")
	if d.Config == nil {
		debug.Bug("Need config to decode block here")
	}

	b := new(ethtypes.Block)
	if err := rlp.DecodeBytes(bytes, b); err != nil {
		return nil, bytes, err
	}

	bi := newBlock(b, d.Config)

	return bi, []byte{}, nil
}

func (d *DataUnmarshallerImpl) UnmarshalProposal(bytes []byte) (Proposal, []byte, error) {
	logger.Debug("UnmarshalProposal")
	idStr, bytes, err := utils.BytesToString(bytes)
	if err != nil {
		return nil, nil, err
	}
	id := ConsensusId(idStr)

	sig, bytes, err := bytesToBlsSig(bytes)
	if err != nil {
		return nil, nil, err
	}

	if block, bytes, err := d.UnmarshalBlock(bytes); err != nil {
		return nil, nil, err
	} else {
		return &proposalImpl{block: block, proposerId: id, signature: sig}, bytes, nil
	}
}

func (d *DataUnmarshallerImpl) UnmarshalVote(bytes []byte) (Vote, []byte, error) {
	logger.Debug("UnmarshalVote")
	idStr, bytes, err := utils.BytesToString(bytes)
	if err != nil {
		return nil, nil, err
	}
	id := ConsensusId(idStr)

	sig, bytes, err := bytesToBlsSig(bytes)
	if err != nil {
		return nil, nil, err
	}

	sn, bytes, err := NewBlockSnFromBytes(bytes)
	if err != nil {
		return nil, nil, err
	}

	if hash, bytes, err := bytesToHash(bytes); err != nil {
		return nil, nil, err
	} else {
		return &voteImpl{voterId: id, sn: sn, signature: sig, blockHash: hash}, bytes, nil
	}
}

// | blocksn  |  common.Hash | bls.sig 256 / 8 * 2 | pindex (int16) | nvote (int16) |  nmissingVote(int16) |  missvote * n (int16 * n)
func (d *DataUnmarshallerImpl) UnmarshalNotarization(bytes []byte) (Notarization, []byte, error) {
	logger.Debug("UnmarshalNotarization")
	missingVoterIdxs := make([]uint16, 0)

	sn, bytes, err := NewBlockSnFromBytes(bytes)
	if err != nil {
		return nil, nil, err
	}

	hash, bytes, err := bytesToHash(bytes)
	if err != nil {
		return nil, nil, err
	}

	sig, bytes, err := bytesToBlsSig(bytes)
	if err != nil {
		return nil, nil, err
	}

	pIdx, bytes, err := utils.BytesToUint16(bytes)
	if err != nil {
		return nil, nil, err
	}

	nVote, bytes, err := utils.BytesToUint16(bytes)
	if err != nil {
		return nil, nil, err
	}

	nMissingVote, bytes, err := utils.BytesToUint16(bytes)
	if err != nil {
		return nil, nil, err
	}

	for i := 0; i < int(nMissingVote); i++ {
		var v uint16
		var err error
		v, bytes, err = utils.BytesToUint16(bytes)
		if err != nil {
			return nil, nil, err
		}
		missingVoterIdxs = append(missingVoterIdxs, v)
	}
	return &notarizationImpl{
		sn:               sn,
		aggSig:           sig,
		blockHash:        hash,
		proposerIdx:      pIdx,
		nVote:            nVote,
		missingVoterIdxs: missingVoterIdxs,
	}, bytes, nil
}

func (d *DataUnmarshallerImpl) UnmarshalClockMsg(bytes []byte) (ClockMsg, []byte, error) {
	logger.Debug("UnmarshalClockMsg")
	idStr, bytes, err := utils.BytesToString(bytes)
	if err != nil {
		return nil, nil, err
	}
	id := ConsensusId(idStr)

	sig, bytes, err := bytesToBlsSig(bytes)
	if err != nil {
		return nil, nil, err
	}

	if e, bytes, err := NewEpochFromBytes(bytes); err != nil {
		return nil, nil, err
	} else {
		return &clockMsgImpl{voterId: id, signature: sig, epoch: e}, bytes, nil
	}
}

// | epoch | bls.sig 256 / 8 * 2 | pindex (int16) | nvote (int16) |  nmissingVote(int16) |  missvote * n (int16 * n) |
func (d *DataUnmarshallerImpl) UnmarshalClockMsgNota(bytes []byte) (ClockMsgNota, []byte, error) {
	logger.Debug("UnmarshalClockMsgNota")
	missingVoterIdxs := make([]uint16, 0)

	e, bytes, err := NewEpochFromBytes(bytes)
	if err != nil {
		return nil, nil, err
	}

	sig, bytes, err := bytesToBlsSig(bytes)
	if err != nil {
		return nil, nil, err
	}

	pIdx, bytes, err := utils.BytesToUint16(bytes)
	if err != nil {
		return nil, nil, err
	}

	nVote, bytes, err := utils.BytesToUint16(bytes)
	if err != nil {
		return nil, nil, err
	}

	nMissingVote, bytes, err := utils.BytesToUint16(bytes)
	if err != nil {
		return nil, nil, err
	}

	for i := 0; i < int(nMissingVote); i++ {
		var v uint16
		var err error
		v, bytes, err = utils.BytesToUint16(bytes)
		if err != nil {
			return nil, nil, err
		}
		missingVoterIdxs = append(missingVoterIdxs, v)
	}
	return &clockMsgNotaImpl{
		epoch:            e,
		aggSig:           sig,
		proposerIdx:      pIdx,
		nVote:            nVote,
		missingVoterIdxs: missingVoterIdxs,
	}, bytes, nil
}
