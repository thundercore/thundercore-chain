package blockchain

import (
	"bytes"
	"fmt"
	"reflect"
	"sync"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"
)

type notarizationImpl struct {
	sn               BlockSn
	blockHash        Hash
	aggSig           *bls.Signature
	proposerIdx      uint16
	nVote            uint16
	missingVoterIdxs []uint16
	// Cache: should not be serialized.
	statusMutex sync.Mutex
	vStatus     verificationStatus
}

type verificationStatus int

const (
	unknown = verificationStatus(0)
	valid   = verificationStatus(1)
	invalid = verificationStatus(2)
)

func (n *notarizationImpl) ImplementsNotarization() {
}

func (n *notarizationImpl) GetType() Type {
	return TypeNotarization
}

func (n *notarizationImpl) GetBody() []byte {
	var out [][]byte
	out = append(out, n.sn.ToBytes())
	out = append(out, n.blockHash.Bytes())
	out = append(out, n.aggSig.ToBytes())
	out = append(out, utils.Uint16ToBytes(n.proposerIdx))
	out = append(out, utils.Uint16ToBytes(n.nVote))
	out = append(out, utils.Uint16ToBytes(uint16(len(n.missingVoterIdxs))))
	for _, v := range n.missingVoterIdxs {
		out = append(out, utils.Uint16ToBytes(v))
	}
	return utils.ConcatCopyPreAllocate(out)
}

func (n *notarizationImpl) GetBlockSn() BlockSn {
	return n.sn
}

func (n *notarizationImpl) GetMissingVoterIdxs() []uint16 {
	return n.missingVoterIdxs
}

func (n *notarizationImpl) GetDebugString() string {
	return n.String()
}

func (n *notarizationImpl) String() string {
	return fmt.Sprintf("notarizationImpl{%s,%x,%d,%d,%d}", n.sn, n.blockHash, n.proposerIdx, n.nVote, n.missingVoterIdxs)
}

func (n *notarizationImpl) GetNVote() uint16 {
	return n.nVote
}

func (n *notarizationImpl) GetBlockHash() Hash {
	return n.blockHash
}

func (n *notarizationImpl) equals(v *notarizationImpl) bool {
	return bytes.Equal(n.aggSig.ToBytes(), v.aggSig.ToBytes()) &&
		n.sn.Compare(v.GetBlockSn()) == 0 &&
		n.blockHash == v.GetBlockHash() &&
		n.proposerIdx == v.proposerIdx &&
		n.nVote == v.nVote &&
		reflect.DeepEqual(n.missingVoterIdxs, v.missingVoterIdxs)
}

func (n *notarizationImpl) setStatus(s verificationStatus) {
	n.statusMutex.Lock()
	defer n.statusMutex.Unlock()
	if n.vStatus != unknown {
		debug.Bug("unexpected call: notarizationImpl.setStatus should be called only once")
	}
	n.vStatus = s
}

func (n *notarizationImpl) getStatus() verificationStatus {
	n.statusMutex.Lock()
	defer n.statusMutex.Unlock()
	return n.vStatus
}

func NewNotarizationImpl(b Block, pSigner bls.BlsSigner, pIdx uint16, vSigners []*bls.SigningKey, missingVIdxs []uint16) Notarization {
	aggSig, aggPk := pSigner.Sign(b.GetHash().Bytes()), pSigner.GetPublicKey()
	for _, s := range vSigners {
		sig := s.Sign(b.GetHash().Bytes())
		aggSig, aggPk = bls.CombineSignatures(aggSig, sig, aggPk, s.GetPublicKey())
	}
	return &notarizationImpl{
		aggSig:           aggSig,
		blockHash:        b.GetHash(),
		sn:               b.GetBlockSn(),
		proposerIdx:      pIdx,
		nVote:            uint16(len(vSigners)),
		missingVoterIdxs: missingVIdxs,
	}
}
