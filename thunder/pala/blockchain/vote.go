package blockchain

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"
)

type voteImpl struct {
	blockHash Hash
	sn        BlockSn
	signature *bls.Signature
	voterId   ConsensusId
}

func (v *voteImpl) ImplementsVote() {
}

func (v *voteImpl) GetType() Type {
	return TypeVote
}

func (v *voteImpl) GetBody() []byte {
	bytes := utils.StringToBytes(string(v.voterId))
	bytes = append(bytes, v.signature.ToBytes()...)
	bytes = append(bytes, v.sn.ToBytes()...)
	return append(bytes, v.blockHash.Bytes()...)
}

func (v *voteImpl) GetBlockSn() BlockSn {
	return v.sn
}

func (v *voteImpl) GetDebugString() string {
	return v.String()
}

func (v *voteImpl) String() string {
	return fmt.Sprintf("voteImpl{%s,%s}", v.sn, v.voterId)
}

func (v *voteImpl) GetVoterId() ConsensusId {
	return v.voterId
}

func (v *voteImpl) GetBlockHash() Hash {
	return v.blockHash
}

func (v *voteImpl) GetSignature() *bls.Signature {
	return v.signature
}

func (v *voteImpl) equals(s *voteImpl) bool {
	return bytes.Equal(v.signature.ToBytes(), s.signature.ToBytes()) &&
		v.blockHash == s.blockHash &&
		v.sn.Compare(s.GetBlockSn()) == 0 &&
		v.voterId == s.GetVoterId()
}

func NewVoteImpl(p Proposal, s bls.BlsSigner) Vote {
	return &voteImpl{
		blockHash: p.GetBlock().GetHash(),
		sn:        p.GetBlockSn(),
		signature: s.Sign(p.GetBlock().GetHash().Bytes()),
		voterId:   ConsensusIdFromPubKey(s.GetPublicKey()),
	}
}
