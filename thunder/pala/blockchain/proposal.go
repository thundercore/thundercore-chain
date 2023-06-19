package blockchain

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"
)

type proposalImpl struct {
	block      Block
	signature  *bls.Signature
	proposerId ConsensusId
}

func (p *proposalImpl) ImplementsProposal() {
}

func (p *proposalImpl) GetType() Type {
	return TypeProposal
}

func (p *proposalImpl) GetBody() []byte {
	bytes := utils.StringToBytes(string(p.proposerId))
	bytes = append(bytes, p.signature.ToBytes()...)
	return append(bytes, p.block.GetBody()...)
}

func (p *proposalImpl) GetBlockSn() BlockSn {
	return p.block.GetBlockSn()
}

func (p *proposalImpl) GetDebugString() string {
	return p.String()
}

func (p *proposalImpl) String() string {
	return fmt.Sprintf("proposalImpl{%s,%s}", p.block.GetBlockSn(), p.proposerId)
}

func (p *proposalImpl) GetBlock() Block {
	return p.block
}

func (p *proposalImpl) GetProposerId() ConsensusId {
	return p.proposerId
}

func (p *proposalImpl) equals(v *proposalImpl) bool {
	return bytes.Equal(p.signature.ToBytes(), v.signature.ToBytes()) &&
		p.GetBlockSn() == v.GetBlockSn() &&
		p.GetBlock().GetHash() == v.GetBlock().GetHash() &&
		p.proposerId == v.GetProposerId()
}

func NewProposalImpl(b Block, s bls.BlsSigner) Proposal {
	return &proposalImpl{
		block:      b,
		signature:  s.Sign(b.GetHash().Bytes()),
		proposerId: ConsensusIdFromPubKey(s.GetPublicKey()),
	}
}
