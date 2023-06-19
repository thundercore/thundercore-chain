package blockchain

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"
)

type clockMsgImpl struct {
	epoch     Epoch
	signature *bls.Signature
	voterId   ConsensusId
}

func (c *clockMsgImpl) ImplementsClockMsg() {
}

func (c *clockMsgImpl) GetType() Type {
	return TypeClockMsg
}

func (c *clockMsgImpl) GetBody() []byte {
	bytes := utils.StringToBytes(string(c.voterId))
	bytes = append(bytes, c.signature.ToBytes()...)
	return append(bytes, c.epoch.ToBytes()...)
}

func (c *clockMsgImpl) GetBlockSn() BlockSn {
	return BlockSn{c.epoch, 1}
}

func (c *clockMsgImpl) GetDebugString() string {
	return c.String()
}

func (c *clockMsgImpl) String() string {
	return fmt.Sprintf("clockMsgImpl{%s,%s}", c.epoch, c.voterId)
}

func (c *clockMsgImpl) GetEpoch() Epoch {
	return c.epoch
}

func (c *clockMsgImpl) GetVoterId() ConsensusId {
	return c.voterId
}

func (c *clockMsgImpl) GetSignature() *bls.Signature {
	return c.signature
}

func (c *clockMsgImpl) equals(v *clockMsgImpl) bool {
	return bytes.Equal(c.signature.ToBytes(), v.signature.ToBytes()) &&
		c.epoch.Compare(v.GetEpoch()) == 0 &&
		c.voterId == v.GetVoterId()
}

func NewClockMsgImpl(e Epoch, s bls.BlsSigner) ClockMsg {
	return &clockMsgImpl{
		epoch:     e,
		signature: s.Sign(e.ToBytes()),
		voterId:   ConsensusIdFromPubKey(s.GetPublicKey()),
	}
}
