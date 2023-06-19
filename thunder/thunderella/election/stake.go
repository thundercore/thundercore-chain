package election

import (
	// Standard imports

	"math/big"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"

	// Vendor imports
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// StakeMsg is what a committee candidate sends to the commElection
type StakeMsg struct {
	Stake      *big.Int
	PubVoteKey *bls.PublicKey
	Coinbase   common.Address
	GasPrice   *big.Int
}

// ToBytes serializes a StakeMsg to bytes using RLP.
func (si *StakeMsg) ToBytes() []byte {
	buf, err := rlp.EncodeToBytes(si)
	if err != nil {
		debug.Bug("Encoding of StakeInfo err: %s", err)
	}
	return buf
}

// FromBytes decodes an RLP encoded buffer into a fully formed StakeMsg struct.
func (si *StakeMsg) FromBytes(buf []byte) error {
	if err := rlp.DecodeBytes(buf, si); err != nil {
		return err
	}
	return nil
}

// StakeInfo holds the stake message for a specific committee in a specific round.
type StakeInfo struct {
	StakeMsg
	StakingAddr common.Address // This is the sender of the stake in message. TODO rename to RefundAddr
	RefundID    []byte
}

// ToBytes serializes a StakeInfo to bytes using RLP.
func (si *StakeInfo) ToBytes() []byte {
	buf, err := rlp.EncodeToBytes(si)
	if err != nil {
		debug.Bug("Encoding of StakeInfo err: %s", err)
	}
	return buf
}

// FromBytes decodes an RLP encoded buffer into a fully formed StakeInfo struct.
func (si *StakeInfo) FromBytes(buf []byte) error {
	if err := rlp.DecodeBytes(buf, si); err != nil {
		return err
	}
	return nil
}

// ToMemberInfo converts StakeInfo into a MemberInfo struct.
func (si *StakeInfo) ToMemberInfo() *committee.MemberInfo {
	return &committee.MemberInfo{
		Stake:      new(big.Int).Set(si.Stake),
		PubVoteKey: si.PubVoteKey,
		Coinbase:   si.Coinbase,
		GasPrice:   new(big.Int).Set(si.GasPrice),
	}
}

type SignedStakeInfo struct {
	StakeInfo
	Session *big.Int
	Nonce   *big.Int
	Sig     *bls.Signature
}

func (si *SignedStakeInfo) ToBytes() []byte {
	buf, err := rlp.EncodeToBytes(si)
	if err != nil {
		debug.Bug("Encoding of StakeInfo err: %s", err)
	}
	return buf
}

func (si *SignedStakeInfo) FromBytes(buf []byte) error {
	if err := rlp.DecodeBytes(buf, si); err != nil {
		return err
	}
	return nil
}

func (si *SignedStakeInfo) signingBytes() []byte {
	/*
	                   fill    sign    store
	   Stake           o       o       o
	   PubVoteKey      o       o       o
	   Coinbase        o       o       o
	   GasPrice        o       o       o
	   Session         o       o       x
	   BiddingNonce    o       o       x
	   Sig             o       x       x
	   RefundID        o       x       o
	   StakingAddr     x       x       o
	*/
	bytes := si.StakeInfo.StakeMsg.ToBytes()
	bytes = append(bytes, si.Session.Bytes()...)
	return append(bytes, si.Nonce.Bytes()...)
}

func (si *SignedStakeInfo) Sign(key bls.BlsSigner) {
	si.Sig = key.Sign(si.signingBytes())
}

func (si *SignedStakeInfo) Verify() bool {
	return si.PubVoteKey.VerifySignature(si.signingBytes(), si.Sig)
}
