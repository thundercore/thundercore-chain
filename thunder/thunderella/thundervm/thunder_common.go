package thundervm

import (
	"math/big"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"

	"github.com/ethereum/go-ethereum/common"
)

type stakeValue struct {
	Value *big.Int
}

func (sv *stakeValue) FromBytes(input []byte) error {
	if len(input) > HashLength {
		input = input[len(input)-HashLength:]
	} else {
		input = common.LeftPadBytes(input, HashLength)
	}

	sv.Value = common.BytesToHash(input).Big()

	return nil
}

func (sv *stakeValue) ToBytes() []byte {
	return common.BigToHash(sv.Value).Bytes()
}

type frozenIndex string

func (fi *frozenIndex) ToBytes() []byte {
	return []byte(*fi)
}

func (fi *frozenIndex) FromBytes(input []byte) error {
	*fi = frozenIndex(input)
	return nil
}

type testBidder struct {
	votekey *bls.SigningKey
	addr    common.Address
}
