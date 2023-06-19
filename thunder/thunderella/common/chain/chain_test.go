package chain

import (
	"math"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalJSON(t *testing.T) {
	assert := assert.New(t)

	var seqUnmarshalTests = []struct {
		input []byte
		s     Seq
		err   error
	}{
		{[]byte("latest"), LatestSeqNumber, nil},
		{[]byte("0x1"), Seq(1), nil},
		{[]byte(" 0x10 "), Seq(0x10), nil},
		{[]byte("0x01"), Seq(0), hexutil.ErrLeadingZero},
		{[]byte(""), Seq(0), hexutil.ErrEmptyString},
		{[]byte("xyz"), Seq(0), hexutil.ErrMissingPrefix},
		{[]byte("0xxyz"), Seq(0), hexutil.ErrSyntax},
		{[]byte("0x7fffffffffffffff"), Seq(math.MaxInt64), nil},
		{[]byte("0x8fffffffffffffff"), Seq(0), errHighSeqNum},
	}

	for _, test := range seqUnmarshalTests {
		var s Seq
		err := (&s).UnmarshalJSON(test.input)
		assert.Equal(s, test.s)
		assert.Equal(err, test.err)
	}
}
