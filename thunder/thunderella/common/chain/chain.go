package chain

import (
	// Standard imports
	"errors"
	"io"
	"math"
	"strings"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"

	// Vendor imports
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	GenesisBlockNumber = 0
	FirstBlockNumber   = 1
	SeqSize            = 8
	LatestSeqNumber    = Seq(-1)
)

var (
	errHighSeqNum = errors.New("seq number too high")
)

// These types are used to encode sequence numbers (fast path) and height (auxnet / slow chain)
// in a way that will avoid accidental underflow when doing arithmetic.  We provide a base
// type which facilitates RLP serialization / deserialization.
type S int64

// Fast path sequence
type Seq S

// Slow chain height
type Height S

// Testing this revealed several very surprising behaviors of
// RLP encoding; broken messages which decode as zero can silently
// stall the consensus engine.  Be very careful what you put in
// on the wire packets.
func (s S) EncodeRLP(w io.Writer) error {
	if s < 0 {
		debug.Bug("Encoding negative sequence")
	}
	return rlp.Encode(w, uint64(s))
}

func (s Seq) EncodeRLP(w io.Writer) error {
	return S(s).EncodeRLP(w)
}

func (h Height) EncodeRLP(w io.Writer) error {
	return S(h).EncodeRLP(w)
}

func (s *S) DecodeRLP(st *rlp.Stream) error {
	var u uint64
	err := st.Decode(&u)
	if err != nil {
		return err
	}
	*s = S(u)
	return nil
}

func (s *Seq) DecodeRLP(st *rlp.Stream) error {
	return (*S)(s).DecodeRLP(st)
}

// The idea is borrowed from go-ethereum/rpc/types.go
func (s *Seq) UnmarshalJSON(data []byte) error {
	input := strings.TrimSpace(string(data))
	if len(input) >= 2 && input[0] == '"' && input[len(input)-1] == '"' {
		input = input[1 : len(input)-1]
	}

	if input == "latest" {
		*s = LatestSeqNumber
		return nil
	}

	seqNum, err := hexutil.DecodeUint64(input)
	if err != nil {
		return err
	}
	if seqNum > math.MaxInt64 {
		return errHighSeqNum
	}

	*s = Seq(seqNum)
	return nil
}

func (h *Height) DecodeRLP(st *rlp.Stream) error {
	return (*S)(h).DecodeRLP(st)
}
