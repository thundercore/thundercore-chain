package types

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"

	"golang.org/x/crypto/sha3"
)

type ConsensusId string

type HasToBytes interface {
	ToBytes() []byte
}

func ConsensusIdFromPubKey(publicKey HasToBytes) ConsensusId {
	// last 20 bytes of keccak256(publicKey)
	return ConsensusIdFromBytes(publicKey.ToBytes())
}

func ConsensusIdFromBytes(bytes []byte) ConsensusId {
	h := sha3.NewLegacyKeccak256()
	t := make([]byte, 0, h.Size())
	_, err := h.Write(bytes)
	if err != nil {
		debug.Bug("sha3.LegacyKeccak256.Write failed: %s", err)
	}
	t = h.Sum(t)
	return ConsensusId(fmt.Sprintf("%0x", t[len(t)-20:]))
}

// ConsensusIdWithRandomPostfix returns strings with the format "${prefix}-${randomNumber}"
// These are meant to be used as consensus-IDs of nodes that don't derive
// an ID from a public-private key.
func ConsensusIdWithRandomPostfix(prefix string) ConsensusId {
	const nBits = 64
	n := new(big.Int)
	n.Lsh(big.NewInt(1), nBits) // n := (1 << nBits)
	r, err := rand.Int(rand.Reader, n)
	if err != nil {
		debug.Bug("crypto/rand.Int failed: %s", err)
	}
	return ConsensusId(fmt.Sprintf("%s-%0x", prefix, r.Bytes()))
}

type ConsensusIdSlice []ConsensusId

// ConsensusIds attaches its methods e.g. `Sort()` and `StringSlice()` to `[]Consensus`
func ConsensusIds(ids []ConsensusId) ConsensusIdSlice {
	return ConsensusIdSlice(ids)
}

func (ids ConsensusIdSlice) StringSlice() []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	return out
}

// Sort sorts a ConsensusIdSlice in increasing order
func (ids ConsensusIdSlice) Sort() {
	sort.Slice(ids, func(i, j int) bool {
		return ids[i] < ids[j]
	})
}

func (ids ConsensusIdSlice) FindIndex(target ConsensusId) int {
	for i, id := range ids {
		if id == target {
			return i
		}
	}
	return len(ids)
}

func (ids ConsensusIdSlice) Contains(target ConsensusId) bool {
	return ids.FindIndex(target) != len(ids)
}

// MakeConsensusIds converts its arguments to a `[]ConsensusId`
func MakeConsensusIds(ids ...string) []ConsensusId {
	out := make([]ConsensusId, len(ids))
	for i, id := range ids {
		out[i] = ConsensusId(id)
	}
	return out
}
