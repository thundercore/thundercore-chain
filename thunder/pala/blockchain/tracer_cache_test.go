package blockchain

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func IntToHash(i int64) common.Hash {
	return common.BigToHash(new(big.Int).SetInt64(i))
}
func TestCapAndEvictPolicy(t *testing.T) {
	req := require.New(t)
	var (
		get = 0
		put = 1
	)

	tc := newTracerCache(4)
	testcase := []struct {
		op          int
		number      uint64
		hash        common.Hash
		expectExist bool
	}{
		{put, 0, IntToHash(0), false},
		{put, 1, IntToHash(1), false},
		{put, 2, IntToHash(2), false},
		{put, 3, IntToHash(3), false},
		{get, 4, IntToHash(4), false},

		// evict 0
		{put, 5, IntToHash(5), false},
		{get, 5, IntToHash(5), true},
		{get, 3, IntToHash(3), true},
		{get, 0, IntToHash(0), false},

		// evict 1
		{put, 10, IntToHash(10), false},
		{get, 1, IntToHash(1), false},

		// evict 2
		{put, 9, IntToHash(9), false},
		{get, 2, IntToHash(2), false},
		{get, 3, IntToHash(3), true},

		// evict 3
		{put, 8, IntToHash(8), false},
		{get, 3, IntToHash(3), false},

		// evict 5
		{put, 7, IntToHash(7), false},

		// evict 6 itself
		{put, 6, IntToHash(6), false},

		{get, 10, IntToHash(10), true},
		{get, 9, IntToHash(9), true},
		{get, 8, IntToHash(8), true},
		{get, 7, IntToHash(7), true},
		{get, 6, IntToHash(6), false},
		{get, 5, IntToHash(5), false},
		{get, 4, IntToHash(4), false},
		{get, 0, IntToHash(0), false},

		// getter evict hash mismatch, evict 7 since getter mismatched
		{get, 7, IntToHash(8), false},
		{get, 7, IntToHash(7), false},
	}

	for _, t := range testcase {
		switch t.op {
		case put:
			tc.put(t.number, t.hash, nil)
		case get:
			_, err := tc.get(t.number, t.hash)
			if t.expectExist {
				req.NoError(err)
			} else {
				req.EqualError(err, ErrBlockNotFound.Error())
			}
		}
	}
}
