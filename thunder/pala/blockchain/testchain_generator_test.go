package blockchain

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/thunder/thunderella/config"

	"github.com/stretchr/testify/require"
)

func DumpChain(chain BlockChain, tailBs BlockSn) string {
	bs := []Block{}
	b := chain.GetBlock(tailBs)
	for {
		if b == nil || b.GetBlockSn() == GetGenesisBlockSn() {
			break
		}
		bs = append(bs, b)
		b = chain.GetBlock(b.GetParentBlockSn())
	}

	for i, j := 0, len(bs)-1; i < j; i, j = i+1, j-1 {
		bs[i], bs[j] = bs[j], bs[i]
	}

	var blockStrs []string
	for _, b := range bs {
		blockStrs = append(blockStrs, b.GetBlockSn().String())
	}

	return strings.Join(blockStrs, "->")

}

func TestRealChainGenerator(t *testing.T) {
	t.Run("normal chain", func(t *testing.T) {
		req := require.New(t)
		k := uint32(2)
		hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
		hardforkK.SetTestValueAtSession(int64(k), 0)

		c, err := NewChainGenerator(false, hardforkK)
		req.NoError(err)

		err = c.Init(NewBlockSn(1, 1, 5))
		req.NoError(err)

		req.Equal(
			"(1,1,1)->(1,1,2)->(1,1,3)->(1,1,4)->(1,1,5)",
			DumpChain(c.GetChain(), NewBlockSn(1, 1, 5)),
		)
		req.Equal(NewBlockSn(1, 1, 3), c.GetChain().GetFreshestNotarizedHeadSn())
		req.Equal(NewBlockSn(1, 1, 1), c.GetChain().GetFinalizedHeadSn())
	})

	t.Run("add non-existed block", func(t *testing.T) {
		req := require.New(t)
		k := uint32(2)
		hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
		hardforkK.SetTestValueAtSession(int64(k), 0)

		c, err := NewChainGenerator(false, hardforkK)
		req.NoError(err)

		err = c.Init(NewBlockSn(1, 1, 5))
		req.NoError(err)

		err = c.Branch(NewBlockSn(1, 2, 2), NewBlockSn(1, 2, 5))
		req.Error(err)
	})

	t.Run("timeout chain", func(t *testing.T) {
		req := require.New(t)
		k := uint32(3)
		hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
		hardforkK.SetTestValueAtSession(int64(k), 0)

		c, err := NewChainGenerator(false, hardforkK)
		req.NoError(err)

		// (1,1,1)->(1,1,2)->(1,1,3)
		//             |
		//             ----->(1,2,1)->(1,2,2)->(1,2,3)
		//                               |
		//                               ----->(1,3,1)->(1,3,2)->(1,3,3)->(1,3,4)->(1,3,5)
		err = c.Init(NewBlockSn(1, 1, 3))
		req.NoError(err)
		err = c.Branch(NewBlockSn(1, 1, 2), NewBlockSn(1, 2, 3))
		req.NoError(err)
		err = c.Branch(NewBlockSn(1, 2, 2), NewBlockSn(1, 3, 5))
		req.NoError(err)

		req.Equal(
			"(1,1,1)->(1,1,2)->(1,1,3)",
			DumpChain(c.GetChain(), NewBlockSn(1, 1, 3)),
		)
		req.Equal(
			"(1,1,1)->(1,1,2)->(1,2,1)->(1,2,2)->(1,2,3)",
			DumpChain(c.GetChain(), NewBlockSn(1, 2, 3)),
		)
		req.Equal(
			"(1,1,1)->(1,1,2)->(1,2,1)->(1,2,2)->(1,3,1)->(1,3,2)->(1,3,3)->(1,3,4)->(1,3,5)",
			DumpChain(c.GetChain(), NewBlockSn(1, 3, 5)),
		)
		req.Equal(NewBlockSn(1, 3, 2), c.GetChain().GetFreshestNotarizedHeadSn())
	})
}

func TestFakeChainGenerator(t *testing.T) {
	t.Run("normal chain", func(t *testing.T) {
		req := require.New(t)
		k := uint32(2)
		hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
		hardforkK.SetTestValueAtSession(int64(k), 0)

		c, err := NewChainGenerator(true, hardforkK)
		req.NoError(err)

		err = c.Init(NewBlockSn(1, 1, 5))
		req.NoError(err)

		req.Equal(
			"(1,1,1)->(1,1,2)->(1,1,3)->(1,1,4)->(1,1,5)",
			DumpChain(c.GetChain(), NewBlockSn(1, 1, 5)),
		)
		req.Equal(NewBlockSn(1, 1, 3), c.GetChain().GetFreshestNotarizedHeadSn())
		req.Equal(NewBlockSn(1, 1, 1), c.GetChain().GetFinalizedHeadSn())
	})

	t.Run("timeout chain", func(t *testing.T) {
		req := require.New(t)
		k := uint32(3)
		hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
		hardforkK.SetTestValueAtSession(int64(k), 0)

		c, err := NewChainGenerator(true, hardforkK)
		req.NoError(err)

		// (1,1,1)->(1,1,2)->(1,1,3)
		//             |
		//             ----->(1,2,1)->(1,2,2)->(1,2,3)
		//                               |
		//                               ----->(1,3,1)->(1,3,2)->(1,3,3)->(1,3,4)->(1,3,5)
		err = c.Init(NewBlockSn(1, 1, 3))
		req.NoError(err)
		err = c.Branch(NewBlockSn(1, 1, 2), NewBlockSn(1, 2, 3))
		req.NoError(err)
		err = c.Branch(NewBlockSn(1, 2, 2), NewBlockSn(1, 3, 5))
		req.NoError(err)

		req.Equal(
			"(1,1,1)->(1,1,2)->(1,1,3)",
			DumpChain(c.GetChain(), NewBlockSn(1, 1, 3)),
		)
		req.Equal(
			"(1,1,1)->(1,1,2)->(1,2,1)->(1,2,2)->(1,2,3)",
			DumpChain(c.GetChain(), NewBlockSn(1, 2, 3)),
		)
		req.Equal(
			"(1,1,1)->(1,1,2)->(1,2,1)->(1,2,2)->(1,3,1)->(1,3,2)->(1,3,3)->(1,3,4)->(1,3,5)",
			DumpChain(c.GetChain(), NewBlockSn(1, 3, 5)),
		)
		req.Equal(NewBlockSn(1, 3, 2), c.GetChain().GetFreshestNotarizedHeadSn())
	})
}
