package blockchain

import (
	"testing"

	"github.com/petar/GoLLRB/llrb"
	"github.com/stretchr/testify/require"
)

type testItem struct {
	sn    BlockSn
	value string
}

func (i *testItem) Less(other llrb.Item) bool {
	return i.sn.Compare(other.(BlockSnGetter).GetBlockSn()) < 0
}

func (i *testItem) GetBlockSn() BlockSn {
	return i.sn
}

func TestUsingLLRB(t *testing.T) {
	data := []testItem{
		testItem{NewBlockSn(1, 3, 1), "3-1"},
		testItem{NewBlockSn(1, 5, 1), "5-1"},
		testItem{NewBlockSn(1, 1, 1), "1-1"},
		testItem{NewBlockSn(1, 4, 1), "4-1"},
		testItem{NewBlockSn(1, 2, 1), "2-1"},
	}
	expected := []testItem{
		testItem{NewBlockSn(1, 1, 1), "1-1"},
		testItem{NewBlockSn(1, 2, 1), "2-1"},
		testItem{NewBlockSn(1, 3, 1), "3-1"},
		testItem{NewBlockSn(1, 4, 1), "4-1"},
		testItem{NewBlockSn(1, 5, 1), "5-1"},
	}

	t.Run("iterator", func(t *testing.T) {
		req := require.New(t)

		tree := llrb.New()
		for i := range data {
			tree.ReplaceOrInsert(&data[i])
		}

		req.Equal(len(data), tree.Len())

		i := 0
		tree.AscendGreaterOrEqual(tree.Min(), func(actual llrb.Item) bool {
			req.Equal(expected[i], *actual.(*testItem))
			i++
			return true
		})
	})

	t.Run("get", func(t *testing.T) {
		req := require.New(t)

		tree := llrb.New()
		for i := range data {
			tree.ReplaceOrInsert(&data[i])
		}

		req.Equal(len(data), tree.Len())

		// Use the same type as the key with an empty value.
		for i := 0; i < len(data); i++ {
			key := testItem{expected[i].sn, ""}
			req.Equal(expected[i], *tree.Get(&key).(*testItem))
		}

		// Use BlockSnGetter.
		for i := 0; i < len(data); i++ {
			req.Equal(expected[i], *tree.Get(expected[i].sn).(*testItem))
		}
	})

	t.Run("delete min", func(t *testing.T) {
		req := require.New(t)

		tree := llrb.New()
		for i := range data {
			tree.ReplaceOrInsert(&data[i])
		}

		req.Equal(len(data), tree.Len())

		for i := 0; i < len(data); i++ {
			min := tree.Min()
			req.Equal(expected[i], *min.(*testItem))
			tmp := tree.DeleteMin()
			req.Equal(min, tmp)
		}
	})
}
