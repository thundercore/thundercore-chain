package blockchain

import (
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/petar/GoLLRB/llrb"
)

type tracerCacheItem struct {
	blockNumber uint64
	transfers   []TtTransferWithHash
	hash        common.Hash
}

func (i *tracerCacheItem) Less(item llrb.Item) bool {
	return i.blockNumber < item.(*tracerCacheItem).blockNumber
}

func getItem(item llrb.Item) *tracerCacheItem {
	return item.(*tracerCacheItem)
}

type tracerCache struct {
	tree *llrb.LLRB
	cap  int64
	mu   *sync.Mutex
}

func newTracerCache(cap int64) *tracerCache {
	return &tracerCache{
		cap:  cap,
		tree: llrb.New(),
		mu:   &sync.Mutex{},
	}
}

func (t *tracerCache) evict() {
	t.tree.DeleteMin()
}

func (t *tracerCache) put(n uint64, hash common.Hash, tx []TtTransferWithHash) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.tree.ReplaceOrInsert(&tracerCacheItem{
		blockNumber: n,
		hash:        hash,
		transfers:   tx,
	})

	for int64(t.tree.Len()) > t.cap {
		t.evict()
	}
}

func (t *tracerCache) get(n uint64, hash common.Hash) ([]TtTransferWithHash, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := &tracerCacheItem{
		blockNumber: n,
	}

	if t.tree.Has(key) {
		cached := getItem(t.tree.Get(key))
		if cached.hash != hash {
			logger.Warn("Get number %d, hash mistmatched, cached(%s) want (%s)", n, cached.hash.Hex(), hash.Hex())
			t.tree.Delete(cached)
			return nil, ErrBlockNotFound
		} else {
			return cached.transfers, nil
		}
	}

	return nil, ErrBlockNotFound
}
