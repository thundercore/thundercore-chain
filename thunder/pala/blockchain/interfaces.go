package blockchain

import "github.com/ethereum/go-ethereum/ethdb"

// DatabaseReader wraps the Has and Get method of a backing data store.
type DatabaseReader interface {
	ethdb.KeyValueReader
	ethdb.AncientReader
	ethdb.HistoryReader
}

// DatabaseWriter wraps the Put method of a backing data store.
type DatabaseWriter interface {
	Put(key []byte, value []byte) error
}

// DatabaseDeleter wraps the Delete method of a backing data store.
type DatabaseDeleter interface {
	Delete(key []byte) error
}
