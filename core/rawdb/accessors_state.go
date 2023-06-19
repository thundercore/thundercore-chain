// Copyright 2020 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package rawdb

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
)

// ReadPreimage retrieves a single preimage of the provided hash.
// thunder_patch begin
func ReadPreimage(db ethdb.Reader, hash common.Hash) []byte {
	// thunder_patch original
	// func ReadPreimage(db ethdb.KeyValueReader, hash common.Hash) []byte {
	// thunder_patch end
	data, _ := db.Get(preimageKey(hash))
	// thunder_patch begin
	if len(data) == 0 {
		// Then try to look up the history data in the history store.
		data, _ = db.HistoryGet(preimageKey(hash))
	}
	// thunder_patch end
	return data
}

// WritePreimages writes the provided set of preimages to the database.
func WritePreimages(db ethdb.KeyValueWriter, preimages map[common.Hash][]byte) {
	for hash, preimage := range preimages {
		if err := db.Put(preimageKey(hash), preimage); err != nil {
			log.Crit("Failed to store trie preimage", "err", err)
		}
	}
	preimageCounter.Inc(int64(len(preimages)))
	preimageHitCounter.Inc(int64(len(preimages)))
}

// ReadCode retrieves the contract code of the provided code hash.
// thunder_patch begin
func ReadCode(db ethdb.Reader, hash common.Hash) []byte {
	// thunder_patch original
	// func ReadCode(db ethdb.KeyValuReader, hash common.Hash) []byte {
	// thunder_patch end

	// Try with the legacy code scheme first, if not then try with current
	// scheme. Since most of the code will be found with legacy scheme.
	//
	// todo(rjl493456442) change the order when we forcibly upgrade the code
	// scheme with snapshot.
	data, _ := db.Get(hash[:])
	// thunder_patch begin
	if len(data) == 0 {
		// Then try to look up the history data in the history store.
		data, _ = db.HistoryGet(hash[:])
	}
	// thunder_patch end
	if len(data) != 0 {
		return data
	}
	return ReadCodeWithPrefix(db, hash)
}

// ReadCodeWithPrefix retrieves the contract code of the provided code hash.
// The main difference between this function and ReadCode is this function
// will only check the existence with latest scheme(with prefix).
// thunder_patch begin
func ReadCodeWithPrefix(db ethdb.Reader, hash common.Hash) []byte {
	// thunder_patch original
	// func ReadCodeWithPrefix(db ethdb.KeyValueReader, hash common.Hash) []byte {
	// thunder_patch end
	data, _ := db.Get(codeKey(hash))
	// thunder_patch begin
	if len(data) == 0 {
		// Then try to look up the history data in the history store.
		data, _ = db.Get(codeKey(hash))
	}
	// thunder_patch end
	return data
}

// WriteCode writes the provided contract code database.
func WriteCode(db ethdb.KeyValueWriter, hash common.Hash, code []byte) {
	if err := db.Put(codeKey(hash), code); err != nil {
		log.Crit("Failed to store contract code", "err", err)
	}
}

// DeleteCode deletes the specified contract code from the database.
func DeleteCode(db ethdb.KeyValueWriter, hash common.Hash) {
	if err := db.Delete(codeKey(hash)); err != nil {
		log.Crit("Failed to delete contract code", "err", err)
	}
}

// ReadTrieNode retrieves the trie node of the provided hash.
// thunder_patch begin
func ReadTrieNode(db ethdb.Reader, hash common.Hash) []byte {
	// thunder_patch original
	// func ReadTrieNode(db ethdb.KeyValueReader, hash common.Hash) []byte {
	// thunder_patch end

	data, _ := db.Get(hash.Bytes())
	// thunder_patch begin
	if len(data) == 0 {
		// Then try to look up the history data in the history store.
		data, _ = db.HistoryGet(hash.Bytes())
	}
	// thunder_patch end
	return data
}

// WriteTrieNode writes the provided trie node database.
func WriteTrieNode(db ethdb.KeyValueWriter, hash common.Hash, node []byte) {
	if err := db.Put(hash.Bytes(), node); err != nil {
		log.Crit("Failed to store trie node", "err", err)
	}
}

// DeleteTrieNode deletes the specified trie node from the database.
func DeleteTrieNode(db ethdb.KeyValueWriter, hash common.Hash) {
	if err := db.Delete(hash.Bytes()); err != nil {
		log.Crit("Failed to delete trie node", "err", err)
	}
}
