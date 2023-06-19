// bytemap is an implementation of a map inside of an EVM vault storage
package thundervm

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
)

// ByteMap is a map implementation in StateDB
// address --> <prefix>m<key>0 -> value len
// address --> <prefix>m<key><n> -> nth value
// address --> <prefix>keyXXX -> bytelist of keys
type ByteMap struct {
	account common.Address
	stateDB vm.StateDB
	prefix  []byte
	keyList *ByteList
}

var (
	mappingPrefix = []byte{'m'}
	keyPrefix     = "key"
)

// ByteSerializable make a struct can directly op with ByteMap
type ByteSerializable interface {
	ToBytes() []byte
	FromBytes([]byte) error
}

// NewByteMap create a map based on the prefix, share the same assumption of bytelist
// that is, the structure of data under the prefix is assumed to be ByteMap
func NewByteMap(account common.Address, stateDB vm.StateDB, prefix string) *ByteMap {
	extendedPrefix := prefix + keyPrefix
	return &ByteMap{
		account: account,
		stateDB: stateDB,
		prefix:  []byte(prefix),
		keyList: NewByteList(stateDB, account, extendedPrefix),
	}
}

func (bm *ByteMap) getValueLocationPrefix(key string) []byte {
	return append(bm.prefix, append(mappingPrefix, []byte(key)...)...)
}

func (bm *ByteMap) getValueLengthLocation(key string) common.Hash {
	return common.Hash(sha256.Sum256(append(bm.getValueLocationPrefix(key), big.NewInt(0).Bytes()...)))
}

func (bm *ByteMap) getValueLocation(key string, index int64) common.Hash {
	return common.Hash(sha256.Sum256(append(bm.getValueLocationPrefix(key), big.NewInt(index+1).Bytes()...)))
}

// Size returns number of key in the map
func (bm *ByteMap) Size() int64 {
	return bm.keyList.Length()
}

func (bm *ByteMap) setValueLength(key string, size int64) {
	if size > 0 {
		bm.stateDB.SetState(bm.account, bm.getValueLengthLocation(key), common.BigToHash(big.NewInt(size)))
	} else {
		// set length to 2^64, relying on big.IsInt64() to check the value
		empty := make([]byte, 9)
		empty[0] = 1
		bm.stateDB.SetState(bm.account, bm.getValueLengthLocation(key), common.BytesToHash(empty))
	}
}

// InsertOrReplace inserts a key-value pair into ByteMap. If it already contains the key, replace it.
func (bm *ByteMap) InsertOrReplace(key string, value []byte) bool {
	needLength := int64(len(value))
	needSize := byteSizeToHashSize(needLength)
	inserted := false

	currentHash := bm.stateDB.GetState(bm.account, bm.getValueLengthLocation(key))
	if currentHash == (common.Hash{}) {
		bm.keyList.Append([]byte(key))
		inserted = true
	} else {
		length := int64(0)
		if b := currentHash.Big(); b.IsInt64() {
			length = b.Int64()
		}
		currentSize := byteSizeToHashSize(length)

		// truncate data
		if needSize < currentSize {
			for i := needSize; i < currentSize; i++ {
				bm.stateDB.SetState(bm.account, bm.getValueLocation(key, i), common.Hash{})
			}
		}
	}

	bm.setValueLength(key, needLength)

	for i := int64(0); i < needSize; i++ {
		headByte := i * HashLength
		tailByte := headByte + HashLength
		if tailByte > needLength {
			tailByte = needLength
		}
		byteToWrite := make([]byte, HashLength)
		copy(byteToWrite[:tailByte-headByte], value[headByte:tailByte])

		bm.stateDB.SetState(bm.account, bm.getValueLocation(key, i), common.BytesToHash(byteToWrite))
	}

	return inserted
}

// Find finds value with specify key.
func (bm *ByteMap) Find(key string) ([]byte, bool) {
	currentHash := bm.stateDB.GetState(bm.account, bm.getValueLengthLocation(key))

	if currentHash == (common.Hash{}) {
		return nil, false
	}

	length := currentHash.Big().Int64()
	n := byteSizeToHashSize(length)

	output := make([]byte, length)
	for i := int64(0); i < n; i++ {
		headByte := i * HashLength
		tailByte := headByte + HashLength
		if tailByte > length {
			tailByte = length
		}
		hash := bm.stateDB.GetState(bm.account, bm.getValueLocation(key, i))
		copy(output[headByte:tailByte], hash.Bytes()[:tailByte-headByte])
	}

	return output, true
}

// Clear clears the contents.
func (bm *ByteMap) Clear() {
	keys := bm.Keys()

	for _, key := range keys {
		length := bm.stateDB.GetState(bm.account, bm.getValueLengthLocation(key)).Big().Int64()
		bm.stateDB.SetState(bm.account, bm.getValueLengthLocation(key), common.Hash{})

		n := byteSizeToHashSize(length)

		for i := int64(0); i < n; i++ {
			bm.stateDB.SetState(bm.account, bm.getValueLocation(key, i), common.Hash{})
		}
	}

	bm.keyList.Clear()
}

// Keys returns keys in the container.
func (bm *ByteMap) Keys() []string {
	keyBytes := bm.keyList.ToSlice()
	keys := make([]string, len(keyBytes))

	for i := range keys {
		keys[i] = string(keyBytes[i])
	}

	return keys
}

// InsertOrReplaceEntry insert a key-entry pair. If the key exists, replace it.
func (bm *ByteMap) InsertOrReplaceEntry(key string, entry ByteSerializable) bool {
	return bm.InsertOrReplace(key, entry.ToBytes())
}

var ErrNotExist = fmt.Errorf("cannot find entry")

// FindEntry find an entry from key in, retruns ErrNotExist if entry does not exist in map
func (bm *ByteMap) FindEntry(key string, entry ByteSerializable) error {
	rawdata, exists := bm.Find(key)
	if !exists {
		return ErrNotExist
	}

	return entry.FromBytes(rawdata)
}

// byteLengthToHashLength returns the min number of 32-bytes hashes that can take up the length of bytes
// and also cast the type to uint64 for gas calculation.
func byteLengthToHashLength(inBytes int) uint64 {
	return uint64(byteSizeToHashSize(int64(inBytes)))
}

// gasByteMapFind calculates the gas we need when finding an entry from ByteMap
// we do sha256 for every time before we GetState
func gasByteMapFind(keyLengthInBytes, valueLengthInBytes int) uint64 {
	gasEachStateDBEntry := byteLengthToHashLength(keyLengthInBytes)*params.Sha256PerWordGas + params.SloadGas
	return byteLengthToHashLength(valueLengthInBytes) * gasEachStateDBEntry
}

// gasByteMapReplace calculates the gas we need when inserting an entry into ByteMap
// we do sha256 for every time before we SetState
func gasByteMapReplace(keyLengthInBytes, valueLengthInBytes int) uint64 {
	gasEachStateDBEntry := byteLengthToHashLength(keyLengthInBytes)*params.Sha256PerWordGas + params.SstoreResetGas
	return byteLengthToHashLength(valueLengthInBytes) * gasEachStateDBEntry
}

// gasByteMapInsert calculates the gas we need when create an entry into ByteMap
// we do sha256 for every time before we SetState
func gasByteMapInsert(keyLengthInBytes, valueLengthInBytes int) uint64 {
	gasEachStateDBEntry := byteLengthToHashLength(keyLengthInBytes)*params.Sha256PerWordGas + params.SstoreSetGas
	return byteLengthToHashLength(valueLengthInBytes) * gasEachStateDBEntry
}
