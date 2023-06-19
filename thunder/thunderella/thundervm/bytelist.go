// bytelist is an implementation of a list inside of an EVM account storage
package thundervm

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
)

const HashLength = common.HashLength

// ByteList is a list implementation inside of statedb.
type ByteList struct {
	// account address where the ByteList resides
	account common.Address
	// statedb where data is stored
	statedb vm.StateDB

	// offset in the account storage where the ByteList resides
	// TODO change this to string and rename to prefix
	prefix []byte
}

// length is stored at sha256(prefix+lengthPrefix)
// size of entry i is stored at sha256(prefix+sizePrefix+i)
// jth 32 byte value of entry i is stored at sha256(prefix+sizePrefix+i*MaxInt64+j)
var (
	lengthPrefix = []byte{'l'}
	sizePrefix   = []byte{'s'}
	dataPrefix   = []byte{'d'}
)

// NewByteList creates a new ByteList at the given account and offset
// This will assume the structure of the data at the given offset is a ByteList.
// You'll in a lot of trouble if it's not.
func NewByteList(statedb vm.StateDB, account common.Address, prefix string) *ByteList {
	return &ByteList{
		account: account,
		statedb: statedb,
		prefix:  []byte(prefix),
	}
}

// hashesToBytes converts a hash slice to a byte slice
func hashesToBytes(hashes []common.Hash, sz int64) (r []byte) {
	r = make([]byte, sz)
	// now write the byte array itself
	for i := int64(0); i*HashLength < sz; i++ {
		endBytes := (i + 1) * HashLength
		if endBytes > sz {
			endBytes = sz
		}
		copy(r[i*HashLength:endBytes],
			hashes[i].Bytes()[0:endBytes-i*HashLength])
	}
	return
}

func (bl *ByteList) lengthLoc() common.Hash {
	return common.Hash(sha256.Sum256(append(bl.prefix, lengthPrefix...)))
}

func (bl *ByteList) entrySizeLoc(index int64) common.Hash {
	return common.Hash(sha256.Sum256(
		append(bl.prefix, append(sizePrefix, big.NewInt(index).Bytes()...)...)))
}

func (bl *ByteList) entryDataLoc(entryIndex int64, dataIndex int64) common.Hash {
	// using 32 bytes for both entryIndex and dataIndex irrespective of value ensures
	// (12, 3) != (1, 23)
	key := make([]byte, len(bl.prefix)+len(dataPrefix)+16)
	copy(key, bl.prefix)
	copy(key[len(bl.prefix):], dataPrefix)
	offset := len(bl.prefix) + len(dataPrefix)
	binary.LittleEndian.PutUint64(key[offset:], uint64(entryIndex))
	binary.LittleEndian.PutUint64(key[offset+8:], uint64(dataIndex))
	return common.Hash(sha256.Sum256(key))
}

// Length returns the length of the ByteList
func (bl *ByteList) Length() int64 {
	return bl.statedb.GetState(bl.account, bl.lengthLoc()).Big().Int64()
}

// byteSizeToHashSize converts byte length to number of 32 byte hashes it will take up
func byteSizeToHashSize(l int64) int64 {
	// ceiling( n/m ) = floor( n-1/m ) + 1
	return (l-1)/HashLength + 1
}

// ToSlice converts a StateDB ByteList to a []byte slice
// This function does no error checking on data formatting so be sure you only call it
// on valid ByteSlices.
// TODO maybe add some error checking and return with an error
func (bl *ByteList) ToSlice() (r [][]byte) {
	entries := bl.Length()

	r = make([][]byte, entries)

	for i := int64(0); i < entries; i++ {
		// length in bytes of the data
		l := bl.statedb.GetState(bl.account, bl.entrySizeLoc(i)).Big().Int64()
		n := byteSizeToHashSize(l)

		// read all hashes
		hashes := make([]common.Hash, n)
		for j := int64(0); j < n; j++ {
			hashes[j] = bl.statedb.GetState(bl.account,
				bl.entryDataLoc(i, j))
		}

		// convert the hashes to []byte
		r[i] = hashesToBytes(hashes, l)
	}
	return
}

// Append adds a byte slice to the ByteList
func (bl *ByteList) Append(val []byte) {
	sz := int64(len(val))

	// increase the total length of the list
	l := bl.Length()
	bl.statedb.SetState(bl.account,
		bl.lengthLoc(),
		common.BigToHash(big.NewInt(0).Add(big.NewInt(l), big.NewInt(1))))

	// write the size
	bl.statedb.SetState(bl.account,
		bl.entrySizeLoc(l),
		common.BigToHash(big.NewInt(sz)))

	// now write the byte array itself
	for i := int64(0); i*HashLength < sz; i++ {
		endBytes := i*HashLength + HashLength
		if endBytes > sz {
			endBytes = sz
		}
		writeme := make([]byte, HashLength)
		copy(writeme[0:endBytes-i*HashLength], val[i*HashLength:endBytes])
		bl.statedb.SetState(bl.account,
			bl.entryDataLoc(l, i),
			common.BytesToHash(writeme))
		//fmt.Println("wrote ", val[i*32:endBytes])
	}
}

// Clear clears the ByteList
func (bl *ByteList) Clear() {

	// clear all entries in statedb
	entries := bl.Length()
	for i := int64(0); i < entries; i++ {
		// cache the size and clear it
		l := bl.statedb.GetState(bl.account, bl.entrySizeLoc(i)).Big().Int64()
		bl.statedb.SetState(bl.account, bl.entrySizeLoc(i), common.Hash{})

		// clear the data
		n := byteSizeToHashSize(l)
		for j := int64(0); j < n; j++ {
			bl.statedb.SetState(bl.account, bl.entryDataLoc(i, j), common.Hash{})
		}
	}

	// Set the length of the list to 0
	bl.statedb.SetState(bl.account,
		bl.lengthLoc(),
		common.BigToHash(big.NewInt(0)))
}
