// This tests thunder stuff in "github.com/ethereum/go-ethereum/core/vm"
// This needs to be here becaues it depends on state.StateDB to test stuff in vm module
package thundervm

import (
	"math/rand"
	"testing"

	// Vendor imports
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/stretchr/testify/assert"
)

var (
	testAddress = common.Address{}
	prefix      = "aoneuthaonsetuhos"
)

func newTestStateDB(t *testing.T) vm.StateDB {
	db := rawdb.NewMemoryDatabase()
	state, err := state.New(common.Hash{}, state.NewDatabase(db), nil)
	if err != nil {
		t.Fatal("Cannot create testing state db.")
	}

	return state
}

func getRandomBytes(len int, t *testing.T) []byte {
	bytes := make([]byte, 0, len)
	_, err := rand.Read(bytes)
	assert.NoError(t, err)
	return bytes
}

func setupTestData(t *testing.T) [][]byte {
	return [][]byte{
		getRandomBytes(3, t),          // small slice
		[]byte{0},                     // zero value
		[]byte{},                      // empty byte array
		getRandomBytes(HashLength, t), // bytes32
		getRandomBytes(40, t),         // longish slice
		getRandomBytes(300, t),        // very long slice
	}
}

// TestStateDB tests some assumptino we are making about state db
func TestStateDB(t *testing.T) {
	assert := assert.New(t)

	// Create an empty state database
	state := newTestStateDB(t)

	// empty key test
	assert.Equal(common.Hash{}, state.GetState(testAddress, common.Hash{}),
		"expected value of non-existing key to by 0")

	// basic set/get test
	val := common.BytesToHash([]byte{1, 2, 3})
	state.SetState(testAddress, common.Hash{}, val)
	assert.Equal(val, state.GetState(testAddress, common.Hash{}), "unexpected value")
}

func TestByteList(t *testing.T) {
	assert := assert.New(t)

	// Create an empty state database
	state := newTestStateDB(t)
	allVals := setupTestData(t)

	// create an empty bytelist
	bl := NewByteList(state, testAddress, prefix)
	assert.Equal(int64(0), bl.Length(), "expected 0 length")

	// add stuff to it
	for _, v := range allVals {
		bl.Append(v)
	}

	// verify it
	assert.Equal(int64(len(allVals)), bl.Length(), "unexpected length")
	vals := bl.ToSlice()
	for i, v := range allVals {
		assert.Equal(v, vals[i], "expected to be the same")
	}

	// create a new byte array in the same location
	bl2 := NewByteList(state, testAddress, prefix)

	// verify it
	assert.Equal(int64(len(allVals)), bl2.Length(), "unexpected length")
	vals = bl.ToSlice()
	for i, v := range allVals {
		assert.Equal(v, vals[i], "expected to be the same")
	}

	// add something to it
	someValue := make([]byte, 50)
	_, err := rand.Read(someValue)
	assert.NoError(err)
	bl2.Append(someValue)

	// verify it again
	assert.Equal(int64(len(allVals)+1), bl2.Length(), "unexpected length")
	vals = bl.ToSlice()
	for i, v := range allVals {
		assert.Equal(v, vals[i], "expected to be the same")
	}
	assert.Equal(someValue, vals[len(allVals)])

	// clear the byte array
	bl.Clear()

	// check that it has no values
	assert.Equal(int64(0), bl.Length(), "expected 0 length")
	assert.Equal([][]byte{}, bl.ToSlice(), "expected no values")

	// check that the copy has no values too
	// N.B. because of caching, bl2.Append will be broken
	assert.Equal(int64(0), bl2.Length(), "expected 0 length")
	assert.Equal([][]byte{}, bl2.ToSlice(), "expected no values")

	// now add a bunch of random values to it
	numRand := 500
	randVals := make([][]byte, numRand)
	for i := 0; i < numRand; i++ {
		l := rand.Int31n(2000)
		randVals[i] = make([]byte, l)
		bl.Append(randVals[i])
	}

	// verify it
	assert.Equal(int64(len(randVals)), bl.Length(), "unexpected length")
	vals = bl.ToSlice()
	for i, v := range randVals {
		assert.Equal(v, vals[i], "expected to be the same")
	}
}

func TestEntryDataLoc(t *testing.T) {
	bl := NewByteList(nil, testAddress, prefix)
	// Test that 0 is not ignored when hashing
	assert.NotEqual(t, bl.entryDataLoc(0, 2), bl.entryDataLoc(2, 0))
	assert.NotEqual(t, bl.entryDataLoc(0, 25), bl.entryDataLoc(2, 5))
	assert.NotEqual(t, bl.entryDataLoc(11, 0), bl.entryDataLoc(1, 1))
	// Using non-zero index
	assert.NotEqual(t, bl.entryDataLoc(1, 23), bl.entryDataLoc(12, 3))
}
