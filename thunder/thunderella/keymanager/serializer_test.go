package keymanager

import (
	// Standard imports
	"testing"

	// Vendor imports
	"github.com/stretchr/testify/assert"
)

func TestAppendMultiple(t *testing.T) {
	assert := assert.New(t)

	a1 := []byte{1, 2, 3}
	a2 := []byte{4, 5}
	a3 := []byte{6, 7, 8, 9}
	a4 := []byte{}

	a5 := appendMultiple(a1, a2, a3, a4)
	assert.Equal(a5, []byte{3, 0, 0, 0, 1, 2, 3,
		2, 0, 0, 0, 4, 5,
		4, 0, 0, 0, 6, 7, 8, 9,
		0, 0, 0, 0},
		"append multiple failed")
}

func TestUint32BytesConversion(t *testing.T) {
	assert := assert.New(t)

	x := uint32(42)
	bytes := uint32ToBytes(x)
	reversedX := bytesToUint32(bytes)
	assert.Equal(x, reversedX, "uint32 <-> bytes round trip conversion failed")
}

func TestUint64BytesConversion(t *testing.T) {
	assert := assert.New(t)

	x := uint64(18446744073709551613)
	bytes := uint64ToBytes(x)
	reversedX := bytesToUint64(bytes)
	assert.Equal(x, reversedX, "uint64 <-> bytes round trip conversion failed")
}
