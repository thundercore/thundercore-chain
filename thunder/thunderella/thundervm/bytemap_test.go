package thundervm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	notInsertedKey = "not_inserted"
)

func getRandomTestMap(t *testing.T) map[string][]byte {
	return map[string][]byte{
		"short":    getRandomBytes(3, t),
		"zero":     {0},
		"no":       {},
		"full":     getRandomBytes(HashLength, t),
		"long":     getRandomBytes(50, t),
		"verylong": getRandomBytes(300, t),
		"veryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryverylongkey": []byte{0},
	}
}

func TestByteMap(t *testing.T) {
	t.Parallel()
	t.Run("InsertOrReplace", func(t *testing.T) {
		require := require.New(t)
		state := newTestStateDB(t)

		byteMap := NewByteMap(testAddress, state, prefix)

		key := "test"
		value := []byte{1, 2, 3, 4}

		inserted := byteMap.InsertOrReplace(key, value)
		require.True(inserted, "Expected insert %q: %v", key, value)

		newValue := []byte{1}
		inserted = byteMap.InsertOrReplace(key, newValue)
		require.False(inserted, "Expected replace %q to %v", key, newValue)

		b, exists := byteMap.Find(key)
		require.True(exists, "Expected key %q exists.", exists)
		require.Equal(b, newValue, "Expected value of key %q should be correct", key)

	})

	t.Run("Size", func(t *testing.T) {
		require := require.New(t)
		state := newTestStateDB(t)
		testMap := getRandomTestMap(t)

		byteMap := NewByteMap(testAddress, state, prefix)

		byteMap.Clear()
		expectedSize := int64(0)
		require.Equal(expectedSize, byteMap.Size())

		for k, v := range testMap {
			byteMap.InsertOrReplace(k, v)
			expectedSize++
			require.Equal(expectedSize, byteMap.Size(), "expect size increased after insertion.")
		}
	})

	t.Run("Find", func(t *testing.T) {
		require := require.New(t)
		state := newTestStateDB(t)
		testMap := getRandomTestMap(t)

		byteMap := NewByteMap(testAddress, state, prefix)

		byteMap.Clear()

		for k := range testMap {
			_, exists := byteMap.Find(k)
			require.False(exists, "expected to be empty.")
		}

		for k, v := range testMap {
			inserted := byteMap.InsertOrReplace(k, v)
			require.True(inserted, "map inserted new value %q failed.", k)
		}

		for k, v := range testMap {
			b, exists := byteMap.Find(k)
			require.True(exists, "expected key exists")
			require.Equal(b, v, "expected match the inserted value.")
		}

		keys := byteMap.Keys()

		require.Equal(len(keys), len(testMap), "expected number will match.")
		for _, key := range keys {
			_, ok := testMap[key]
			require.True(ok, "expected key %q exists in %v.", key, testMap)
		}

		_, exists := byteMap.Find(notInsertedKey)
		require.False(exists, "expected not found.")

		byteMap.Clear()

		keys = byteMap.Keys()
		require.Zero(len(keys), "expected no key after clear.")
	})
}
