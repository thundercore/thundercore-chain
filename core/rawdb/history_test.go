package rawdb

// thunder_patch begin
import (
	"testing"

	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/stretchr/testify/assert"
)

func TestHistoryBasicTest(t *testing.T) {
	t.Parallel()
	historyDB1 := memorydb.New()
	historyDB2 := memorydb.New()
	historyStore := &history{
		dbList: []ethdb.KeyValueStore{historyDB1, historyDB2},
	}
	defer historyStore.Close()
	var cases = []struct {
		key   string
		value string
		db    *memorydb.Database
	}{
		{"a", "a-value", historyDB1},
		{"b", "b-value", historyDB2},
		{"c", "c-value", historyDB1},
		{"d", "d-value", historyDB2},
	}

	for _, c := range cases {
		// check data is not exist before data inserted
		isExist, err := historyStore.HistoryHas([]byte(c.key))
		assert.Equal(t, false, isExist)
		assert.NoError(t, err)
		// get error when the data key is not exist.
		_, err = historyStore.HistoryGet([]byte(c.key))
		assert.Equal(t, errDataNotFound, err)

		// insert data
		c.db.Put([]byte(c.key), []byte(c.value))

		// check the data can be retrieved by the given key.
		isExist, err = historyStore.HistoryHas([]byte(c.key))
		assert.Equal(t, true, isExist)
		assert.NoError(t, err)
		value, err := historyStore.HistoryGet([]byte(c.key))
		assert.NoError(t, err)
		assert.Equal(t, []byte(c.value), value, "The values should be the same.")
	}
}

// thunder_patch end
