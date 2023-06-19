package rawdb

// thunder_patch begin
import (
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/ethdb/leveldb"
	"github.com/ethereum/go-ethereum/log"
)

var (
	// errReadOnly is returned if the history store is opened in read only mode. All the
	// mutations are disallowed.
	errOnlySupportReadOnly = errors.New("history db only support readonly mode")

	// errDataNotFound is returned if the quering data is not found. It aligns leveldb behavior
	errDataNotFound = errors.New("historydb: not found")
)

// histroy is an leveldb history database to store cold immutable chain data
//
// - search cold immutable data. Such as state which is pruned by snapshot.
type history struct {
	dbList []ethdb.KeyValueStore
}

// newReadonlyDefaultHistory open history chain databases to make chain query old blocks or old transactions.
//
// - Use lexicographical order as history query order
// - Naming database must be careful.
//   Bad Case: chaindata.1, chaindata.11, chaindata.2 ...
//   Good Case: chaindata.01, chaindata.02, ... chaindata.11
func newReadonlyDefaultHistory(rootDir, dataDir string, cache int, handles int, namespace string) (*history, error) {
	history := &history{}
	// get all its directory entries sorted by filename
	files, err := ioutil.ReadDir(rootDir)
	if err != nil {
		return nil, err
	}

	// use lexicographical order as history query order if history config is not set value
	prefixMatch := dataDir + "."
	for _, file := range files {
		// only consider chaindata.1, chaindata.2, chaindata.3...
		// we do not open chaindata db, because it is live database not immutable database.
		if strings.HasPrefix(file.Name(), prefixMatch) != true || file.IsDir() != true {
			continue
		}
		historyNamespace := namespace + "history/" + file.Name() + "/"
		// Readonly levelDB
		db, err := leveldb.New(filepath.Join(rootDir, file.Name()), cache, handles, historyNamespace, true)
		if err != nil {
			return nil, err
		}
		history.dbList = append(history.dbList, db)
		log.Info("Opened history database", "database", file.Name(), "readonly")
	}
	return history, nil
}

// newReadonlyOrderListHistory open history chain databases to make chain query old blocks or old transactions.
//
// - Use config order as history query order
func newReadonlyOrderListHistory(rootDir, orderList string, cache int, handles int, namespace string) (*history, error) {
	history := &history{}

	dirList := strings.Split(orderList, ",")
	for _, dirName := range dirList {
		historyNamespace := namespace + "history/" + dirName + "/"
		// Readonly levelDB
		db, err := leveldb.New(filepath.Join(rootDir, dirName), cache, handles, historyNamespace, true)
		if err != nil {
			return nil, err
		}
		history.dbList = append(history.dbList, db)
		log.Info("Opened history database", "database", dirName, "readonly")
	}
	return history, nil
}

// Close terminates all history leveldb
func (h *history) Close() error {
	var errs []error
	for idx, db := range h.dbList {
		if err := db.Close(); err != nil {
			log.Error("History store close failed: db-index[%d], err[%v]", idx, err)
			errs = append(errs, err)
		} else {
			log.Info("History store close successfully: db-index[%d]", idx)
		}
	}

	if len(errs) != 0 {
		return fmt.Errorf("%v", errs)
	}
	return nil
}

// HistoryHas retrieves if a key is present in the history stores.
func (h *history) HistoryHas(key []byte) (bool, error) {
	for idx, db := range h.dbList {
		hasData, err := db.Has(key)
		if err != nil {
			return false, fmt.Errorf("HistoryHas retrieves failed: db-index[%d], err[%v]", idx, err)
		}
		if hasData == true {
			return hasData, nil
		}
	}
	return false, nil
}

// HistoryGet retrieves the given key if it's present in the history stores.
func (h *history) HistoryGet(key []byte) ([]byte, error) {
	for _, db := range h.dbList {
		data, _ := db.Get(key)
		if len(data) != 0 {
			return data, nil
		}
	}
	return nil, errDataNotFound
}

// thunder_patch end
