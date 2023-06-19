package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/thunder/pala/server"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"golang.org/x/xerrors"
)

func programName() string {
	return filepath.Base(os.Args[0])
}

func printUsageExit() {
	fmt.Fprintf(os.Stderr, "usage: %s DATA-DIR, e.g.\n       %s $PWD/datadir\n",
		programName(), programName())
	os.Exit(2)
}

func exitWithError(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func getDb(dataDir string) (ethdb.Database, error) {
	fInfo, err := os.Stat(dataDir)
	if err != nil {
		return nil, xerrors.Errorf("Failed to stat dataDir %s: %s", dataDir, err)
	}
	if !fInfo.IsDir() {
		return nil, xerrors.Errorf("dataDir %s is not a folder", dataDir)
	}

	config.SetHardfork(config.RequiredSettings{
		BlockGasLimit: server.ScientificBigIntParse("1e+8").Int64(),
	}, nil, nil /* SessionSettings */)
	_, db, err := server.GetBlockChainAndDb(dataDir)
	if err != nil {
		return nil, xerrors.Errorf("Failed to load db: %s", err)
	}
	return db, nil
}

func dumpChainIndexer(db ethdb.Database) {
	validSectionsKey := func() []byte { return []byte("count") }
	sectionHeadKey := func(section uint64) []byte {
		var data [8]byte
		binary.BigEndian.PutUint64(data[:], section)
		return append([]byte("shead"), data[:]...)
	}

	bloomTable := rawdb.NewTable(db, string(rawdb.BloomBitsIndexPrefix))

	var (
		key           []byte
		validSections uint64
	)
	key = validSectionsKey()
	bytes, err := bloomTable.Get(key)
	if err != nil {
		fmt.Printf("db.Get() failed with key %s: %s\n", key, err)
		return
	}

	validSections = binary.BigEndian.Uint64(bytes)
	fmt.Printf("validSections: %d\n", validSections)

	for i := uint64(0); i < validSections; i++ {
		key := sectionHeadKey(i)
		bytes, err = bloomTable.Get(key)
		if err != nil {
			fmt.Printf("db.Get() failed with key %s: %s\n", key, err)
		} else {
			fmt.Printf("sectionHead(%d): %s\n", i, common.BytesToHash(bytes).String())
		}
	}
}

func main() {
	// Not using the `flags` module since some code we import introduces:
	//  -httptest.serve string
	//     	if non-empty, httptest.NewServer serves on this address and blocks
	args := os.Args[1:]
	if len(args) != 1 {
		printUsageExit()
	}
	err := server.SetupLogging(server.StderrLogOutputMode, "", "")
	if err != nil {
		exitWithError(err)
	}

	db, err := getDb(args[0])
	if err != nil {
		exitWithError(err)
	}

	dumpChainIndexer(db)
}
