package main

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/server"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"

	"golang.org/x/xerrors"
)

const (
	timePerBlock = 1 * time.Second
)

func programName() string {
	return filepath.Base(os.Args[0])
}

func printUsageExit() {
	fmt.Fprintf(os.Stderr, "usage: %s (NUMBER | DATA-DIR) DURATION, e.g.\n       %s 15017360 15m\n",
		programName(), programName())
	os.Exit(2)
}

func exitWithError(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func lastBlockFromDataDir(dataDir string) (*big.Int, error) {
	ethChain, _, err := server.GetBlockChainAndDb(dataDir)
	if err != nil {
		return nil, err
	}

	h := ethChain.CurrentHeader()
	return h.Number, nil
}

func durationToBlocks(d time.Duration) *big.Int {
	return new(big.Int).SetInt64(int64(d / timePerBlock))
}

func main() {
	// Not using the `flags` module since some code we import introduces:
	//  -httptest.serve string
	//     	if non-empty, httptest.NewServer serves on this address and blocks
	args := os.Args[1:]
	if len(args) != 2 {
		printUsageExit()
	}
	err := server.SetupLogging(server.StderrLogOutputMode, "", "")
	if err != nil {
		exitWithError(err)
	}

	startArg := args[0]
	var blockNum *big.Int
	if fInfo, err := os.Stat(startArg); err == nil {
		if fInfo.IsDir() {
			config.SetHardfork(config.RequiredSettings{
				BlockGasLimit: server.ScientificBigIntParse("1e+8").Int64(),
			}, nil, nil /* SessionSettings */)
			blockNum, err = lastBlockFromDataDir(startArg)
			if err != nil {
				exitWithError(xerrors.Errorf("Failed to read block number from datadir %q: %s", startArg, err))
			}
			// fall-through
		} else {
			exitWithError(xerrors.Errorf("Datadir argument %q is not a directory", startArg))
		}
	} else {
		var ok bool
		blockNum, ok = new(big.Int).SetString(startArg, 0 /*base*/)
		if !ok {
			exitWithError(xerrors.Errorf("Invalid number %q", startArg))
		}
	}

	durationArg := args[1]
	duration, err := time.ParseDuration(durationArg)
	if err != nil {
		exitWithError(xerrors.Errorf("Invalid duration %q: %s", durationArg, err))
	}
	// NOTE: don't modify blockNum, it's read from blockchain.CurrentHeader and is
	// a potential data race
	n := durationToBlocks(duration)
	n.Add(n, blockNum)
	fmt.Printf("%d\n", n)
}
