package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/server"
	palaTypes "github.com/ethereum/go-ethereum/thunder/pala/types"

	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chainconfig"
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/election"

	"github.com/ethereum/go-ethereum/common"
	flag "github.com/spf13/pflag"
	"golang.org/x/xerrors"
)

const (
	clientIdentifier = "thunder" // copied from server/builder.go
)

var (
	palaHardfork = config.NewBoolHardforkConfig(
		"pala.hardfork",
		"The number of block we start run with pala protocol.",
	)
)

type stakeinKeys struct {
	NumKey       int      `json:"NumKey"`
	Type         string   `json:"Type"`
	PublicKeys   []string `json:"PublicKeys"`
	Addresses    []string `json:"Addresses"`
	Certificates []string `json:"Certificates"`
}

func loadStakeinAddrs(path string) ([]common.Address, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var keys stakeinKeys
	if err = json.Unmarshal(data, &keys); err != nil {
		return nil, err
	}

	var addrs []common.Address
	for _, h := range keys.Addresses {
		addrs = append(addrs, common.HexToAddress(h))
	}
	return addrs, nil
}

func failWithErr(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func dumpElectionResult(header string, er *election.Result) {
	fmt.Printf("\n%s:\n", header)
	for _, m := range er.Members {
		id := palaTypes.ConsensusIdFromPubKey(m.PubVoteKey)
		fmt.Printf("%s: {\n%s\n}\n\n", id, m.String())
	}
	fmt.Println("")
}

func commInfoFromJsonBytes(data []byte) (*committee.CommInfo, error) {
	ci := &committee.CommInfo{}
	if err := ci.FromJSON(data); err != nil {
		return nil, xerrors.Errorf("failed to decode CommInfo: %s", err)
	}
	return ci, nil
}

func getNewElectionResult(genesisCommInfoPath string) (*committee.CommInfo, *election.Result, error) {
	data, err := ioutil.ReadFile(genesisCommInfoPath)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to read %q: %s", genesisCommInfoPath, err)
	}
	ci, err := commInfoFromJsonBytes(data)
	if err != nil {
		return nil, nil, err
	}
	return ci, &election.Result{
		Members:          ci.MemberInfo,
		ClearingGasPrice: ci.ClearingGasPrice(),
	}, nil
}

func programName() string {
	return filepath.Base(os.Args[0])
}

func printUsageExit() {
	fmt.Fprintf(os.Stderr, "usage: %s [OPTIONS] DATA_DIR COMM_INFO.JSON STAKEIN_KEYS.JSON\n", programName())
	fmt.Fprintf(os.Stderr, "\tCOMM_INFO.JSON: the public proposing and voting BLS keys of the Committee\n")
	fmt.Fprintf(os.Stderr, "\tSTAKEIN_KEYS.JSON: the Ethereum addresses and hash of public voting keys of the Committee\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "OPTIONS:\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	flag.Usage = printUsageExit
	flag.Parse()

	args := flag.Args()
	if len(args) != 3 {
		printUsageExit()
	}
	dataDir := args[0]
	commInfoPath := args[1]
	stakeinFile := args[2]

	fmt.Println("Setup chain db")
	// BlockGasLimit is required.
	config.SetHardfork(config.RequiredSettings{
		BlockGasLimit: server.ScientificBigIntParse("1e+8").Int64(),
	}, nil /* BlockNumSetting */, nil /* SessionSettings */)
	chainconfig.SetChainId(chainconfig.MainnetChainID) // doesn't matter
	ethChain, db, err := server.GetBlockChainAndDb(dataDir)
	if err != nil {
		failWithErr(xerrors.Errorf("Failed to start node: %s", err))
	}

	stakeInAddrs, err := loadStakeinAddrs(stakeinFile)
	if err != nil {
		failWithErr(err)
	}
	newCommInfo, newEr, err := getNewElectionResult(commInfoPath)
	if err != nil {
		failWithErr(fmt.Errorf("Failed to load election result: %s", err))
	}
	logger := func(s string) (n int, err error) {
		return fmt.Printf("%s", s)
	}
	oldEr, err := blockchain.ReplaceCommitteeForTest(
		ethChain, db, stakeInAddrs, newCommInfo, newEr, logger)
	if err != nil {
		failWithErr(fmt.Errorf("Failed to replace committee: %s", err))
	}

	fmt.Println("")
	dumpElectionResult("Original election result", oldEr)
	fmt.Println("")
	dumpElectionResult("New election result", newEr)
}
