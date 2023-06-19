package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/thunder/pala/testutils"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/commitsha1"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

const genesisFileName = "genesis.json"

var (
	configPath          string
	additionalAllocFile string
	genesisFile         string
	printVersion        bool
)

type allocDataJson struct {
	Expenses []accountJson `json:"balances"`
}

type accountJson struct {
	Address string `json:"address"`
	Value   string `json:"value"`
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "generategenesis",
		Short: "generate genesis config",
		RunE: func(cmd *cobra.Command, args []string) error {
			return generateGenesis(configPath, additionalAllocFile, genesisFile)
		},
	}
	rootCmd.Flags().StringVarP(&additionalAllocFile, "allocFile", "a", "",
		"Json file containing additional account balance")
	rootCmd.Flags().StringVarP(&genesisFile, "genesisFile", "g", "genesis.json",
		"File path to write genesis config")
	rootCmd.Flags().StringVarP(&configPath, "configPath", "c", "config",
		"Configuration file(s) path")
	rootCmd.Flags().BoolVar(&printVersion, "version", false, "Print the version and exit")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generateGenesis(configPath, additionalAllocFile, genesisFile string) error {
	if printVersion {
		fmt.Println(commitsha1.CommitSha1)
		return nil
	}

	// mainly for the hardfork.yaml because protocol.BlockGasLimit is referenced
	config.InitThunderConfig(configPath)
	genesis := core.DefaultThunderGenesisBlock()

	err := populateAccounts(genesis, additionalAllocFile)
	if err != nil {
		return errors.Errorf("Failed to populate accounts: %s", err)
	}

	b, err := json.MarshalIndent(genesis, "", "\t")
	if err != nil {
		return errors.Errorf("Unable to form genesis json file: %s", err)
	}

	err = ioutil.WriteFile(genesisFile, b, 0644)
	if err != nil {
		return errors.Errorf("Failed to write genesis file: %s", err)
	}

	return nil
}

func populateAccounts(genesis *core.Genesis, allocFile string) error {
	if len(allocFile) == 0 {
		return nil
	}

	b, err := ioutil.ReadFile(allocFile)
	if err != nil {
		return err
	}

	var allocData allocDataJson
	err = json.Unmarshal(b, &allocData)
	if err != nil {
		return err
	}

	allocator := testutils.NewGenesisAllocator()
	for _, v := range allocData.Expenses {
		addr := common.HexToAddress(v.Address)
		value, ok := new(big.Int).SetString(v.Value, 10)
		if !ok {
			return errors.Errorf("Failed to convert '%s' to big.Int", v.Value)
		}
		allocator.AddEntry(addr, value)
	}
	allocator.PopulateGenesis(genesis)
	return nil
}
