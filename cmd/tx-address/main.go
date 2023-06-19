package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chainconfig"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

const exampleIn = `
{
    "nonce": "0x0",
    "gasPrice": "0x3b9aca00",
    "gas": "0xf4240",
    "to": "0x30d87bd4d1769437880c64a543bb649a693eb348",
    "value": "0x152d02c7e14af6800000",
    "input": "0x40011ebd000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000152d02c7e14af6800000000000000000000000000000000000000000000000000000000000000098968000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000008042358ce70430665cc2b0caaf96d7fec644048699fe7ee0302153bd8b4689942a20b750ee87b32e13b6f4fec599e78edeb9946d44dc7088f4af6b72754c0c54c17e59ffc53dc7a667462cac3832744142fa1a41e74ff090bea5ecebaca8cf4ea68f921c4814a8b05e61492baa5127d4a753d84cb408654d6f34ce8dc6af40a0330000000000000000000000000000000000000000000000000000000000000000",
    "v": "0x49",
    "r": "0xc0a893156095648d48db63b3af43626189a16162d2c833d1a51910f0f350fb36",
    "s": "0xe18cccd44af8a39c1bb06a80c9be1f3983a3ba292b003086db6ec54eb0343a6",
    "hash": "0x37976f54b1c0393df0f8ec4497ae512d598d14539eb353bad095bf0ff76503c3"
}
`

const exampleOut = `Testnet: 80e9da9445613c394850f351ebdc8282129138de`

func printUsageExit() {
	fmt.Fprintf(os.Stderr, "usage: tx-address <file>\n")
	fmt.Fprintf(os.Stderr, "print the address of a tx in <file>. The format is in JSON.\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "example of a file content: %s\n", exampleIn)
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "example of output:\n%s\n", exampleOut)
	fmt.Fprintf(os.Stderr, "\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func getAddress(chainID int64, tx *types.Transaction) (common.Address, error) {
	signer := types.NewEIP155Signer(big.NewInt(chainID))
	return types.Sender(signer, tx)
}

func main() {
	logger := log.New(os.Stderr, "" /* prefix*/, 0 /*flags*/)
	flag.Usage = printUsageExit
	flag.Parse()
	args := flag.Args()
	if len(args) != 1 {
		printUsageExit()
	}

	fin, err := os.Open(args[0])
	if err != nil {
		logger.Fatalf("Open: %+v", err)
	}
	defer fin.Close()
	bs, err := ioutil.ReadAll(fin)
	if err != nil {
		logger.Fatalf("Read: %+v", err)
	}

	tx := &types.Transaction{}
	if err := tx.UnmarshalJSON(bs); err != nil {
		logger.Fatalf("Failed to decode JSON: %+v", err)
	}

	chain := "Mainnet"
	addr, err := getAddress(chainconfig.MainnetChainID, tx)
	if err != nil {
		chain = "Testnet"
		addr, err = getAddress(chainconfig.TestnetChainID, tx)
		if err != nil {
			logger.Fatalf("Failed to decode address: %+v", err)
		}
	}
	fmt.Printf("%s: %s\n", chain, hex.EncodeToString(addr[:]))
}
