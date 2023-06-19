package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/ethereum/go-ethereum/thunder/pala/types"
)

type pubkey struct {
	data []byte
}

func (k pubkey) ToBytes() []byte {
	return k.data
}

func printUsageExit() {
	fmt.Fprintf(os.Stderr, "usage: pubkey-id <pubkey-in-base64 or pubkey-in-hex>\n")
	fmt.Fprintf(os.Stderr, "print the consensus id from public key\n")
	fmt.Fprintf(os.Stderr, "\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	logger := log.New(os.Stderr, "" /* prefix*/, 0 /*flags*/)
	flag.Usage = printUsageExit
	flag.Parse()
	args := flag.Args()
	if len(args) != 1 {
		printUsageExit()
	}
	var bs []byte
	var err error
	if len(args[0]) == 256 {
		bs, err = hex.DecodeString(args[0])
		if err != nil {
			logger.Fatalf("Failed to decode: %+v", err)
		}
	} else {
		bs, err = base64.StdEncoding.DecodeString(args[0])
		if err != nil {
			logger.Fatalf("Failed to decode: %+v", err)
		}
	}

	fmt.Println(types.ConsensusIdFromPubKey(pubkey{bs}))
}
