package main

import (
	"bufio"
	"crypto/ecdsa"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/xerrors"
)

func SecretKeyAddress(sk *ecdsa.PrivateKey) (common.Address, error) {
	publicKey := sk.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return common.Address{}, xerrors.Errorf("type assertion: publicKey is not of type (*ecdsa.PublicKey): %#v", publicKey)
	}
	return crypto.PubkeyToAddress(*publicKeyECDSA), nil
}

func programName() string {
	return filepath.Base(os.Args[0])
}

func printUsageExit() {
	fmt.Fprintf(os.Stderr, "usage: %s [OPTIONS] [PRIVATE_KEYS_FILE]\n", programName())
	fmt.Fprintf(os.Stderr, "OPTIONS:\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	logger := log.New(os.Stderr, "" /* prefix*/, 0 /*flags*/)
	flag.Usage = printUsageExit
	flag.Parse()
	args := flag.Args()
	var (
		fIn *os.File
		err error
	)
	if len(args) == 0 {
		fIn = os.Stdin
	} else if len(args) == 1 {
		fileName := args[0]
		fIn, err = os.Open(fileName)
		if err != nil {
			logger.Fatalf("Open: %+v", err)
		}
		defer fIn.Close()
	} else {
		printUsageExit()
	}

	scanner := bufio.NewScanner(fIn)
	addrs := make([]common.Address, 0)
	for scanner.Scan() {
		skStr := scanner.Text()
		if skStr[:2] == "0x" || skStr[:2] == "0X" {
			skStr = skStr[2:]
		}
		skBytes, err := hex.DecodeString(skStr)
		if err != nil {
			logger.Fatalf("hex.DecodeString(%q): %+v", skStr, err)
		}
		sk, err := crypto.ToECDSA(skBytes)
		if err != nil {
			logger.Fatalf("crypto.ToECDSA(%q): %+v", skStr, err)
		}
		addr, err := SecretKeyAddress(sk)
		if err != nil {
			logger.Fatalf("SecretKeyAddress(%q): %+v", skStr, err)
		}
		addrs = append(addrs, addr)
	}
	if err := scanner.Err(); err != nil {
		logger.Fatalf("scanner.Err: %+v", err)
	}

	f := os.Stdout
	for _, addr := range addrs {
		addrBytes := addr[:]
		bs := make([]byte, hex.EncodedLen(len(addrBytes)))
		hex.Encode(bs, addrBytes)
		f.WriteString("0x")
		f.Write(bs)
		f.WriteString("\n")
	}
}
