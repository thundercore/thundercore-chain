package main

import (
	// Standard includes
	"crypto/ecdsa"
	"encoding/hex"
	"flag"
	"fmt"

	// Thunder includes
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"

	// Vendor includes
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	blsFlag   = flag.Bool("bls", false, "create bls signing key instead of ecdsa private key")
	printFlag = flag.String("print", "", "print info about the private or public key specified")
)

func printBlsPrivKey(privKey *bls.SigningKey) {
	fmt.Printf("bls signing key is %s\n", hex.EncodeToString(privKey.ToBytes()))
	printBlsPubKey(privKey.GetPublicKey())
}

func printBlsPubKey(pubKey *bls.PublicKey) {
	fmt.Printf("bls public  key is %s\n", hex.EncodeToString(pubKey.ToBytes()))
}

func printPrivKey(privKey *ecdsa.PrivateKey) {
	keyBytes := crypto.FromECDSA(privKey)
	fmt.Printf("priv key is %s\n", hex.EncodeToString(keyBytes))
	printPubKey(&privKey.PublicKey)
}

func printPubKey(pubKey *ecdsa.PublicKey) {
	keyBytes := crypto.FromECDSAPub(pubKey)
	fmt.Printf("pub  key is %s\n", hex.EncodeToString(keyBytes))
	addr := crypto.PubkeyToAddress(*pubKey)
	fmt.Printf("addr     is %s\n", addr.Hex())
}

func getBlsSigningKey(bytes []byte) (key *bls.SigningKey) {
	defer func() {
		//lint:ignore SA9003 for explanation purpose
		if r := recover(); r != nil {
			//fmt.Printf("caught panic\n")
		}
	}()
	key = bls.SigningKeyFromBytes(bytes) // panics if not right
	return key
}

func main() {
	flag.Parse()
	if *printFlag != "" {
		// print the key corresponding to the hex in printFlag
		bytes, err := hex.DecodeString(*printFlag)
		if err != nil {
			fmt.Printf("can't get hex from %s: %s\n", *printFlag, err)
			return
		}
		if *blsFlag {
			pubKey := &bls.PublicKey{}
			err = pubKey.FromBytes(bytes)
			if err == nil {
				printBlsPubKey(pubKey)
			} else {
				signingKey := getBlsSigningKey(bytes)
				if signingKey != nil {
					printBlsPrivKey(signingKey)
				} else {
					fmt.Printf("not a bls key\n")
				}
			}
		} else {
			privKey, err := crypto.ToECDSA(bytes)
			if err == nil {
				printPrivKey(privKey)
			} else {
				pubKey, err := crypto.UnmarshalPubkey(bytes)
				// crypto.UnmarshalPubkey only checks X value, do we need to check Y value?
				if err != nil || pubKey.Y == nil {
					fmt.Printf("bad value\n")
					return
				}
				printPubKey(pubKey)
			}
		}
	} else if *blsFlag {
		signingKey, err := bls.NewSigningKey()
		if err != nil {
			fmt.Printf("can't generate key: %s\n", err)
			return
		}
		printBlsPrivKey(signingKey)
	} else {
		privKey, err := crypto.GenerateKey()
		if err != nil {
			fmt.Printf("can't generate key: %s\n", err)
			return
		}
		printPrivKey(privKey)
	}
}
