package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

func printUsage() {
	fmt.Printf("usage: %s txHash sourceRpcUrl targetRpcUrl\n", os.Args[0])
}

func main() {
	if len(os.Args) < 4 {
		printUsage()
		os.Exit(1)
	}
	txHash := common.HexToHash(os.Args[1])
	sourceRpc := os.Args[2]
	targetRpc := os.Args[3]
	ctx := context.Background()

	sourceClient, targetClient, signer := getClients(sourceRpc, targetRpc)

	tx, _, err := sourceClient.TransactionByHash(ctx, txHash)
	if err != nil {
		log.Fatalf("Failed to get tx %s: %s", txHash, err)
	}

	from, err := types.Sender(signer, tx)
	if err != nil {
		log.Fatalf("Failed to get sender: %s", err)
	}

	nonce, err := targetClient.NonceAt(ctx, from, nil)
	if err != nil {
		log.Fatalf("Failed to get nonce for %s: %s", from.String(), err)
	}
	if nonce != tx.Nonce() {
		log.Fatalf("Nonce mismatch")
	}

	spew.Dump(tx)

	err = targetClient.SendTransaction(ctx, tx)
	if err != nil {
		log.Fatalf("Failed to send tx: %s", err)
	}

	timeout := time.After(60 * time.Minute)
ForEnd:
	for {
		select {
		case <-timeout:
			log.Fatal("Failed to get receipt\n")
			break ForEnd
		case <-time.After(1 * time.Second):
			receipt, err := targetClient.TransactionReceipt(ctx, txHash)
			if err == nil {
				spew.Dump(receipt)
				break ForEnd
			}
			log.Print("Did not get receipt, try again\n")
		}
	}

	os.Exit(0)
}

func getClients(sourceRpc, targetRpc string) (*ethclient.Client, *ethclient.Client, types.Signer) {
	sourceClient, err := ethclient.Dial(sourceRpc)
	if err != nil {
		log.Fatalf("Failed to connect to source-rpc: %s", err)
	}

	targetClient, err := ethclient.Dial(targetRpc)
	if err != nil {
		log.Fatalf("Failed to connect to source-rpc: %s", err)
	}

	ctx := context.Background()
	sourceNId, err := sourceClient.NetworkID(ctx)
	if err != nil {
		log.Fatalf("Failed to get sourceRpc networkId: %s", err)
	}
	targetNId, err := targetClient.NetworkID(ctx)
	if err != nil {
		log.Fatalf("Failed to get targetRpc networkId: %s", err)
	}
	if sourceNId.Cmp(targetNId) != 0 {
		log.Fatalf("Network ID mismatch")
	}
	return sourceClient, targetClient, types.NewEIP155Signer(sourceNId)
}
