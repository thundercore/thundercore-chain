package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/xerrors"
)

var (
	logger = lgr.NewLgr("/transfer")
)

type transfer struct {
	client        *ethclient.Client
	sourceAccount *account
	chainId       *big.Int
	gasPrice      *big.Int
}

type account struct {
	privateKey *ecdsa.PrivateKey
	address    common.Address
	nonce      uint64
}

func newTransfer(sourceKeyHex string, rpcUrl string) *transfer {
	fmt.Fprintf(os.Stderr, "> Connecting to rpcUrl %q\n", rpcUrl)

	client, err := ethclient.Dial(rpcUrl)
	if err != nil {
		logger.Error("cannot connect to %s: %s", rpcUrl, err)
		os.Exit(1)
	}

	privateKey, err := crypto.HexToECDSA(sourceKeyHex)
	if err != nil {
		logger.Error("failed to create the private key: %s", err)
		os.Exit(1)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		logger.Error("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
		os.Exit(1)
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		logger.Error("failed to get pending nonce: %s", err)
		os.Exit(1)
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		logger.Error("failed to get suggested gas price: %s", err)
		os.Exit(1)
	}

	chainId, err := client.NetworkID(context.Background())
	if err != nil {
		logger.Error("failed to get network id: %s", err)
		os.Exit(1)
	}

	return &transfer{
		client: client,
		sourceAccount: &account{
			privateKey: privateKey,
			address:    fromAddress,
			nonce:      nonce,
		},
		chainId:  chainId,
		gasPrice: gasPrice,
	}
}

func (t *transfer) transfer(
	toAddress common.Address, value *big.Int,
) (*types.Transaction, error) {
	gasLimit := uint64(21000) // in gas units

	var data []byte
	from := t.sourceAccount
	tx := types.NewTransaction(from.nonce, toAddress, value, gasLimit, t.gasPrice, data)
	txJsonBytes, err := tx.MarshalJSON()
	if err != nil {
		logger.Error("tx.MarshalJSON failed: %s", err)
	} else {
		fmt.Fprintf(os.Stderr, "tx: %s\n", string(txJsonBytes))
	}
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(t.chainId), from.privateKey)
	if err != nil {
		return nil, xerrors.Errorf("failed to sign tx: %s", err)
	}

	err = t.client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return nil, xerrors.Errorf("failed to send transaction: %s", err)
	}
	return signedTx, nil
}

type PrettyReceiptType map[string]string

func transactionReceipt(ctx context.Context, ec *ethclient.Client, txHash common.Hash) (PrettyReceiptType, error) {
	var r map[string]string
	err := ec.CallContext(ctx, &r, "eth_getTransactionReceipt", txHash)
	if err == nil {
		if r == nil {
			return nil, ethereum.NotFound
		}
	}
	return r, nil
}

func (t *transfer) pollReceipt(
	txHash common.Hash, receiptWaitingPeriod time.Duration,
) (PrettyReceiptType, error) {
	begin := time.Now()
	defer func() {
		fmt.Fprintf(os.Stderr, "> Took %s to get the receipt\n", fmtDuration(time.Now().Sub(begin)))
	}()

	for {
		receipt, err := transactionReceipt(context.Background(), t.client, txHash)
		if err == nil {
			return receipt, nil
		}
		if err != ethereum.NotFound {
			return nil, xerrors.Errorf("failed to get receipt: %s", err)
		}
		if receiptWaitingPeriod <= 0 {
			return nil, xerrors.New("timeout")
		}
		t := 200 * time.Millisecond
		if t > receiptWaitingPeriod {
			t = receiptWaitingPeriod
		}
		time.Sleep(t)
		receiptWaitingPeriod -= t
	}
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Millisecond)
	return fmt.Sprintf("%dms", int(d/time.Millisecond))
}

func programName() string {
	return filepath.Base(os.Args[0])
}

func printUsageExit() {
	fmt.Fprintf(os.Stderr, "usage: %s RPC_URL PRIVATE_KEY_FILE [[DEST_ADDR] AMOUNT_IN_TT]\n", programName())
	os.Exit(2)
}

func exitWithError(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func main() {
	receiptWaitTime := flag.Duration("w", 2*time.Second, "duration to wait for transaction receipt (e.g., 5s).")
	flag.Parse()

	args := flag.Args()
	if len(args) < 2 || 4 < len(args) {
		printUsageExit()
	}

	rpcUrl := args[0]
	sourceKeyFilename := args[1]
	destAddrStr := "0x123456789"
	if len(args) > 2 {
		destAddrStr = args[2]
	}
	amountInTtStr := "0"
	if len(args) > 3 {
		amountInTtStr = args[3]
	}

	sourceKeyHex, err := ioutil.ReadFile(sourceKeyFilename)
	if err != nil {
		exitWithError(err)
	}

	t := newTransfer(strings.TrimSuffix(string(sourceKeyHex), "\n"), rpcUrl)
	toTt, ok := big.NewInt(0).SetString("1000000000000000000", 10)
	if !ok {
		fmt.Fprintf(os.Stderr, "%+v", xerrors.New("(*big.Int)SetString failed"))
		os.Exit(1)
	}
	amount, ok := big.NewInt(0).SetString(amountInTtStr, 0)
	if !ok {
		fmt.Fprintf(os.Stderr, "%+v", xerrors.New("(*big.Int)SetString failed"))
		os.Exit(1)
	}
	amount.Mul(amount, toTt)
	signedTx, err := t.transfer(common.HexToAddress(destAddrStr), amount)
	if err != nil {
		exitWithError(err)
	}
	receipt, err := t.pollReceipt(signedTx.Hash(), *receiptWaitTime)
	if err != nil {
		exitWithError(err)
	}
	fmt.Printf("txHash: %v\n", signedTx.Hash().Hex())
	receiptBytes, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "json.MarshalIndent failed: %s\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "receipt:\n")
	os.Stdout.Write(receiptBytes)
	os.Stdout.Write([]byte("\n"))
}
