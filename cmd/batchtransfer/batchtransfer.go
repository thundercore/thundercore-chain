package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/xerrors"
)

const (
	desiredTps           = 4000
	transactionsPerBatch = 10 * desiredTps // number of transactions to send in one batch
	receiptWaitTime      = 10 * time.Minute
	transactionGasLimit  = uint64(21 * 1000)
)

func printUsageExit() {
	fmt.Fprintf(os.Stderr, "usage: %s [OPTIONS] RPC-URL PRIVATEKEY-FILE ACCOUNTS-AND-BALANCES.json\n", path.Base(os.Args[0]))
	fmt.Fprintf(os.Stderr, "-i, start index: index of transaction to start sending\n")
	fmt.Fprintf(os.Stderr, "-t, top N accounts by balance to withold funds from\n")
	fmt.Fprintf(os.Stderr, `
Sample Input:

# File containing private key of source address
5082363a2d018a10471c49efac549369a716754ca3c4ac2dc49e33ef726ffc4c

# JSON file contaning destination account and balances, where balance is interpreted as amount of transfer
{
	"accounts": {
		"0000000000000000000000000000000000000000": {
			"balance": "27127951493290000002",
		},
		...
	},
}
`)
	os.Exit(2)
}

type BigInt big.Int

func (z *BigInt) UnmarshalJSON(p []byte) error {
	if bytes.Equal(p, []byte("null")) {
		return nil
	}
	if p[0] == '"' && p[len(p)-1] == '"' {
		p = p[1 : len(p)-1]
	}
	_, ok := ((*big.Int)(z)).SetString(string(p), 0)
	if !ok {
		return xerrors.Errorf("not a valid big integer value: %q", p)
	}
	return nil
}

func readPrivateKey(filePath string) (*ecdsa.PrivateKey, error) {
	b, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return ethCrypto.HexToECDSA(strings.TrimRight(string(b), " \n"))
}

type balance struct {
	Balance *BigInt
}

type accountsType map[string]balance // 'accounts' -> { address: balance }

func readAccountsAndBalancesJson(filePath string) (accountsType, error) {
	b, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	data := make(map[string]json.RawMessage)
	if err = json.Unmarshal(b, &data); err != nil {
		return nil, err
	}
	accounts := make(accountsType)
	if err = json.Unmarshal(data["accounts"], &accounts); err != nil {
		return nil, err
	}
	return accounts, nil
}

func sortedKeys(a map[string]balance) []string {
	keys := make([]string, 0, len(a))
	for k := range a {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func isErrKnownTransaction(err error) bool {
	return (strings.Index(err.Error(), "known transaction:") >= 0)
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

func pollReceipt(ethClient *ethclient.Client, txHash common.Hash) (PrettyReceiptType, error) {
	var (
		receipt PrettyReceiptType
		err     error
	)
	tEnd := time.Now().Add(receiptWaitTime)
	for time.Now().Before(tEnd) {
		receipt, err = transactionReceipt(context.Background(), ethClient, txHash)
		if err == nil {
			return receipt, nil
		}
		fmt.Fprintf(os.Stderr, "%s: TransactionReceipt: %s\n", time.Now().Format(time.RFC3339), err)
		if err != nil && err != ethereum.NotFound {
			return nil, err
		}
		time.Sleep(1 * time.Second)
	}
	if receipt == nil {
		return nil, xerrors.New("timedout waiting for receipt")
	}
	return receipt, nil
}

type Transfer struct {
	ethClient  *ethclient.Client
	privKey    *ecdsa.PrivateKey
	sourceAddr common.Address
	nonce      uint64
	chainId    *big.Int
	gasPrice   *big.Int
}

func NewTransfer(
	ethClient *ethclient.Client,
	privKey *ecdsa.PrivateKey,
	sourceAddr common.Address,
	nonce uint64,
	chainId *big.Int,
	gasPrice *big.Int) *Transfer {
	return &Transfer{
		ethClient:  ethClient,
		privKey:    privKey,
		sourceAddr: sourceAddr,
		nonce:      nonce,
		chainId:    chainId,
		gasPrice:   gasPrice,
	}
}

func (t *Transfer) sendBatch(txGasLimit uint64, txSpace []*types.Transaction,
	accountsAndBalances accountsType, accounts []string) (PrettyReceiptType, error) {
	c := make(chan error, len(accounts))
	nTxns := len(accounts)
	for i := 0; i < nTxns; i++ {
		destStr := accounts[i]
		dest := common.HexToAddress(destStr)
		value := (*big.Int)(accountsAndBalances[destStr].Balance)
		go func(i int) {
			tx := types.NewTransaction(t.nonce+uint64(i), dest, value, txGasLimit, t.gasPrice, nil)
			signedTx, err := types.SignTx(tx, types.NewEIP155Signer(t.chainId), t.privKey)
			if err != nil {
				c <- err
				return
			}
			txSpace[i] = signedTx
			c <- nil
		}(i)
	}
	for i := 0; i < nTxns; i++ {
		if err := <-c; err != nil {
			fmt.Fprintf(os.Stderr, "SignTx Failed: %s\n", err)
			return nil, err
		}
	}
	txSent := txSpace[:nTxns]
	err := t.ethClient.SendTransactions(context.Background(), txSent)
	if err != nil && !isErrKnownTransaction(err) {
		fmt.Fprintf(os.Stderr, "SendTransactions failed: %s\n", err)
		return nil, err
	}
	txLast := txSent[len(txSent)-1]
	receipt, err := pollReceipt(t.ethClient, txLast.Hash())
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: pollReceipt failed: %s\n", time.Now().Format(time.RFC3339), err)
		return nil, err
	}
	t.nonce += uint64(nTxns)
	return receipt, nil
}

func sumBalance(accountsAndBalances accountsType, startIndex int) *big.Int {
	accountsAll := sortedKeys(accountsAndBalances)
	s := big.NewInt(0)
	for i := startIndex; i < len(accountsAll); i++ {
		account := accountsAll[i]
		b := (*big.Int)(accountsAndBalances[account].Balance)
		if b.Sign() < 0 {
			panic(fmt.Sprintf("destination account with negative balance: %q, %d", account, b))
		}
		s.Add(s, b)
	}
	return s
}

func (t *Transfer) transfer(accountsAndBalances accountsType, startIndex int) (PrettyReceiptType, error) {
	txs := make([]*types.Transaction, transactionsPerBatch)
	accountsAll := sortedKeys(accountsAndBalances)

	var (
		receipt PrettyReceiptType
		err     error
	)
	for i := startIndex; i < len(accountsAll); i += transactionsPerBatch {
		fmt.Fprintf(os.Stderr, "%s: transaction-index: %d\n", time.Now().Format(time.RFC3339), i)
		end := i + transactionsPerBatch
		if end > len(accountsAll) {
			end = len(accountsAll)
		}
		accounts := accountsAll[i:end]
		receipt, err = t.sendBatch(transactionGasLimit, txs, accountsAndBalances, accounts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sendBatch: transaction-index: %d failed: %s\n", i, err)
			return nil, err
		}
	}
	fmt.Fprintf(os.Stderr, "%s: transaction-index: %d\n", time.Now().Format(time.RFC3339), len(accountsAll)-1)
	return receipt, nil
}

func sortAccountByBalance(accountsAndBalances accountsType) []string {
	as := make([]string, 0, len(accountsAndBalances))
	for a := range accountsAndBalances {
		as = append(as, a)
	}
	sort.Slice(as, func(i, j int) bool {
		// sort descending by (balance, account) lexicographical order
		r := (*big.Int)(accountsAndBalances[as[i]].Balance).Cmp((*big.Int)(accountsAndBalances[as[j]].Balance))
		if r == 0 {
			return as[i] > as[j]
		}
		return (r > 0)
	})
	return as
}

func main() {
	startIndex := flag.Int("i", 0, "index of transaction to start with")
	topNtoWithold := flag.Int("t", 0, "top N accounts by balance to withold funds from")

	flag.Parse()
	args := flag.Args()
	if len(args) != 3 {
		printUsageExit()
	}
	RpcUrl := args[0]
	privateKeyFilePath := args[1]
	balancesJsonPath := args[2]

	privKey, err := readPrivateKey(privateKeyFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "readPrivateKey failed: %s\n", err)
		os.Exit(1)
	}
	sourceAccount := ethCrypto.PubkeyToAddress(*(privKey.Public().(*ecdsa.PublicKey)))

	accountsAndBalances, err := readAccountsAndBalancesJson(balancesJsonPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "readAccountsAndBalances failed: %s\n", err)
		os.Exit(1)
	}

	var accountsByBalance []string
	if *topNtoWithold > 0 {
		accountsByBalance = sortAccountByBalance(accountsAndBalances)
		avoid := accountsByBalance[:*topNtoWithold]
		for _, addr := range avoid {
			delete(accountsAndBalances, addr)
		}
		avoided := []byte(strings.Join(avoid, "\n"))
		avoided = append(avoided, byte('\n'))
		if err := ioutil.WriteFile("topN", avoided, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "WriteFile(\"topN\") failed: %s\n", err)
			os.Exit(1)
		}
	}

	ethClient, err := ethclient.Dial(RpcUrl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ethclient.Dial failed: %s\n", err)
		os.Exit(1)
	}

	gasPrice, err := ethClient.SuggestGasPrice(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "suggestedGasPrice failed: %s\n", err)
		os.Exit(1)
	}

	chainId, err := ethClient.NetworkID(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "NetworkID failed: %s\n", err)
		os.Exit(1)
	}

	nonce, err := ethClient.PendingNonceAt(context.Background(), sourceAccount)
	if err != nil {
		fmt.Fprintf(os.Stderr, "PendingNonceAt(%q) failed: %s\n", sourceAccount.Hex(), err)
		os.Exit(1)
	}

	totalBalance := sumBalance(accountsAndBalances, *startIndex)
	sourceAccountBalance, err := ethClient.BalanceAt(context.Background(), sourceAccount, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "PendingNonceAt(%q) failed: %s\n", sourceAccount.Hex(), err)
		os.Exit(1)
	}
	estimatedGas := big.NewInt(int64(transactionGasLimit))
	estimatedGas.Mul(estimatedGas, gasPrice)
	totalBalance.Add(totalBalance, estimatedGas)

	if sourceAccountBalance.Cmp(totalBalance) < 0 {
		fmt.Fprintf(os.Stderr, "Balance of source account %q less than required\nHave: %d\nWant: %d\n",
			sourceAccount.Hex(), sourceAccountBalance, totalBalance)
		os.Exit(1)
	}

	t := NewTransfer(ethClient, privKey, sourceAccount, nonce, chainId, gasPrice)
	receipt, err := t.transfer(accountsAndBalances, *startIndex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "transfer failed: %#v(%T), %s\n", err, err, err)
		os.Exit(1)
	}

	receiptBytes, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "json.MarshalIndent failed: %s\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "receipt:\n")
	os.Stdout.Write(receiptBytes)
	os.Stdout.Write([]byte("\n"))
}
