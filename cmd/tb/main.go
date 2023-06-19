package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/xerrors"
)

var logger = lgr.NewLgr("/tb")

const (
	// The hard-coded genesis key in the local chain and tools/pala-dev
	genesisKeyHex = "5082363a2d018a10471c49efac549369a716754ca3c4ac2dc49e33ef726ffc4c"
)

type txBenchmarker struct {
	verbose              bool
	receiptWaitingPeriod time.Duration
	useBatchTransfer     bool
	client               *ethclient.Client
	root                 *account
	chainId              *big.Int
	gasPrice             *big.Int
	gasPriceMultiple     int
	numTxsDiff           uint64

	mu sync.Mutex
	wg sync.WaitGroup
}

type account struct {
	index      int
	privateKey *ecdsa.PrivateKey
	address    common.Address
	nonce      uint64
}

//------------------------------------------------------------------------------

func newTxBenchmarker(
	url string, receiptWaitingPeriod time.Duration, useBatchTransfer bool,
	gasPriceMultiple int, verbose bool,
) *txBenchmarker {
	fmt.Printf("> Connect to %s\n", url)
	client, err := ethclient.Dial(url)
	if err != nil {
		logger.Error("cannot connect to %s: %s", url, err)
		os.Exit(1)
	}

	privateKey, err := crypto.HexToECDSA(genesisKeyHex)
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
	if gasPriceMultiple > 1 {
		gasPrice.Mul(gasPrice, big.NewInt(int64(gasPriceMultiple)))
	}

	chainId, err := client.NetworkID(context.Background())
	if err != nil {
		logger.Error("failed to get network id: %s", err)
		os.Exit(1)
	}

	return &txBenchmarker{
		verbose:              verbose,
		receiptWaitingPeriod: receiptWaitingPeriod,
		useBatchTransfer:     useBatchTransfer,
		client:               client,
		gasPriceMultiple:     gasPriceMultiple,
		root: &account{
			privateKey: privateKey,
			address:    fromAddress,
			nonce:      nonce,
		},
		chainId:  chainId,
		gasPrice: gasPrice,
	}
}

func (tb *txBenchmarker) transferFromRootKey(
	toAddress common.Address, value *big.Int,
	receiptWaitingPeriod time.Duration, gasPrice *big.Int,
) (*types.Receipt, error) {
	return tb.transfer(tb.root, toAddress, value, receiptWaitingPeriod, gasPrice)
}

func (tb *txBenchmarker) transfer(
	from *account, toAddress common.Address, value *big.Int,
	receiptWaitingPeriod time.Duration, gasPrice *big.Int,
) (*types.Receipt, error) {
	// Prepare and send tx.
	gasLimit := uint64(21000) // in units

	var data []byte
	tx := types.NewTransaction(from.nonce, toAddress, value, gasLimit, gasPrice, data)
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(tb.chainId), from.privateKey)
	if err != nil {
		return nil, xerrors.Errorf("failed to sign tx: %s", err)
	}

	err = tb.client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return nil, xerrors.Errorf("failed to send transaction: %s", err)
	}

	if receiptWaitingPeriod == 0 {
		return nil, nil
	}

	// Poll the receipt.
	return tb.pollReceipt(signedTx, receiptWaitingPeriod)
}

func (tb *txBenchmarker) batchTransfer(
	from *account, toAddress common.Address, value *big.Int, n int,
	receiptWaitingPeriod time.Duration, gasPrice *big.Int,
) (*types.Receipt, error) {
	if n <= 0 {
		return nil, xerrors.Errorf("n = %d is <= 0", n)
	}

	// Prepare and send tx.
	gasLimit := uint64(21000) // in units

	txs := make([]*types.Transaction, n)
	for i := 0; i < n; i++ {
		tx := types.NewTransaction(from.nonce, toAddress, value, gasLimit, gasPrice, nil)
		signedTx, err := types.SignTx(tx, types.NewEIP155Signer(tb.chainId), from.privateKey)
		if err != nil {
			return nil, xerrors.Errorf("failed to sign tx: %s", err)
		}
		txs[i] = signedTx
		from.nonce++
	}

	err := tb.client.SendTransactions(context.Background(), txs)
	if err != nil {
		return nil, xerrors.Errorf("failed to send transaction: %s", err)
	}

	if receiptWaitingPeriod == 0 {
		return nil, nil
	}

	// Poll the receipt.
	return tb.pollReceipt(txs[len(txs)-1], receiptWaitingPeriod)
}

func (tb *txBenchmarker) pollReceipt(
	tx *types.Transaction, receiptWaitingPeriod time.Duration,
) (*types.Receipt, error) {
	begin := time.Now()
	defer func() {
		fmt.Printf("> Waited %s to get the receipt\n", fmtDuration(time.Since(begin)))
	}()

	h := tx.Hash()
	for {
		receipt, err := tb.client.TransactionReceipt(context.Background(), h)
		if err == nil {
			return receipt, nil
		}
		if err != ethereum.NotFound {
			return nil, xerrors.Errorf("failed to get receipt: %s", err)
		}
		//fmt.Printf("No receipt for %s. Wait a while\n", hex.EncodeToString(h[:]))
		if receiptWaitingPeriod <= 0 {
			return nil, xerrors.New("timeout")
		}
		// This is related to timePerBlock (1s) in PaLa.
		t := 200 * time.Millisecond
		if t > receiptWaitingPeriod {
			t = receiptWaitingPeriod
		}
		time.Sleep(t)
		receiptWaitingPeriod -= t
	}
}

func (tb *txBenchmarker) newAccount() (*ecdsa.PrivateKey, common.Address) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		logger.Error("cannot generate key: %s", err)
		os.Exit(1)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		logger.Error("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
		os.Exit(1)
	}

	return privateKey, crypto.PubkeyToAddress(*publicKeyECDSA)
}

func (tb *txBenchmarker) createAccounts(numAccounts int) ([]*account, error) {
	fmt.Printf("> Create %d accounts\n", numAccounts)

	var receipt *types.Receipt
	var err error
	accounts := []*account{}
	for i := 0; i < numAccounts; i++ {
		privateKey, address := tb.newAccount()
		var receiptWaitingPeriod time.Duration
		if i == numAccounts-1 {
			receiptWaitingPeriod = 10 * time.Second
		}
		// When we run 2+ tb and there are lots of txs, the txs may be processed after a long time.
		// Use 10x price to make things happen faster.
		gasPrice := new(big.Int).Set(tb.getGasPrice())
		gasPrice.Mul(gasPrice, big.NewInt(10))
		val := new(big.Int)
		val.SetString("5902958103587056517120", 10) // (1 << 64) * 40 * 8
		receipt, err = tb.transferFromRootKey(address, val, receiptWaitingPeriod, gasPrice)
		if err != nil {
			fmt.Printf("Failed to transfer from root: %s\n", err)
			return nil, err
		}

		tb.root.nonce++

		accounts = append(accounts, &account{
			index:      i + 1,
			privateKey: privateKey,
			address:    address,
		})

		addressInHex := hex.EncodeToString(address[:])
		fmt.Printf("%d account: %s\n", i, addressInHex)
	}

	if receipt == nil || receipt.Status != 1 {
		fmt.Printf("Failed to initialize new accounts\n")
		return accounts, nil
	}

	return accounts, nil
}

func RandomSelectAccounts(accounts []*account, num int) (ret []*account) {
	for i := 0; i < num; i++ {
		ret = append(ret, accounts[rand.Intn(len(accounts))])
	}
	return ret
}

func (tb *txBenchmarker) updateAccountNonce(accounts []*account) {
	var wg sync.WaitGroup
	for _, acc := range accounts {
		wg.Add(1)
		go func(acc *account) {
			defer wg.Done()
			nonce, err := tb.client.PendingNonceAt(context.Background(), acc.address)
			if err != nil {
				fmt.Printf(">Failed to update account nonce: %v", err.Error())
			}
			acc.nonce = nonce

		}(acc)
	}
	wg.Wait()
}

func (tb *txBenchmarker) runAsync(numAccounts, concurrency, numRound, numTx int) {
	accounts, err := tb.createAccounts(numAccounts)
	if err != nil {
		fmt.Printf("> Failed to create %d accounts", numAccounts)
		return
	}

	fmt.Printf("> Successful created and made transfers to %d accounts\n", numAccounts)
	tb.wg.Add(1)
	stopCh := make(chan struct{}, 1)
	go func() {
		defer func() {
			tb.wg.Done()
		}()

		var wg sync.WaitGroup
		for i := 0; i < numRound; i++ {
			fmt.Printf("Round %d, concurrency %d:\n", i, concurrency)
			wg = sync.WaitGroup{}
			accountSet := RandomSelectAccounts(accounts, concurrency)
			tb.updateAccountNonce(accountSet)
			for i := 0; i < len(accountSet); i++ {
				from := accountSet[i]
				to := accountSet[(i+1)%len(accountSet)]
				wg.Add(1)
				go tb.runOneAccount(&wg, from, to, numTx)
			}
			wg.Wait()
		}
		close(stopCh)
	}()

	tb.wg.Add(1)
	go tb.listenGasPrice(stopCh)
	go tb.showDiffStatus()
}

func (tb *txBenchmarker) setGasPrice(price *big.Int) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.gasPrice = price
}

func (tb *txBenchmarker) getGasPrice() *big.Int {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.gasPrice
}

func (tb *txBenchmarker) listenGasPrice(stopCh chan struct{}) {
	defer func() {
		tb.wg.Done()
	}()

LOOP:
	for {
		select {
		case <-stopCh:
			break LOOP
		default:
		}

		<-time.After(time.Second)

		gasPrice, err := tb.client.SuggestGasPrice(context.Background())
		if err == nil {
			if tb.gasPriceMultiple > 1 {
				gasPrice.Mul(gasPrice, big.NewInt(int64(tb.gasPriceMultiple)))
			}
			tb.setGasPrice(gasPrice)
		} else {
			fmt.Printf("Failed to get gas price: %s\n", err)
		}
	}
}

func (tb *txBenchmarker) runOneAccount(wg *sync.WaitGroup, from, to *account, numTx int) {
	defer func() {
		wg.Done()
	}()

	toAddress := to.address
	addressInHex := hex.EncodeToString(from.address[:])
	fmt.Printf("> send %d txs from accounts[%d] to accounts[%d]\n", numTx, from.index, to.index)

	begin := time.Now()
	beginNonce := from.nonce

	// Start a new round.
	if tb.useBatchTransfer {
		_, err := tb.batchTransfer(from, toAddress, big.NewInt(1), numTx, tb.receiptWaitingPeriod, tb.getGasPrice())
		if err != nil {
			fmt.Printf("Failed to transfer in a batch from %s: %s. Reset the state.\n", addressInHex, err)
		}
	} else {
		for j := 0; j < numTx; j++ {
			var receiptWaitingPeriod time.Duration
			if tb.receiptWaitingPeriod > 0 && j == numTx-1 {
				receiptWaitingPeriod = tb.receiptWaitingPeriod
			}
			_, err := tb.transfer(from, toAddress, big.NewInt(1), receiptWaitingPeriod, tb.getGasPrice())
			from.nonce++
			if err != nil {
				if strings.Contains(err.Error(), "known transaction:") {
					// It's okay. The tx is probably in the non-executable queue.
					fmt.Printf("Failed to transfer from %s: %s.\n", addressInHex, err)
					continue
				} else {
					// Unknown error. Restart to get the nonce.
					fmt.Printf("Failed to transfer from %s: %s. Reset the state.\n", addressInHex, err)
					return
				}
			}
		}
	}

	// Show the statistics per account.
	txDiff := from.nonce - beginNonce
	tb.addTxDiff(txDiff)

	if tb.verbose {
		tps := "n.a."
		duration := time.Since(begin)
		if duration > 0 {
			tps = fmt.Sprintf("%.1f", float64(txDiff)/(float64(duration)/float64(time.Second)))
		}
		fmt.Printf("> account %d: nonce=%d (+%d, TPS=%s)\n", from.index, from.nonce, txDiff, tps)
	}
}

func (tb *txBenchmarker) addTxDiff(diff uint64) {
	for {
		old := tb.numTxsDiff
		if atomic.CompareAndSwapUint64(&tb.numTxsDiff, old, old+diff) {
			break
		}
	}
}

func (tb *txBenchmarker) showDiffStatus() {
	reset := func() uint64 {
		for {
			old := tb.numTxsDiff
			if atomic.CompareAndSwapUint64(&tb.numTxsDiff, old, 0) {
				return old
			}
		}
	}
	for {
		reset()
		d := 2 * time.Second
		time.Sleep(d)

		n := reset()
		fmt.Printf("> Total TPS=%.1f\n", calculateTps(int(n), d))
	}
}

//------------------------------------------------------------------------------

func benchmarkRpcPerSecond(url string) {
	run := func(n int) (time.Duration, error) {
		tb := newTxBenchmarker(url, 0, false, 1, false)
		begin := time.Now()
		for i := 0; i < n; i++ {
			_, err := tb.client.NetworkID(context.Background())
			if err != nil {
				logger.Error("failed to get network id: %s", err)
				return 0, err
			}
		}
		return time.Since(begin), nil
	}

	// Benchmark 1 client.
	n := 20000
	d, err := run(n)
	if err != nil {
		fmt.Printf("Failed to benchmark: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("1 client: %.1f\n", calculateTps(n, d))

	// Benchmark 2 client.
	var wg sync.WaitGroup
	n /= 2
	ds := make([]time.Duration, 2)
	for k := 0; k < 2; k++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			ds[k], err = run(n)
			if err != nil {
				fmt.Printf("Failed to benchmark: %s\n", err)
				os.Exit(1)
			}
		}(k)
	}
	wg.Wait()

	fmt.Printf("2 clients: %.1f\n", calculateTps(n*2, ds[0]+ds[1]))
}

func calculateTps(n int, d time.Duration) float64 {
	return float64(n) / (float64(d) / float64(time.Second))
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Millisecond)
	return fmt.Sprintf("%dms", int(d/time.Millisecond))
}

//------------------------------------------------------------------------------

func main() {
	numAccounts := flag.Int("a", 100, "number of accounts")
	concurrency := flag.Int("c", 10, "number of concurrency")
	benchmarkRpc := flag.Bool("b", false, "benchmark RPC/s using a simple RPC")
	gasPriceMultiple := flag.Int("p", 1, "set the multiple of the gas price "+
		"(e.g., \"2\" means \"suggested gas price\" * 2)")
	numRound := flag.Int("r", 10000000, "number of rounds")
	single := flag.Bool("s", false, "Send transactions one by one (default: send txs in a batch). This slows down TPS significantly.")
	numTx := flag.Int("t", 1000, "number of txs in a round")
	url := flag.String("u", "http://127.0.0.1:8545", "RPC URL")
	verbose := flag.Bool("v", false, "verbose output")
	wait := flag.Duration("w", 0, "waiting period for the last receipt in a round (e.g., 5s). This slows down TPS significantly.")
	flag.Parse()

	if *benchmarkRpc {
		benchmarkRpcPerSecond(*url)
		return
	}

	tb := newTxBenchmarker(*url, *wait, !*single, *gasPriceMultiple, *verbose)
	tb.runAsync(*numAccounts, *concurrency, *numRound, *numTx)
	tb.wg.Wait()
}
