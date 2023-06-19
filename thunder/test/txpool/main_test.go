//go:build !skipe2etest
// +build !skipe2etest

package txpool

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/test"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"
)

const (
	rpcURL = "http://127.0.0.1:8545"
)

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		fmt.Println("skipping rpc tests in short mode")
		os.Exit(0)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-sig
		cancel()
	}()

	result := make(chan int)

	if err := checkNoPalaServerIsRunning(ctx, 3); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	cmd, err := test.StartPala("-g", "-r", "single-test")
	if err != nil {
		fmt.Println("start pala-dev fail", err)
		os.Exit(1)
	}

	time.Sleep(5 * time.Second)

	if err := waitForRPCServerIsUp(ctx, 60); err != nil {
		fmt.Println("wait for rpc service fail", err)
		test.StopPala(cmd)
		os.Exit(1)
	}

	go func() {
		result <- m.Run()
	}()

	var r int
	select {
	case <-ctx.Done():
		r = 1
	case r = <-result:
	}
	test.StopPala(cmd)
	os.Exit(r)
}

func TestTxPool(t *testing.T) {
	client := mustDial(t, rpcURL)

	ctx := context.Background()
	account, err := test.NewGenesisAccount()
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	chainID, err := client.NetworkID(ctx)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	// Setup signer
	signer := types.NewLondonSigner(chainID)

	nonce, err := client.GetNonce(ctx, account.Address, nil)
	if err != nil {
		t.Fatalf("%v\n", err)
	}

	// Send a non executable tx, it will be added to tx pool's queue.
	queueTx, err := test.SendRawTransaction(client, signer, account.Key, nonce+1, account.Address,
		test.ToWei(big.NewInt(1)), 21000, test.ToWei(big.NewInt(1)), nil)

	if err != nil {
		t.Fatalf("%v\n", err)
	}

	// Wait longer than a tx pool evict interval, but shorted than tx lifetime.
	time.Sleep(20 * time.Second)

	// Send a tx to fill the gap.
	_, err = test.SendRawTransaction(client, signer, account.Key, nonce, account.Address,
		test.ToWei(big.NewInt(1)), 21000, test.ToWei(big.NewInt(1)), nil)

	if err != nil {
		t.Fatalf("%v\n", err)
	}

	// queueTx become executable and hasn't been evicted.
	waitTx(t, client, queueTx.Hash())

	// Send a non executable tx, it will be added to tx pool's queue.
	queueTx, err = test.SendRawTransaction(client, signer, account.Key, nonce+3, account.Address,
		test.ToWei(big.NewInt(1)), 21000, test.ToWei(big.NewInt(1)), nil)

	if err != nil {
		t.Fatalf("%v\n", err)
	}

	// Wait longer than a tx lifetime.
	time.Sleep(45 * time.Second)

	_, err = client.GetTransactionByHash(ctx, queueTx.Hash())
	if err != ethereum.NotFound {
		t.Fatalf("queueTx should be evicted")
	}
}

func TestTxSizeLimit(t *testing.T) {
	req := require.New(t)
	client := mustDial(t, rpcURL)

	ctx := context.Background()
	account, err := test.NewGenesisAccount()
	req.NoError(err)
	chainID, err := client.NetworkID(ctx)
	req.NoError(err)
	// Setup signer
	signer := types.NewLondonSigner(chainID)

	nonce, err := client.GetNonce(ctx, account.Address, nil)
	req.NoError(err)

	txSizeLimit := 4*32*1024 - 1 // 131072 - 1 (tx type)
	preservedSize := 130         // magic number, to make a transaction as big as it could
	gas := uint64(9000000)

	tests := []struct {
		name       string
		dataSize   int
		txSize     int
		shouldFail bool
	}{
		{
			name:       "oversized",
			dataSize:   txSizeLimit - preservedSize + 1,
			txSize:     txSizeLimit + 1,
			shouldFail: true,
		},
		{
			name:       "just fit",
			dataSize:   txSizeLimit - preservedSize,
			txSize:     txSizeLimit,
			shouldFail: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.dataSize)
			_, err = rand.Read(data)
			req.NoError(err)
			tx, err := test.SendRawTransaction(client, signer, account.Key, nonce, account.Address,
				test.ToWei(big.NewInt(1)), gas, test.ToWei(big.NewInt(1)), data)
			req.Equal(common.StorageSize(tt.txSize), tx.Size())
			if tt.shouldFail {
				req.Error(err)
			} else {
				req.NoError(err)
			}
		})
	}
}

func waitTx(t *testing.T, client *test.Client, hash common.Hash) *test.Transaction {
	t.Helper()
	var tx *test.Transaction
	var err error
	for i := 0; i < 10; i++ {
		tx, err = client.GetTransactionByHash(context.Background(), hash)
		if err == nil && tx.BlockNumber != nil {
			return tx
		}
		if err != nil && err != ethereum.NotFound {
			t.Fatalf("%v\n", err)
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("wait for tx confirmation timeout\n")
	return nil
}

func checkNoPalaServerIsRunning(ctx context.Context, retry int) error {
	c, err := test.Dial(rpcURL)
	if err != nil {
		return err
	}
	defer c.Close()

	for i := 0; i < retry; i++ {
		if _, err := c.NetworkID(context.Background()); err != nil {
			return nil
		}
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return xerrors.New("existing rpc service is running, please make sure no pala-dev is running before run this test")
}

func waitForRPCServerIsUp(ctx context.Context, retry int) error {
	c, err := test.Dial(rpcURL)
	if err != nil {
		return err
	}
	defer c.Close()

	for i := 0; i < retry; i++ {
		if _, err := c.NetworkID(context.Background()); err == nil {
			return nil
		}
		select {
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return xerrors.New("timeout")
}

func mustDial(t *testing.T, url string) *test.Client {
	t.Helper()
	c, err := test.Dial(url)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
		return nil
	}
	return c
}
