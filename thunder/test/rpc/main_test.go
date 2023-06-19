//go:build !skipe2etest
// +build !skipe2etest

package rpc

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/test"

	"github.com/stretchr/testify/suite"
	"golang.org/x/xerrors"
)

// See:
// https://github.com/ethereum/wiki/wiki/JSON-RPC
// https://infura.io/docs/ethereum/json-rpc
var wantRPCCall = map[string][]string{
	"fast_rpc": []string{
		"net_version",
		"net_peerCount",
		"net_listening",
		"web3_clientVersion",
		"web3_sha3",
		"eth_blockNumber",
		"personal_newAccount",
		"personal_listAccounts",
		"eth_newBlockFilter",
		"eth_gasPrice",
		"eth_getBlockByHash",
		"eth_getBlockByNumber",
		"eth_getBlockTransactionCountByHash",
		"eth_getBlockTransactionCountByNumber",
	},

	"slow_rpc": []string{
		"personal_sendTransaction",

		// State related
		"eth_getBalance",
		"eth_getTransactionCount",
		"eth_getCode",
		"eth_getStorageAt",

		// TODO(sonic)
		// "eth_getProof",

		// Transaction related
		"eth_getTransactionByHash",
		"eth_getTransactionByBlockHashAndIndex",
		"eth_getTransactionByBlockNumberAndIndex",
		"eth_getTransactionReceipt",

		"eth_call",
		"eth_estimateGas",

		// Chain related filters
		"eth_newPendingTransactionFilter",

		// Event log related filters
		"eth_newFilter",
		"eth_getFilterChanges",
		"eth_getFilterLogs",
		"eth_getLogs",

		"eth_uninstallFilter",
	},

	"slow_ws": []string{
		"eth_subscribe_newPendingTransactions",
		"eth_subscribe_logs",
	},
	"fast_ws": []string{
		"eth_subscribe_newHeads",
	},
}

const (
	rpcURL = "http://127.0.0.1:8545"
	wsURL  = "ws://127.0.0.1:8546"
)

var (
	errTimeout = xerrors.New("timeout")
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

func TestRPC(t *testing.T) {
	c := mustDial(t, rpcURL)
	suite.Run(t, NewFastRPCTestSuite(c))
	checkCalls(t, c.Record(), wantRPCCall["fast_rpc"])
}

func TestRPCWithDefaultAccounts(t *testing.T) {
	c := mustDial(t, rpcURL)
	suite.Run(t, NewSlowRPCTestSuite(c))
	checkCalls(t, c.Record(), wantRPCCall["slow_rpc"])
}

func TestWS(t *testing.T) {
	c := mustDial(t, wsURL)
	suite.Run(t, NewFastWSTestSuite(c))
	checkCalls(t, c.Record(), wantRPCCall["fast_ws"])
}

func TestWSWithDefaultAccounts(t *testing.T) {
	c := mustDial(t, rpcURL)
	wsClient := mustDial(t, wsURL)
	suite.Run(t, NewSlowWSTestSuite(c, wsClient))
	checkCalls(t, wsClient.Record(), wantRPCCall["slow_ws"])
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
	return errTimeout
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

func checkCalls(t *testing.T, called map[string]struct{}, wantCalls []string) {
	t.Helper()
	for _, call := range wantCalls {
		if _, ok := called[call]; !ok {
			t.Errorf("expect %s call", call)
		}
	}
}
