//go:build !skipperftest
// +build !skipperftest

package consensus

import (
	"io/ioutil"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/config"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/consensus/chainsync"
	"github.com/ethereum/go-ethereum/thunder/pala/network"
)

func TestPerfHandleSyncNetworkMsgSpeed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}

	// Setup a chain.
	dir, err := ioutil.TempDir("", "handle_sync_msg_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	chainDB, ethChain, err := blockchain.NewThunderSinceGenesisWithDiskDb(dir)
	if err != nil {
		t.Fatal(err)
	}

	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(1, 0)

	chain, err := blockchain.NewBlockChainWithFakeNota(hardforkK, chainDB, ethChain, nil, nil, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	// Tps load
	nTxsPerBlock := 300
	nBlocks := 250

	// Expected speed of consuming msgs in handle sync message loop
	nMsgs := 200
	timePerMsg := 1 * time.Millisecond
	consumingTimeLimit := timePerMsg * time.Duration(nMsgs)

	nChainSyncExtendedBlocks = 10
	nBlockRead := nMsgs * nChainSyncExtendedBlocks

	// Expected collecting data speed (including find blocks, encode/decode blocks)
	v1TimePerBlock := 1000 * time.Microsecond
	v2TimePerBlock := 200 * time.Microsecond
	v1TotalTimeLimit := v1TimePerBlock * time.Duration(nBlockRead)
	v2TotalTimeLimit := v2TimePerBlock * time.Duration(nBlockRead)

	generator := blockchain.NewRealChainGenerator(hardforkK, chain, ethChain, chainDB)
	generator.SetTxsPerBlock(nTxsPerBlock)
	generator.Init(blockchain.NewBlockSn(1, 1, uint32(nBlocks)))

	m := Mediator{chain: chain}

	rand.Seed(time.Now().UnixNano())

	type testcase struct {
		msg   *network.Message
		reply chan *network.Message
	}

	var v1Testcases []testcase
	var v2Testcases []testcase

	for i := 0; i < nMsgs; i++ {
		// Randomly sync from block n, this n ensures that we can always get nChainSyncExtendedBlocks.
		n := uint64(rand.Int31n(int32(nBlocks) - int32(nChainSyncExtendedBlocks)))
		block := chain.GetBlockByNumber(n)

		getHeadMsg := getFresherHeadV2Message{
			head: block.GetBlockSn(),
			blockIdentities: []chainsync.BlockIdentifier{
				chainsync.BlockIdentifier{
					Number: block.GetNumber(),
					Hash:   block.GetHash(),
				},
			},
		}
		msg := getHeadMsg.toNetworkMessage()

		v1Reply := make(chan *network.Message)
		v1Msg := network.NewMessageWithWriteOnlyConn(
			uint8(MessageGetFresherHead), msg.GetAttribute(), msg.GetBlob(), v1Reply)

		v2Reply := make(chan *network.Message)
		v2Msg := network.NewMessageWithWriteOnlyConn(
			uint8(MessageGetFresherHeadV2), msg.GetAttribute(), msg.GetBlob(), v2Reply)
		v1Testcases = append(v1Testcases, testcase{msg: v1Msg, reply: v1Reply})
		v2Testcases = append(v2Testcases, testcase{msg: v2Msg, reply: v2Reply})
	}

	tests := []struct {
		name               string
		testcases          []testcase
		nReplyPerMsg       int
		consumingTimeLimit time.Duration
		totalTimeLimit     time.Duration
	}{
		{"v1", v1Testcases, 1 + nChainSyncExtendedBlocks, consumingTimeLimit, v1TotalTimeLimit},
		{"v2", v2Testcases, 2, consumingTimeLimit, v2TotalTimeLimit},
	}

	for _, tt := range tests {
		done := make(chan struct{})
		start := time.Now()
		wait := time.After(tt.totalTimeLimit)
		go func() {
			for _, tc := range tt.testcases {
				m.handleNetworkMessage(tc.msg)
			}
			done <- struct{}{}
		}()

		select {
		case <-done:
			close(done)
		case <-time.After(tt.consumingTimeLimit):
			t.Errorf("handle %s sync msg too long, expected: %s", tt.name, tt.consumingTimeLimit)
		}
		<-done
		t.Logf("%s msg consuming time: %s limit: %s", tt.name, time.Since(start), tt.consumingTimeLimit)

		fail := false
		for i, tc := range tt.testcases {
			for n := 0; n < tt.nReplyPerMsg; n++ {
				select {
				case <-tc.reply:
				case <-wait:
					t.Errorf("i=%d n=%d, %s reply is not received, limit: %s", i, n, tt.name, tt.totalTimeLimit)
					fail = true
				}
			}
		}
		if !fail {
			t.Logf("all %s sync reply received within: %s, %d blocks read", tt.name, tt.totalTimeLimit, nBlockRead)
		}
	}
}
