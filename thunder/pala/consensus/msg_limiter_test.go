package consensus

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/config"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/consensus/chainsync"
	"github.com/ethereum/go-ethereum/thunder/pala/limiter"
	"github.com/ethereum/go-ethereum/thunder/pala/network"
)

func TestMsgRateLimit(t *testing.T) {
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	generator, err := blockchain.NewChainGenerator(true, hardforkK)
	if err != nil {
		t.Fatal(err)
	}
	generator.Init(blockchain.NewBlockSn(1, 1, uint32(30)))
	chain := generator.GetChain()
	m := Mediator{chain: chain}
	configs := []limiter.MsgLimitConfig{
		limiter.MsgLimitConfig{MsgId: limiter.MsgId(MessageGetFresherHead.String()), Limit: 3, Window: 100 * time.Millisecond},
	}
	m.msgLimiter = limiter.NewMsgLimiter(configs)

	block := chain.GetGenesisBlock()
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

	var v1Msgs []*network.Message
	var v2Msgs []*network.Message
	var v1Replys []chan *network.Message
	var v2Replys []chan *network.Message
	for i := 0; i < 7; i++ {
		v1Reply := make(chan *network.Message)
		v1Msgs = append(v1Msgs, network.NewMessageWithWriteOnlyConn(
			uint8(MessageGetFresherHead), msg.GetAttribute(), msg.GetBlob(), v1Reply))
		v1Replys = append(v1Replys, v1Reply)

		v2Reply := make(chan *network.Message)
		v2Msgs = append(v2Msgs, network.NewMessageWithWriteOnlyConn(
			uint8(MessageGetFresherHeadV2), msg.GetAttribute(), msg.GetBlob(), v2Reply))
		v2Replys = append(v2Replys, v2Reply)
	}

	testcases := []struct {
		msg     *network.Message
		reply   chan *network.Message
		sleep   time.Duration
		dropped bool
	}{
		{v1Msgs[0], v1Replys[0], 10 * time.Millisecond, false},
		{v1Msgs[1], v1Replys[1], 10 * time.Millisecond, false},
		{v1Msgs[2], v1Replys[2], 70 * time.Millisecond, false},
		{v1Msgs[3], v1Replys[3], 100 * time.Millisecond, true},
		{v1Msgs[4], v1Replys[4], 120 * time.Millisecond, false},
		{v1Msgs[5], v1Replys[5], 130 * time.Millisecond, false},
		{v1Msgs[6], v1Replys[6], 140 * time.Millisecond, true},

		{v2Msgs[0], v2Replys[0], 10 * time.Millisecond, false},
		{v2Msgs[1], v2Replys[1], 10 * time.Millisecond, false},
		{v2Msgs[2], v2Replys[2], 70 * time.Millisecond, false},
		{v2Msgs[3], v2Replys[3], 100 * time.Millisecond, false},
		{v2Msgs[4], v2Replys[4], 120 * time.Millisecond, false},
		{v2Msgs[5], v2Replys[5], 130 * time.Millisecond, false},
		{v2Msgs[6], v2Replys[6], 140 * time.Millisecond, false},
	}

	msgCh := make(chan *network.Message, 14)

	for _, tc := range testcases {
		go func(msg *network.Message, sleep time.Duration) {
			time.Sleep(sleep)
			msgCh <- msg

		}(tc.msg, tc.sleep)
	}

	for i := 0; i < len(testcases); i++ {
		m.handleNetworkMessage(<-msgCh)
	}

	timeout := time.After(1 * time.Second)
	for i, tc := range testcases {
		if !tc.dropped {
			select {
			case <-tc.reply:
			case <-timeout:
				t.Fatalf("test #%d: wait for reply timeout", i)
			}
		}
	}

	for i, tc := range testcases {
		if tc.dropped {
			select {
			case <-tc.reply:
				t.Errorf("test #%d: should be dropped", i)
			default:
			}
		}
	}

}
