package txservice

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/consensus/startstopwaiter"
	"github.com/ethereum/go-ethereum/thunder/pala/limiter"
	"github.com/ethereum/go-ethereum/thunder/pala/network"
	"github.com/ethereum/go-ethereum/thunder/pala/testutils/detector"
	"github.com/ethereum/go-ethereum/thunder/thunderella/testutils"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"
)

var (
	_ = startstopwaiter.StartStopWaiter(&TxDistributor{})
)

func TestDistributor_DistributeTx(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)
	// this is the potential case we expected, that is a fullnode is connected to two bootnodes, and there's one proposer for each bootnode.
	// fullnode->bootnode1->proposer1
	//  		\
	//           ->bootnode2->proposer2
	topology := make(map[ConsensusId]map[ConsensusId]bool)
	topology["fullnode"] = make(map[ConsensusId]bool)
	topology["bootnode1"] = make(map[ConsensusId]bool)
	topology["bootnode2"] = make(map[ConsensusId]bool)
	topology["proposer1"] = make(map[ConsensusId]bool)
	topology["proposer2"] = make(map[ConsensusId]bool)

	topology["fullnode"]["bootnode1"] = true
	topology["fullnode"]["bootnode2"] = true
	topology["bootnode1"]["proposer1"] = true
	topology["bootnode2"]["proposer2"] = true

	distributors := NewFakeDistributorList(topology, utils.NewClock())

	txChans := make(map[ConsensusId]chan core.NewTxsEvent)

	req.Equal(5, len(distributors))
	for id, d := range distributors {
		req.NotNil(d)
		d.Start()

		txChans[id] = make(chan core.NewTxsEvent, 10)
		sub := d.txpool.SubscribeNewTxsEvent(txChans[id])
		defer sub.Unsubscribe()
	}

	// case1: if fullnode add a transaction Tx, every node gets Tx
	// NOTE: we don't verify any of transactions here
	toAddr := common.HexToAddress("0x0000000000000000000000000000000000000000")
	tx := testutils.MakeTxactSimple(testutils.TestingKey, &toAddr, 1)
	txs := []*types.Transaction{tx}
	distributors["fullnode"].txpool.AddRemotes(txs)

	for id, d := range distributors {
		select {
		case e := <-txChans[id]:
			req.Equal(1, len(e.Txs))
			_, ok := d.txpool.(*TxPoolFake).seenTx[tx.Hash()]
			req.True(ok)
		case <-time.After(1000 * time.Millisecond):
			req.FailNow("Timeout", "Expect %s to get tx", id)
		}
	}

	// case2: if bootnode1 add a transaction Tx, only bootnode1 and proposer1 gets the Tx
	if testing.Short() {
		t.Skip()
	}

	toAddr = common.HexToAddress("0x0000000000000000000000000000000000000000")
	tx = testutils.MakeTxactSimple(testutils.TestingKey, &toAddr, 2)
	txs = append(txs, tx)
	distributors["bootnode1"].txpool.AddRemotes(txs)

	for id, d := range distributors {
		select {
		case e := <-txChans[id]:
			if id != "bootnode1" && id != "proposer1" {
				req.FailNow("Incorrect route", "Expect only bootnode1 and proposer1, but %s got", id)
			}
			req.Equal(1, len(e.Txs))
			_, ok := d.txpool.(*TxPoolFake).seenTx[tx.Hash()]
			req.True(ok)
		case <-time.After(120 * time.Millisecond):
			if id == "bootnode1" || id == "proposer1" {
				req.FailNow("Incorrect route", "Expect bootnode1 and proposer1 don't miss, but %s misses", id)
			}
		}
	}

}

func TestDisconnectAfterRestart(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)
	client := &TxDistributorClientFake{}
	routing := map[ConsensusId]map[ConsensusId]bool{
		"td": {"someone": true},
	}
	r := &TxRouterFake{graph: routing, self: "td"}
	ch := make(chan *network.Message)
	td := NewTxDistributor("td", "td", NewTxPoolFake(), client, r,
		blockchain.Session(1), ch, msgLimiterConfigForTest, utils.NewClock())

	req.NoError(td.Start())
	someOne := ConsensusId("someone")
	ch <- network.NewConnectionOpenMessageFake(someOne, someOne, "1.2.3.4")
	req.NoError(td.StopAndWait())
	req.NoError(td.Start())
	ch <- network.NewConnectionClosedMessageFake(someOne, someOne)
	req.NoError(td.Stop())
}

// Test_Con0Con1Discon0_DoesNotDoubleClose is a regression test for a "double close channel" bug found by anthony
func Test_Con0Con1Discon0_DoesNotDoubleClose(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)
	client := &TxDistributorClientFake{}
	routing := map[ConsensusId]map[ConsensusId]bool{
		"td": {"someone": true},
	}
	r := &TxRouterFake{graph: routing, self: "td"}
	ch := make(chan *network.Message)
	td := NewTxDistributor("td", "td", NewTxPoolFake(), client, r,
		blockchain.Session(1), ch, msgLimiterConfigForTest, utils.NewClock())

	req.NoError(td.Start())
	someOne := ConsensusId("someone")
	ch <- network.NewConnectionOpenMessageFake(someOne, someOne, "1.2.3.4")
	ch <- network.NewConnectionClosedMessageFake(someOne, someOne)
	ch <- network.NewConnectionOpenMessageFake(someOne, someOne, "1.2.3.4")

	req.NoError(td.StopAndWait())
}

func TestRateLimit(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)
	client := &TxDistributorClientFake{}
	config := []limiter.MsgLimitConfig{
		limiter.MsgLimitConfig{MsgId: limiter.MsgId(strconv.Itoa(int(MessageTxDistribute))), Limit: 2, Window: 20 * time.Millisecond},
	}
	ch := make(chan *network.Message)
	td := NewTxDistributor("td", "td", NewTxPoolFake(), client, nil,
		blockchain.Session(1), ch, config, utils.NewClock())
	p := newTxPeer("peer1", "peer1", client)
	td.peers = map[ConsensusId]*txPeer{
		p.verifiedId: p,
	}

	toAddr := common.HexToAddress("0x0000000000000000000000000000000000000000")
	msgs := make([]*network.Message, 4)
	for i := range msgs {
		txs := []*types.Transaction{testutils.MakeTxactSimple(testutils.TestingKey, &toAddr, uint64(i))}
		txsMsg := txDistributeMessage{Txs: types.Transactions(txs)}
		msg := txsMsg.toNetworkMessage()
		msgs[i] = network.NewMessageFake(msg.GetType(), msg.GetAttribute(), p.verifiedId, p.verifiedId, msg.GetBlob())
	}

	stopCh := make(chan interface{})
	msgIn := make(chan *network.Message)
	msgOut := make(chan *network.Message, 2)
	go td.rateLimitLoop(msgIn, msgOut, stopCh)
	defer func() {
		close(stopCh)
	}()

	acceptedMsg := []*network.Message{}
	closedMsg := []*network.Message{}

	msgIn <- msgs[0]
	time.Sleep(5 * time.Millisecond)
	acceptedMsg = append(acceptedMsg, msgs[0])

	msgIn <- msgs[1]
	time.Sleep(5 * time.Millisecond)
	acceptedMsg = append(acceptedMsg, msgs[1])

	// over rate limit
	msgIn <- msgs[2]
	closedMsg = append(closedMsg, msgs[2])
	time.Sleep(20 * time.Millisecond)

	// msgOut is full: this step simulates the worker goroutine is too busy.
	msgIn <- msgs[3]
	closedMsg = append(closedMsg, msgs[3])
	time.Sleep(10 * time.Millisecond)

	for _, msg := range closedMsg {
		req.True(msg.IsClosed())
	}

	for _, msg := range acceptedMsg {
		m := <-msgOut
		req.True(reflect.DeepEqual(m, msg))
	}
}

type dummyClient int

func (d dummyClient) Send(ConsensusId, *network.Message) error {
	return nil
}

func TestTraceRoutes(t *testing.T) {
	const waitingTime = 50 * time.Millisecond

	t.Run("no route", func(t *testing.T) {
		req := require.New(t)

		id := ConsensusId("f1")
		var c dummyClient
		td := NewTxDistributor(
			string(id), id, NewTxPoolFake(), c, &TxRouterFake{self: id},
			blockchain.Session(1), nil, msgLimiterConfigForTest, utils.NewClock())

		td.TraceRoutes()

		time.Sleep(waitingTime)
		actual := td.GetAliveRoutes()
		req.Equal(0, len(actual))
	})

	traceRoute := func(req *require.Assertions, td *TxDistributor, expected int) []*TxRouteLog {
		var actual []*TxRouteLog
		// It's hard to tell whether the path is ready. Try reasonable times.
		maxTrials := 10
		time.Sleep(waitingTime)
		for i := 0; i < maxTrials; i++ {
			td.TraceRoutes()
			time.Sleep(waitingTime)
			actual = td.GetAliveRoutes()
			if len(actual) == expected && i < maxTrials-2 {
				// Run one more time to make it possible to collect more routes.
				i = maxTrials - 2
			}
		}
		req.Equal(expected, len(actual))
		return actual
	}

	routeToKey := func(r []IdAndAddr) string {
		var sb strings.Builder
		for _, t := range r {
			sb.WriteString(string(t.Id) + ",")
		}
		return sb.String()
	}

	checkRoutes := func(req *require.Assertions, actual []*TxRouteLog, expected map[string]bool) {
		for _, log := range actual {
			key := routeToKey(log.Route)
			_, ok := expected[key]
			req.True(ok, "unexpected path: "+key)
			delete(expected, key)
		}
		for k := range expected {
			req.FailNow(k + " does not exist")
		}
	}

	t.Run("multiple proposers", func(t *testing.T) {
		req := require.New(t)

		// This is closed to the topology in R2.
		//
		// fullnode-->bootnode1--+-->proposer1
		//    |                  |
		//    |                  |
		//    +------>bootnode2--+-->proposer2
		topology := make(map[ConsensusId]map[ConsensusId]bool)
		topology["fullnode"] = make(map[ConsensusId]bool)
		topology["bootnode1"] = make(map[ConsensusId]bool)
		topology["bootnode2"] = make(map[ConsensusId]bool)
		topology["proposer1"] = make(map[ConsensusId]bool)
		topology["proposer2"] = make(map[ConsensusId]bool)

		topology["fullnode"]["bootnode1"] = true
		topology["fullnode"]["bootnode2"] = true

		topology["bootnode1"]["proposer1"] = true
		topology["bootnode1"]["proposer2"] = true

		topology["bootnode2"]["proposer1"] = true
		topology["bootnode2"]["proposer2"] = true

		clock := utils.NewClockFake()
		distributors := NewFakeDistributorList(topology, clock)

		for _, d := range distributors {
			req.NotNil(d)
			d.Start()
			defer func(d *TxDistributor) {
				d.StopAndWait()
			}(d)
		}

		td := distributors["fullnode"]
		actual := traceRoute(req, td, 2*2)

		expected := map[string]bool{
			"proposer1,bootnode1,": true,
			"proposer1,bootnode2,": true,
			"proposer2,bootnode1,": true,
			"proposer2,bootnode2,": true,
		}
		checkRoutes(req, actual, expected)

		// Test that the record is cleared after a while.
		clock.Add(time.Minute + time.Second)
		actual = td.GetAliveRoutes()
		req.Equal(0, len(actual))
	})

	t.Run("bootnode circle and proposer circle", func(t *testing.T) {
		req := require.New(t)

		// fullnode-->bootnode1--+-->proposer1
		//    |          ^       |      ^
		//    |          |       |      |
		//    |          v       |      v
		//    +------>bootnode2--+-->proposer2
		topology := make(map[ConsensusId]map[ConsensusId]bool)
		topology["fullnode"] = make(map[ConsensusId]bool)
		topology["bootnode1"] = make(map[ConsensusId]bool)
		topology["bootnode2"] = make(map[ConsensusId]bool)
		topology["proposer1"] = make(map[ConsensusId]bool)
		topology["proposer2"] = make(map[ConsensusId]bool)

		topology["fullnode"]["bootnode1"] = true
		topology["fullnode"]["bootnode2"] = true

		topology["bootnode1"]["proposer1"] = true
		topology["bootnode1"]["proposer2"] = true
		// Simulate bootnodes don't send tx to bootnodes.
		topology["bootnode1"]["bootnode2"] = false
		topology["bootnode2"]["bootnode1"] = false

		topology["bootnode2"]["proposer1"] = true
		topology["bootnode2"]["proposer2"] = true

		// Simulate proposers don't send tx to proposers.
		topology["proposer1"]["proposer2"] = false
		topology["proposer2"]["proposer1"] = false

		clock := utils.NewClockFake()
		distributors := NewFakeDistributorList(topology, clock)

		for _, d := range distributors {
			req.NotNil(d)
			d.Start()
			defer func(d *TxDistributor) {
				d.StopAndWait()
			}(d)
		}

		td := distributors["fullnode"]
		actual := traceRoute(req, td, 2*2)

		expected := map[string]bool{
			"proposer1,bootnode1,": true,
			"proposer1,bootnode2,": true,
			"proposer2,bootnode1,": true,
			"proposer2,bootnode2,": true,
		}
		checkRoutes(req, actual, expected)

		// Test that the record is cleared after a while.
		clock.Add(time.Minute + time.Second)
		actual = td.GetAliveRoutes()
		req.Equal(0, len(actual))
	})

	t.Run("proposers are also bootnodes", func(t *testing.T) {
		req := require.New(t)

		// fullnode-->proposer-bootnode1
		//    |               ^
		//    |               |
		//    |               |
		//    |               v
		//    +------>proposer-bootnode2
		topology := make(map[ConsensusId]map[ConsensusId]bool)
		topology["fullnode"] = make(map[ConsensusId]bool)
		topology["proposer-bootnode1"] = make(map[ConsensusId]bool)
		topology["proposer-bootnode2"] = make(map[ConsensusId]bool)

		topology["fullnode"]["proposer-bootnode1"] = true
		topology["fullnode"]["proposer-bootnode2"] = true
		topology["proposer-bootnode1"]["proposer-bootnode2"] = true
		topology["proposer-bootnode2"]["proposer-bootnode1"] = true

		clock := utils.NewClockFake()
		distributors := NewFakeDistributorList(topology, clock)

		for _, d := range distributors {
			req.NotNil(d)
			d.Start()
			defer func(d *TxDistributor) {
				d.StopAndWait()
			}(d)
		}

		td := distributors["fullnode"]
		actual := traceRoute(req, td, 2)
		expected := map[string]bool{
			"proposer-bootnode1,proposer-bootnode2,": true,
			"proposer-bootnode2,proposer-bootnode1,": true,
		}
		checkRoutes(req, actual, expected)

		// Test that the record is cleared after a while.
		clock.Add(time.Minute + time.Second)
		actual = td.GetAliveRoutes()
		req.Equal(0, len(actual))
	})
}
