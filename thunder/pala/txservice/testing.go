package txservice

import (
	"strconv"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/limiter"
	"github.com/ethereum/go-ethereum/thunder/pala/network"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params"
	"golang.org/x/xerrors"
)

type TxPoolFake struct {
	sync.Mutex
	seenTx       map[common.Hash]*types.Transaction
	txFeed       event.Feed
	removeTxFeed event.Feed
	scope        event.SubscriptionScope
}

var (
	msgLimiterConfigForTest = []limiter.MsgLimitConfig{
		limiter.MsgLimitConfig{MsgId: limiter.MsgId(strconv.Itoa(int(MessageTxDistribute))), Limit: 100, Window: time.Second},
	}
)

func NewTxPoolFake() *TxPoolFake {
	return &TxPoolFake{
		seenTx: make(map[common.Hash]*types.Transaction),
	}
}

func (t *TxPoolFake) SubscribeNewTxsEvent(ch chan<- core.NewTxsEvent) event.Subscription {
	return t.scope.Track(t.txFeed.Subscribe(ch))
}

func (t *TxPoolFake) SubscribeEvictTxsEvent(ch chan<- core.EvictTxEvent) event.Subscription {
	return t.scope.Track(t.removeTxFeed.Subscribe(ch))
}

func (t *TxPoolFake) AddRemotes(txs []*types.Transaction) []error {
	t.Lock()
	defer t.Unlock()
	r := make([]error, len(txs))
	newTxs := make([]*types.Transaction, 0)
	for i, tx := range txs {
		hash := tx.Hash()
		if _, ok := t.seenTx[hash]; !ok {
			t.seenTx[hash] = tx
			r[i] = nil
			newTxs = append(newTxs, tx)
		}
	}

	go t.txFeed.Send(core.NewTxsEvent{Txs: newTxs})

	return r
}

func (t *TxPoolFake) Pending(enforceTip bool) (map[common.Address]types.Transactions, error) {
	t.Lock()
	defer t.Unlock()
	signer := types.NewEIP155Signer(params.ThunderChainConfig().ChainID)
	r := make(map[common.Address]types.Transactions)
	for _, tx := range t.seenTx {
		sender, err := types.Sender(signer, tx)
		if err != nil {
			debug.Bug("Cannot get sender")
		}
		r[sender] = append(r[sender], tx)
	}
	return r, nil
}

func (t *TxPoolFake) Close() {
	t.scope.Close()
}

type TxRouterFake struct {
	sync.Mutex
	graph map[ConsensusId]map[ConsensusId]bool
	self  ConsensusId
}

func (r *TxRouterFake) ShouldSend(verifiedId ConsensusId, session blockchain.Session) bool {
	r.Lock()
	defer r.Unlock()
	return r.graph[r.self][verifiedId]
}

func (r *TxRouterFake) changeRoute(nr map[ConsensusId]map[ConsensusId]bool) {
	r.Lock()
	defer r.Unlock()
	r.graph = nr
}

type TxDistributorClientFake struct {
	connections map[ConsensusId]chan *network.Message
	myId        ConsensusId
}

func (c *TxDistributorClientFake) Send(id ConsensusId, msg *network.Message) error {
	d, ok := c.connections[id]
	if ok {
		d <- network.NewMessageFake(msg.GetType(), msg.GetAttribute(), c.myId, c.myId, msg.GetBlob())

		return nil
	} else {
		return xerrors.New("id Not Found")
	}
}

type FakeDistributorList map[ConsensusId]*TxDistributor

func NewFakeDistributorList(
	topology map[ConsensusId]map[ConsensusId]bool, clock utils.Clock) FakeDistributorList {
	ret := make(map[ConsensusId]*TxDistributor)
	connections := make(map[ConsensusId]chan *network.Message)
	clients := make(map[ConsensusId]*TxDistributorClientFake)
	for id := range topology {
		connections[id] = make(chan *network.Message, 1024)
		clients[id] = &TxDistributorClientFake{
			connections: make(map[ConsensusId]chan *network.Message),
			myId:        id,
		}
	}

	for id, links := range topology {
		for target := range links {
			connect := func(from, to ConsensusId, connectAddress string) {
				myId := clients[to].myId
				clients[from].connections[myId] = connections[to]

				m := network.NewConnectionOpenMessageFake("", to, connectAddress)

				connections[from] <- m
			}

			connect(id, target, "addr-"+string(target))
			connect(target, id, "")
		}
	}

	for id := range topology {
		r := &TxRouterFake{
			graph: topology,
			self:  id,
		}
		ret[id] = NewTxDistributor(
			string(id) /*loggingId*/, id, NewTxPoolFake(), clients[id], r,
			blockchain.Session(1), connections[id],
			msgLimiterConfigForTest, clock)
	}

	return ret
}

type sendRecord struct {
	id  ConsensusId
	msg *network.Message
}
type txDistributorClientMock struct {
	called chan *sendRecord
}

func newTxDistributerClientMock() *txDistributorClientMock {
	return &txDistributorClientMock{
		called: make(chan *sendRecord, 1024),
	}
}

func (t *txDistributorClientMock) Send(id ConsensusId, msg *network.Message) error {
	t.called <- &sendRecord{
		id:  id,
		msg: msg,
	}
	return nil
}
