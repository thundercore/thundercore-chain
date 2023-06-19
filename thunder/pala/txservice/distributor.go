package txservice

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/consensus/startstopwaiter"
	"github.com/ethereum/go-ethereum/thunder/pala/limiter"
	"github.com/ethereum/go-ethereum/thunder/pala/network"
	thunderTypes "github.com/ethereum/go-ethereum/thunder/pala/types"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	mapset "github.com/deckarep/golang-set"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"golang.org/x/xerrors"
)

type ConsensusId = thunderTypes.ConsensusId

var logger = lgr.NewLgr("/distributor")

const (
	NumberTxKept = 256

	// TODO: don't hard code these values.
	// We assume the max connection is 100. However, we haven't limited the connections.
	maxConnection = 100
	// We limit sending txDistributeMessage 100/s. See aggregate in handleEventLoop() for more details.
	msgCountPerSecond = 100
)

type Set interface {
	Add(i interface{}) bool
	Contains(i ...interface{}) bool
	Pop() interface{}
	// Returns the number of elements in the set.
	Cardinality() int
	Remove(i interface{})
}

type txPeer struct {
	loggingId    string
	verifiedId   ConsensusId
	shouldSendTx bool
	knownTxs     Set
	queuedMsgs   chan *network.Message
	term         chan struct{}
	client       TxDistributorClient
}

func newTxPeer(
	loggingId string, verifiedId ConsensusId, client TxDistributorClient,
) *txPeer {
	return &txPeer{
		loggingId:  loggingId,
		verifiedId: verifiedId,
		knownTxs:   mapset.NewSet(),
		client:     client,
		queuedMsgs: make(chan *network.Message, 1024),
	}
}

func (p *txPeer) keepSending() {
	for {
		select {
		case msg := <-p.queuedMsgs:
			p.client.Send(p.verifiedId, msg)
		case <-p.term:
			return
		}
	}
}

func (p *txPeer) markTx(tx *types.Transaction) bool {
	for p.knownTxs.Cardinality() >= NumberTxKept {
		p.knownTxs.Pop()
	}

	return p.knownTxs.Add(tx.Hash())
}

func (p *txPeer) asyncSendTransactions(txs []*types.Transaction) {
	if !p.shouldSendTx {
		logger.Info("[%s] denial tx to %q due to flags", p.loggingId, p.verifiedId)
		return
	}

	msg := txDistributeMessage{
		Txs: txs,
	}
	select {
	case p.queuedMsgs <- msg.toNetworkMessage():
		logger.Debug("[%s] send %d transactions to %q", p.loggingId, len(txs), p.verifiedId)
		for _, tx := range txs {
			p.markTx(tx)
		}
	default:
		logger.Info("[%s] transaction to peer %q full, dropped", p.loggingId, p.verifiedId)
	}
}

func (p *txPeer) asyncSendMsg(msg *network.Message) {
	select {
	case p.queuedMsgs <- msg:
	default:
		logger.Info("[%s] messages to peer %q full, dropped", p.loggingId, p.verifiedId)
	}
}

func (p *txPeer) removeRecord(txs []*types.Transaction) {
	for _, tx := range txs {
		p.knownTxs.Remove(tx)
	}
}

type TxPool interface {
	SubscribeEvictTxsEvent(ch chan<- core.EvictTxEvent) event.Subscription
	SubscribeNewTxsEvent(ch chan<- core.NewTxsEvent) event.Subscription
	AddRemotes([]*types.Transaction) []error
	Pending(bool) (map[common.Address]types.Transactions, error)
}

type TxDistributorClient interface {
	// Send() should be asynchronous send to reduce starvation risk
	Send(ConsensusId, *network.Message) error
}

type TxRouter interface {
	// ShouldSend tells whether we have to send tx to some id on this session,
	ShouldSend(ConsensusId, blockchain.Session) bool
}

type TxDistributor struct {
	startstopwaiter.StartStopWaiterImpl
	loggingId      string
	myId           ConsensusId
	txpool         TxPool
	router         TxRouter
	currentSession blockchain.Session
	sessionChan    chan blockchain.Session
	client         TxDistributorClient
	messageChan    chan *network.Message
	txCh           chan []*types.Transaction
	funcChan       chan func()
	peers          map[ConsensusId]*txPeer
	total          int
	msgLimiter     *limiter.MsgLimiter
	clock          utils.Clock

	routeLogsMutex sync.Mutex
	routeLogs      map[string]*TxRouteLog
}

type IdAndAddr struct {
	Id        ConsensusId
	Address   string
	ShortName string
}

func (i IdAndAddr) String() string {
	return fmt.Sprintf("%s [%s]", i.Id, i.Address)
}

type TxRouteLog struct {
	Route       []IdAndAddr
	RemainedHop uint8
	UpdatedTime time.Time
}

func (log *TxRouteLog) Clone() *TxRouteLog {
	var tmp TxRouteLog
	tmp.Route = make([]IdAndAddr, len(log.Route))
	copy(tmp.Route, log.Route)
	tmp.RemainedHop = log.RemainedHop
	tmp.UpdatedTime = log.UpdatedTime

	return &tmp
}

func NewTxDistributor(
	loggingId string, myId ConsensusId, pool TxPool, client TxDistributorClient, router TxRouter,
	session blockchain.Session, msgChan chan *network.Message,
	limiterConfigs []limiter.MsgLimitConfig, clock utils.Clock,
) *TxDistributor {
	return &TxDistributor{
		loggingId:      loggingId,
		myId:           myId,
		txpool:         pool,
		client:         client,
		router:         router,
		currentSession: session,
		sessionChan:    make(chan blockchain.Session, 1),
		messageChan:    msgChan,
		funcChan:       make(chan func(), 1024),
		msgLimiter:     limiter.NewMsgLimiter(limiterConfigs),
		clock:          clock,
		routeLogs:      make(map[string]*TxRouteLog),
	}
}

func (t *TxDistributor) receiveTx(txmsg *txDistributeMessage, msg *network.Message) {
	peer := t.peers[msg.GetId()]
	if peer == nil {
		logger.Warn("[%s] Get Message from disconnected peer, drop it.", t.loggingId)
		return
	}

	for _, tx := range txmsg.Txs {
		peer.markTx(tx)
	}

	if len(txmsg.Txs) > 0 {
		select {
		case t.txCh <- txmsg.Txs:
		default:
			t.dropPeer(xerrors.New("receiveTx: too busy"), msg)
		}
	}
}

func (t *TxDistributor) handleTraceRoutes(txMsg *txTraceRoutesMessage, msg *network.Message) {
	logger.Info("[%s] handleTraceRoutes from %q", t.loggingId, msg.GetId())

	if txMsg.HopLimit == 0 {
		t.replyTraceRoutes(msg, txMsg)
		return
	}
	var peers []*txPeer
	isLooped := func(target ConsensusId, all []ConsensusId) bool {
		for _, id := range all {
			if target == id {
				return true
			}
		}
		return false

	}
	for _, p := range t.peers {
		if !p.shouldSendTx {
			continue
		}
		// Avoid loops. Note that the TxPool skips duplicated txs, so whenever there is a loop,
		// the route ends immediately.
		if isLooped(p.verifiedId, txMsg.Sources) {
			continue
		}
		peers = append(peers, p)
	}

	if len(peers) == 0 {
		t.replyTraceRoutes(msg, txMsg)
	}

	txMsg.HopLimit--
	txMsg.Sources = append(txMsg.Sources, t.myId)
	newMsg := txMsg.toNetworkMessage()
	for _, p := range peers {
		p.asyncSendMsg(newMsg.Clone())
	}
}

func (t *TxDistributor) replyTraceRoutes(
	msg *network.Message, txMsg *txTraceRoutesMessage) {
	logger.Info("[%s] replyTraceRoutes to %q", t.loggingId, msg.GetId())
	nHop := len(txMsg.Sources)
	if nHop == 0 || txMsg.Sources[nHop-1] != msg.GetId() {
		t := fmt.Sprintf("[%s] format error; message from %s, nHop=%d", t.loggingId, msg.GetId(), nHop)
		if nHop > 0 {
			t += fmt.Sprintf(", last source is %s", txMsg.Sources[nHop-1])
		}
		logger.Info(t)
		return
	}
	reply := &txTraceRoutesReplyMessage{
		HopLimit: txMsg.HopLimit,
		Sources:  txMsg.Sources[:nHop-1],
	}
	p, ok := t.peers[msg.GetId()]
	if !ok {
		logger.Warn("[%s] peer %s does not exist", t.loggingId, msg.GetId())
		return
	}

	p.asyncSendMsg(reply.toNetworkMessage())
}

func (t *TxDistributor) handleTraceRoutesReply(
	reply *txTraceRoutesReplyMessage, msg *network.Message) {
	logger.Info("[%s] handleTraceRoutesReply from %q", t.loggingId, msg.GetId())

	reply.Route = append(reply.Route, IdAndAddr{
		Id:      msg.GetId(),
		Address: msg.GetSourceAddress(),
	})

	nHop := len(reply.Sources)
	if nHop > 0 {
		destination := reply.Sources[nHop-1]
		if p, ok := t.peers[destination]; ok {
			reply.Sources = reply.Sources[:nHop-1]
			p.asyncSendMsg(reply.toNetworkMessage())
		}
		return
	}

	var key strings.Builder
	for _, tmp := range reply.Route {
		key.WriteString(string(tmp.Id))
	}

	t.clearOutOfDateTxRoutes()
	t.routeLogsMutex.Lock()
	t.routeLogs[key.String()] = &TxRouteLog{
		Route:       reply.Route,
		RemainedHop: reply.HopLimit,
		UpdatedTime: t.clock.Now(),
	}
	t.routeLogsMutex.Unlock()
}

func (t *TxDistributor) clearOutOfDateTxRoutes() {
	t.routeLogsMutex.Lock()
	defer t.routeLogsMutex.Unlock()

	now := t.clock.Now()
	for key, log := range t.routeLogs {
		if log.UpdatedTime.Add(time.Minute).Before(now) {
			delete(t.routeLogs, key)
		}
	}
}

func (t *TxDistributor) onConnected(msg *network.Message) {
	verifiedId := msg.GetId()
	p := newTxPeer(t.loggingId, verifiedId, t.client)

	logger.Info("[%s] Connected to peer:%q, id:%s", t.loggingId, verifiedId,
		msg.GetId())
	if old, ok := t.peers[verifiedId]; ok {
		if old.shouldSendTx {
			logger.Warn("[%s] Connected twice, use new connection", t.loggingId)
		}
		t.removePeerById(verifiedId)
	}

	shouldSendTx := t.router.ShouldSend(verifiedId, t.currentSession)
	t.addPeer(p, shouldSendTx)

	if shouldSendTx {
		t.sendPendingTxs(p)
	}
}

func (t *TxDistributor) onDisconnected(msg *network.Message) {
	id := msg.GetId()
	peer := t.peers[id]

	if peer == nil {
		// Note that the mediator will call host to disconnect again,
		// so we don't panic here.
		return
	}
	logger.Info("[%s] Disconnected from %q", t.loggingId, peer.verifiedId)

	t.removePeerById(id)
}

func (t *TxDistributor) handleNetworkMessage(msg *network.Message) {
	attr := msg.GetAttribute()
	if attr&network.AttrOpen > 0 {
		t.onConnected(msg)
		return
	}

	if attr&network.AttrClosed > 0 {
		t.onDisconnected(msg)
		return
	}

	if attr&network.AttrHandshakeError > 0 || attr&network.AttrUnverifiedConnection > 0 {
		return
	}

	f, err := t.decodeNetworkMessage(msg)
	if err != nil {
		t.dropPeer(err, msg)
		return
	}
	if f != nil {
		f()
	}
}

func (t *TxDistributor) decodeNetworkMessage(msg *network.Message) (func(), error) {
	mid := MessageId(msg.GetType())
	switch mid {
	case MessageTxDistribute:
		// TODO(thunder): reject large msg; otherwise, attackers may send msgs with large data
		// and make our node OOM.
		txmsg, err := newTxDistributeMessage(msg)
		if err != nil {
			return nil, xerrors.Errorf("receiveTx: failed to decode txDistributeMessage: %w", err)
		}
		return func() {
			t.receiveTx(txmsg, msg)
		}, nil
	case MessageTxTraceRoutes:
		txMsg, err := newTxTraceRoutesMessage(msg)
		if err != nil {
			return nil, xerrors.Errorf(
				"handleTraceRoutes: failed to decode txTraceRoutesMessage: %w", err)
		}
		return func() {
			t.handleTraceRoutes(txMsg, msg)
		}, nil
	case MessageTxTraceRoutesReply:
		reply, err := newTxTraceRoutesReplyMessage(msg)
		if err != nil {
			return nil, xerrors.Errorf(
				"handleTraceRoutesReply:failed to decode txTraceRoutesReplyMessage: %w", err)
		}
		return func() {
			t.handleTraceRoutesReply(reply, msg)
		}, nil
	default:
		// Skip unknown msg.
		logger.Info("[%s] the message type(%d) is unknown", t.loggingId, mid)
	}

	return nil, nil
}

func (t *TxDistributor) peersWithoutTx(hash common.Hash) []*txPeer {
	list := make([]*txPeer, 0, len(t.peers))
	for _, p := range t.peers {
		if p.shouldSendTx && !p.knownTxs.Contains(hash) {
			list = append(list, p)
		}
	}
	return list
}

func (t *TxDistributor) distributeNewTxs(txs []*types.Transaction) {
	var txset = make(map[*txPeer]types.Transactions)

	t.total += len(txs)

	// Broadcast transactions to a batch of peers not knowing about it
	for _, tx := range txs {
		peers := t.peersWithoutTx(tx.Hash())
		for _, peer := range peers {
			txset[peer] = append(txset[peer], tx)
		}
	}

	for peer, txs := range txset {
		peer.asyncSendTransactions(txs)
	}
}

func (t *TxDistributor) evict(txs []*types.Transaction) {
	for _, p := range t.peers {
		p.removeRecord(txs)
	}
}

func (t *TxDistributor) handleEventLoop(msgCh chan *network.Message, stopChan <-chan interface{},
	stoppedChan chan interface{}) {
	ch := make(chan core.NewTxsEvent, 1024)
	sub := t.txpool.SubscribeNewTxsEvent(ch)
	if sub == nil {
		debug.Bug("Cannot subscribe to txs Event")
	}
	defer sub.Unsubscribe()

	evictCh := make(chan core.EvictTxEvent, 1024)
	eSub := t.txpool.SubscribeEvictTxsEvent(evictCh)
	if eSub == nil {
		debug.Bug("Cannot subscribe to txs Event")
	}
	defer eSub.Unsubscribe()

	debugTicker := time.NewTicker(time.Second)

	// NOTE that this will increase the latency about 2 * n millisecond,
	// since we have to propagate the transaction all the way to proposer.
	aggregate := time.NewTicker(10 * time.Millisecond)
	buffer := make([]*types.Transaction, 0, 1024)

	for {
		select {
		case msg := <-msgCh:
			t.handleNetworkMessage(msg)
		case e := <-ch:
			buffer = append(buffer, e.Txs...)
		case s := <-t.sessionChan:
			t.updateSession(s)
		case <-debugTicker.C:
			if t.total > 0 {
				logger.Debug("[%s] Number of transactions received in this second: %d ", t.loggingId, t.total)
				t.total = 0
			}
		case <-aggregate.C:
			if len(buffer) > 0 {
				t.distributeNewTxs(buffer)
				buffer = buffer[:0]
			}
		case e := <-evictCh:
			logger.Debug("[%s] Number of transactions evicted: %d", t.loggingId, len(e.Txs))
			t.evict(e.Txs)
		case f := <-t.funcChan:
			f()
		case <-stopChan:
			for _, p := range t.peers {
				close(p.term)
			}
			close(stoppedChan)
			return
		}
	}
}

func (t *TxDistributor) rateLimitLoop(msgIn, msgOut chan *network.Message, stopCh <-chan interface{}) {
	for {
		select {
		case msg := <-msgIn:
			if msg.HasId() {
				msgid := limiter.MsgId(strconv.Itoa(int(msg.GetType())))
				id := limiter.Id(msg.GetId())
				if !t.msgLimiter.Allow(msgid, id, 1) {
					t.dropPeer(xerrors.New("ratelimitLoop: over rate limit"), msg)
					break
				}
			}
			select {
			case msgOut <- msg:
			default:
				t.dropPeer(xerrors.New("ratelimitLoop: too busy"), msg)
			}
		case <-stopCh:
			logger.Info("[%s] rate limit loop closed", t.loggingId)
			return
		}
	}
}

func (t *TxDistributor) addTxLoop(txCh chan []*types.Transaction, stopChan <-chan interface{}) {
	for {
		select {
		case txs := <-txCh:
			t.txpool.AddRemotes(txs)
		case <-stopChan:
			logger.Info("[%s] add tx loop closed", t.loggingId)
			return
		}
	}
}

func (t *TxDistributor) dropPeer(err error, msg *network.Message) {
	logger.Warn("[%s] drop connection: err=%s; msg (id=%s) msg type=(%d)",
		t.loggingId, err, msg.GetId(), msg.GetType())
	msg.CloseConnection()
}

func (t *TxDistributor) updateSession(session blockchain.Session) {
	logger.Info("[%s] update Session %d -> %d", t.loggingId, t.currentSession, session)
	t.currentSession = session
	for _, p := range t.peers {
		shouldSendTxNow := t.router.ShouldSend(p.verifiedId, session)
		if p.shouldSendTx != shouldSendTxNow {
			if shouldSendTxNow {
				// switch from NO to YES. Do the initial sync.
				logger.Info("[%s] %q changed from should not send tx to should send tx.",
					t.loggingId, p.verifiedId)
				t.sendPendingTxs(p)
			} else {
				logger.Info("[%s] %q changed from should send tx to should not send tx.",
					t.loggingId, p.verifiedId)
			}

			p.shouldSendTx = shouldSendTxNow
		}
	}
}

func (t *TxDistributor) sendPendingTxs(p *txPeer) {
	var txs types.Transactions
	pending, _ := t.txpool.Pending(false)
	for _, batch := range pending {
		txs = append(txs, batch...)
	}

	if len(txs) > 0 {
		logger.Info("[%s] initsync to %q", t.loggingId, p.verifiedId)
		// TODO(thunder): after we reject large msgs in receiveTx, segment txs into small chunks
		// and limit the sending rate; otherwise, the receiver will drop the connection
		// due to either a large msg or excedding the rate limit.
		p.asyncSendTransactions(txs)
	}
}

// Start starts the go routine to handle event.
func (t *TxDistributor) Start() error {
	t.peers = make(map[ConsensusId]*txPeer)
	t.txCh = make(chan []*types.Transaction, msgCountPerSecond*maxConnection)

	stoppedChan := make(chan interface{})
	action := func(stopChan chan interface{}) error {
		go t.addTxLoop(t.txCh, stopChan)

		msgCh := make(chan *network.Message, msgCountPerSecond*maxConnection)
		go t.rateLimitLoop(t.messageChan, msgCh, stopChan)

		go t.handleEventLoop(msgCh, stopChan, stoppedChan)
		return nil
	}
	return t.StartStopWaiterImpl.Start(action, stoppedChan)
}

// UpdateSession expects to be called by reconfigurer.
func (t *TxDistributor) UpdateSession(session blockchain.Session) {
	t.sessionChan <- session
}

// Always use addPeer/removePeer* when modifying t.peers to ensure consistency
func (t *TxDistributor) addPeer(p *txPeer, shouldSendTx bool) {
	if _, ok := t.peers[p.verifiedId]; ok {
		logger.Error("peer with id '%s' already exists, removing it", p.verifiedId)
		t.removePeerById(p.verifiedId)
	}
	t.peers[p.verifiedId] = p

	p.term = make(chan struct{})
	p.shouldSendTx = shouldSendTx
	logger.Note("[%s] Started sending goroutine for peer %q", p.loggingId, p.verifiedId)
	go p.keepSending()
}

func (t *TxDistributor) removePeerById(id ConsensusId) {
	peer, ok := t.peers[id]
	delete(t.peers, id)
	if ok {
		close(peer.term)
	}
}

func (t *TxDistributor) TraceRoutes() {
	logger.Info("[%s] TraceRoutes", t.loggingId)
	t.routeLogsMutex.Lock()
	defer t.routeLogsMutex.Unlock()

	f := func() {
		txMsg := &txTraceRoutesMessage{
			HopLimit: 10,
			Sources:  []ConsensusId{t.myId},
		}
		msg := txMsg.toNetworkMessage()

		for _, p := range t.peers {
			logger.Info("[%s] send trace tx route msg to %s? %t",
				t.loggingId, p.verifiedId, p.shouldSendTx)
			if p.shouldSendTx {
				p.asyncSendMsg(msg)
			}
		}
	}

	select {
	case t.funcChan <- f:
	default:
		logger.Warn("[%s] skip TraceRoutes because funcChan is full", t.loggingId)
	}
}

func (t *TxDistributor) GetAliveRoutes() []*TxRouteLog {
	t.clearOutOfDateTxRoutes()

	t.routeLogsMutex.Lock()
	defer t.routeLogsMutex.Unlock()
	var logs []*TxRouteLog
	for _, v := range t.routeLogs {
		logs = append(logs, v.Clone())
	}

	return logs
}
