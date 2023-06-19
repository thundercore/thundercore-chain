// TODO(thunder): [R3] Optimization for syncing:
// * Adding another class "Prefetcher" to prefetch blocks in parallel
//   and let ChainSyncer fill the gap to the prefetched data.

package chainsync

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/types"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"golang.org/x/xerrors"
)

type ConsensusId = types.ConsensusId

var ConsensusIds = types.ConsensusIds

var logger = lgr.NewLgr("/chainsync")

// ChainSyncer is a state machine without its own goroutine.
//
// Behaviors:
// * It is responsible to determine the sources to send requests.
// * It sends at most one request within a period.
//
// The caller of ChainSyncer is responsible to:
// * Collect the status of peers and itself and notify ChainSyncer.
// * Call ChainSyncer periodically (e.g., call DoSomethingIfNeeded()) to ensure there is progress.
//
// TODO(thunder): [R3] Reliability for ChainSyncer:
// * Verify whether the peer is honest and fetch data from honest peers.
//
// Important design notes:
// * We need to periodically check whether to do something to ensure there is progress.
//   At first, one may think adding a worker goroutine. However, this makes some operations
//   async and inconveniently to use.
//
//   Decision: No worker goroutine. Instead, the caller is responsible to call ChainSyncer periodically.
//
// * Since there may be some byzantine nodes, we cannot trust status from the peers. If we cannot
//   100% trust the peers, how do get correct info of the chain and make useful requests? E.g.,
//   how do we know BlockSn of blocks that we don't have in the freshest notarized chain?
//
//   Decision: we tell the peer our BlockSn from the finalized head to the freshest notarized head.
//   Let the peer decide the response. Since the peer has more info, it knows how to respond us.
//   The idea that "let the peer decide the response" simplifies the flow a lot.
//
// * Optimization: how do we speed up the syncing process without losing the reliability?
//
//   Decision: Keep it simple and stupid. ChainSyncer is the baseline to ensure there is progress.
//   We can add another class "Prefetcher" to fetch new blocks in parallel. As long as ChainSyncer
//   and Prefetcher work independently, the optimization won't affect the reliability. The worst
//   case is that we waste some CPU/network resources.
type ChainSyncer struct {
	mutex     utils.CheckedLock
	loggingId string
	client    ChainSyncerClient
	selector  Selector

	// States related to chain status.
	myStatus                       Status
	peersStatus                    map[ConsensusId]Status
	peerInconsistentFinalizedHeads map[ConsensusId]BlockInfo
	hostAddresses                  map[ConsensusId]string

	// States related to proposals.
	role                         Role
	sentUnnotarizedProposalPeers map[ConsensusId]time.Time
	isPrimaryProposer            bool

	// States related to requests.
	clock            utils.Clock
	maxWaitingPeriod time.Duration
	// The maximum "penalty time" for timeout.
	timeoutToRetryPeriod time.Duration
	blockTimeoutPeers    map[ConsensusId]time.Time
	epochTimeoutPeers    map[ConsensusId]time.Time
	syncingEpochPeer     *requestManager
	syncingBlockPeer     *requestManager

	rpcMaxDelayBlock uint32
	running          bool
}

type ChainSyncerClient interface {
	RequestNotarizedBlocks(id ConsensusId)
	RequestEpoch(id ConsensusId, session blockchain.Session)
	// SendUnnotarizedProposals request the client to send unnotarized proposals to `id`.
	// Note that to simplify the logic in ChainSyncer, `id` may be self and the client
	// should skip the call in such case.
	SendUnnotarizedProposals(id ConsensusId)
}

type Role interface {
	IsVoter(id ConsensusId, session blockchain.Session) bool
	IsReadyToPropose(ids []ConsensusId, session blockchain.Session) bool
	GetShortName(id ConsensusId) string
}

type Config struct {
	LoggingId string
	Client    ChainSyncerClient
	Role      Role
	Clock     utils.Clock
	// The maximum time to wait for a response.
	MaxRequestWaitingPeriod time.Duration
	// The maximum "penalty time" for timeout.
	TimeoutToRetryPeriod time.Duration
	Selector             Selector
	RpcMaxDelayBlock     int64
}

type Selector func(idsInOrder []ConsensusId) ConsensusId

type FinalizedHeadNotFoundError struct {
	peerBegin       BlockIdentifier
	peerEnd         BlockIdentifier
	myFinalizedHead BlockInfo
}

type chainReader interface {
	GetFreshestNotarizedHead() blockchain.Block
	GetFinalizedHead() blockchain.Block
	GetBlock(s blockchain.BlockSn) blockchain.Block
	GetBlockByNumber(n uint64) blockchain.Block
	GetNotarization(s blockchain.BlockSn) blockchain.Notarization
	GetLatestFinalizedStopBlock() blockchain.Block
	GetHeaderByNumber(n uint64) blockchain.Header
	GetRawBlockBody(hash blockchain.Hash) []byte
	GetRawNotarization(s blockchain.BlockSn) []byte
}

type BlockInfo struct {
	BlockIdentifier
	Sn blockchain.BlockSn
}

type BlockIdentifier struct {
	Number uint64
	Hash   blockchain.Hash
}

type NotarizedBlock struct {
	Header    []byte
	BlockBody []byte
	Nota      []byte
}

type requestManager struct {
	id               ConsensusId
	begin            time.Time
	maxWaitingPeriod time.Duration
}

type requestState int

type DebugState struct {
	peersStatus map[ConsensusId]Status
}

type idSorter struct {
	ids []ConsensusId
	by  func(a, b ConsensusId) bool // Closure used in the Less method.
}

//------------------------------------------------------------------------------

const (
	none       = requestState(0)
	requesting = requestState(1)
	timeout    = requestState(2)

	sentUnnotarizedProposalCoolDownPeriod = 10 * time.Second
)

//------------------------------------------------------------------------------

func SelectMax(idsInOrder []ConsensusId) ConsensusId {
	if len(idsInOrder) == 0 {
		return ConsensusId("")
	}
	return idsInOrder[len(idsInOrder)-1]
}

func NewRandomSelector() Selector {
	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s)
	return func(idsInOrder []ConsensusId) ConsensusId {
		if len(idsInOrder) == 0 {
			return ConsensusId("")
		}
		return idsInOrder[r.Intn(len(idsInOrder))]
	}
}

//------------------------------------------------------------------------------

func NewChainSyncer(config Config) *ChainSyncer {
	if config.Selector == nil {
		config.Selector = SelectMax
	}

	s := ChainSyncer{
		loggingId:                      config.LoggingId,
		client:                         config.Client,
		selector:                       config.Selector,
		peersStatus:                    make(map[ConsensusId]Status),
		peerInconsistentFinalizedHeads: make(map[ConsensusId]BlockInfo),
		hostAddresses:                  make(map[ConsensusId]string),
		role:                           config.Role,
		sentUnnotarizedProposalPeers:   make(map[ConsensusId]time.Time),
		clock:                          config.Clock,
		maxWaitingPeriod:               config.MaxRequestWaitingPeriod,
		timeoutToRetryPeriod:           config.TimeoutToRetryPeriod,
		blockTimeoutPeers:              make(map[ConsensusId]time.Time),
		epochTimeoutPeers:              make(map[ConsensusId]time.Time),
		syncingEpochPeer:               &requestManager{maxWaitingPeriod: config.MaxRequestWaitingPeriod},
		syncingBlockPeer:               &requestManager{maxWaitingPeriod: config.MaxRequestWaitingPeriod},
		rpcMaxDelayBlock:               uint32(config.RpcMaxDelayBlock),
		running:                        true,
	}

	return &s
}

func (cs *ChainSyncer) Start() {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	cs.running = true
}

func (cs *ChainSyncer) Stop() {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	cs.running = false
}

func (cs *ChainSyncer) IsReadyToPropose() bool {
	if !cs.isPrimaryProposer {
		return false
	}

	var ids []ConsensusId
	for v, s := range cs.peersStatus {
		if cs.myStatus.FncBlockSn.Compare(s.FncBlockSn) >= 0 {
			ids = append(ids, v)
		}
	}
	return cs.role.IsReadyToPropose(ids, cs.myStatus.Epoch.Session)
}

func (cs *ChainSyncer) GetPeersStatus() map[ConsensusId]Status {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	s := make(map[ConsensusId]Status)
	for k, v := range cs.peersStatus {
		s[k] = v
	}
	return s
}

func (cs *ChainSyncer) GetDebugState() DebugState {
	return DebugState{cs.GetPeersStatus()}
}

// DoSomethingIfNeeded checks if we need to make new requests.
// This is necessary to address the issue that the peer may not respond after a while.
func (cs *ChainSyncer) DoSomethingIfNeeded() {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	if !cs.running {
		return
	}

	logger.Debug("[%s] ChainSyncer.DoSomethingIfNeeded", cs.loggingId)

	cs.requestNextEpochIfNeeded()
	cs.requestNextBlockIfNeeded()
}

func (cs *ChainSyncer) SetMyStatus(s Status) {
	logger.Info("[%s] ChainSyncer.SetMyStatus %s", cs.loggingId, s)

	cs.SetMyEpoch(s.Epoch)
	cs.SetMyFreshestNotarizedHead(s.FncBlockSn)
}

func (cs *ChainSyncer) SetIAmPrimaryProposer(yes bool) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	logger.Info("[%s] ChainSyncer.SetIAmPrimaryProposer %t", cs.loggingId, yes)

	original := cs.isPrimaryProposer
	cs.isPrimaryProposer = yes
	if !original && yes {
		cs.sentUnnotarizedProposalPeers = make(map[ConsensusId]time.Time)
	}
}

func (cs *ChainSyncer) SetPeerStatus(id ConsensusId, s Status) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	if id == "" {
		logger.Warn("[%s] ChainSyncer.SetPeerStatus id is empty")
		return
	}
	logger.Info("[%s] ChainSyncer.SetPeerStatus(id: %q, status: %s, addr: %s)",
		cs.loggingId, cs.getShortName(id), s, cs.getAddress(id))

	if _, ok := cs.peersStatus[id]; !ok {
		// We just have a new connection with the peer.
		// See if we need to send unnotarized proposals.
		cs.sendUnnotarizedProposalsIfNeeded(id)
	}

	cs.peersStatus[id] = s
	if s.Epoch.Compare(cs.myStatus.Epoch) > 0 {
		cs.requestNextEpochIfNeeded()
	}

	if s.FncBlockSn.Compare(cs.myStatus.FncBlockSn) > 0 {
		cs.requestNextBlockIfNeeded()
	}
}

// SetPeerIsInconsistent sets the finalized head of `id` for manually debugging.
// Also, ChainSyncer will not request data from `id`.
func (cs *ChainSyncer) SetPeerIsInconsistent(
	id ConsensusId, finalizedHead BlockInfo) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	logger.Warn("[%s] ChainSyncer.SetPeerIsInconsistent id=%s, finalized head=%s",
		cs.loggingId, cs.getShortName(id), finalizedHead)

	requestingId := cs.syncingBlockPeer.getId()
	if requestingId == "" {
		logger.Warn("[%s] SetPeerIsInconsistent id=%s, but we already have new progress",
			cs.loggingId, cs.getShortName(id))
	} else if requestingId == id {
		cs.syncingBlockPeer.resetId()
	} else {
		logger.Warn("[%s] SetPeerIsInconsistent id=%s, but we are requesting id=%s",
			cs.loggingId, cs.getShortName(id), requestingId)
	}
	cs.peerInconsistentFinalizedHeads[id] = finalizedHead

	cs.requestNextBlockIfNeeded()
}

func (cs *ChainSyncer) SetMyEpoch(e blockchain.Epoch) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	logger.Info("[%s] ChainSyncer.SetMyEpoch %s", cs.loggingId, e)

	if e.Compare(cs.myStatus.Epoch) <= 0 {
		return
	}

	// This is a simplified model. As long as there is any progress,
	// we assumed the target peer responds us. This is closed to the truth
	// since we only requesting at most one peer at a time.
	cs.syncingEpochPeer.resetId()
	cs.myStatus.Epoch = e
	cs.requestNextEpochIfNeeded()
}

func (cs *ChainSyncer) SetMyFreshestNotarizedHead(sn blockchain.BlockSn) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	logger.Info("[%s] ChainSyncer.SetMyFreshestNotarizedHead %s", cs.loggingId, sn)
	if sn.Compare(cs.myStatus.FncBlockSn) <= 0 {
		return
	}

	// This is a simplified model. As long as there is any progress,
	// we assumed the target peer responds us. This is closed to the truth
	// since we only requesting at most one peer at a time.
	cs.syncingBlockPeer.resetId()
	cs.myStatus.FncBlockSn = sn
	cs.requestNextBlockIfNeeded()
}

func (cs *ChainSyncer) SetPeerOffline(id ConsensusId) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	logger.Info("[%s] ChainSyncer.SetPeerOffline %s", cs.loggingId, cs.getShortName(id))

	delete(cs.peersStatus, id)
	delete(cs.hostAddresses, id)
	now := cs.clock.Now()
	if cs.syncingEpochPeer.getId() == id && cs.syncingEpochPeer.check(now) == requesting {
		cs.syncingEpochPeer.resetId()
		cs.requestNextEpochIfNeeded()
	}
	if cs.syncingBlockPeer.getId() == id && cs.syncingBlockPeer.check(now) == requesting {
		cs.syncingBlockPeer.resetId()
		cs.requestNextBlockIfNeeded()
	}
}

func (cs *ChainSyncer) requestNextEpochIfNeeded() {
	cs.mutex.CheckIsLocked("")

	if !cs.running {
		return
	}

	now := cs.clock.Now()
	r := cs.syncingEpochPeer.check(now)

	logger.Debug("[%s] ChainSyncer.requestNextEpochIfNeeded status=%s, request=%s",
		cs.loggingId, cs.myStatus, r)

	switch r {
	case none:
		// Moving forward.
	case requesting:
		// Wait for the result.
		return
	case timeout:
		cs.epochTimeoutPeers[cs.syncingEpochPeer.getId()] = now
		cs.syncingEpochPeer.resetId()
	}

	sorter := &idSorter{}
	for id, r := range cs.peersStatus {
		if !cs.checkAvailable(cs.epochTimeoutPeers, id, now) || cs.myStatus.Epoch.Compare(r.Epoch) >= 0 {
			continue
		}
		sorter.ids = append(sorter.ids, id)
	}
	if len(sorter.ids) == 0 {
		return
	}

	sorter.by = func(a, b ConsensusId) bool {
		return cs.peersStatus[a].Epoch.Compare(cs.peersStatus[b].Epoch) < 0
	}
	sort.Sort(sorter)
	target := cs.selector(sorter.ids)
	if target != "" {
		cs.syncingEpochPeer.setId(target, now)
		cs.mutex.Unlock()
		defer cs.mutex.Lock()
		logger.Info("[%s] ChainSyncerClient.RequestEpoch %s %s",
			cs.loggingId, target, cs.myStatus.Epoch.Session)
		cs.client.RequestEpoch(target, cs.myStatus.Epoch.Session)
	}
}

func (cs *ChainSyncer) requestNextBlockIfNeeded() {
	cs.mutex.CheckIsLocked("")

	if !cs.running {
		return
	}

	now := cs.clock.Now()
	r := cs.syncingBlockPeer.check(now)

	logger.Debug("[%s] ChainSyncer.requestNextBlockIfNeeded status=%s, request=%s",
		cs.loggingId, cs.myStatus, r)

	switch r {
	case none:
		// Moving forward.
	case requesting:
		// Wait for the result.
		return
	case timeout:
		cs.blockTimeoutPeers[cs.syncingBlockPeer.getId()] = now
		cs.syncingBlockPeer.resetId()
	}

	sorter := &idSorter{}
	for id, r := range cs.peersStatus {
		if _, ok := cs.peerInconsistentFinalizedHeads[id]; ok {
			continue
		}
		if !cs.checkAvailable(cs.blockTimeoutPeers, id, now) || cs.myStatus.FncBlockSn.Compare(r.FncBlockSn) >= 0 {
			continue
		}
		sorter.ids = append(sorter.ids, id)
	}
	if len(sorter.ids) == 0 {
		return
	}

	sorter.by = func(a, b ConsensusId) bool {
		return cs.peersStatus[a].FncBlockSn.Compare(cs.peersStatus[b].FncBlockSn) < 0
	}
	sort.Sort(sorter)
	target := cs.selector(sorter.ids)
	if target != ConsensusId("") {
		cs.syncingBlockPeer.setId(target, now)
		cs.mutex.Unlock()
		defer cs.mutex.Lock()
		logger.Info("[%s] ChainSyncerClient.RequestNotarizedBlocks %s",
			cs.loggingId, cs.getShortName(target))
		cs.client.RequestNotarizedBlocks(target)
	}
}

func (cs *ChainSyncer) checkAvailable(peers map[ConsensusId]time.Time, id ConsensusId, now time.Time) bool {
	if begin, ok := peers[id]; ok {
		if now.Sub(begin) >= cs.timeoutToRetryPeriod {
			delete(peers, id)
			return true
		}
		return false
	}
	return true
}

func (cs *ChainSyncer) sendUnnotarizedProposalsIfNeeded(id ConsensusId) {
	cs.mutex.CheckIsLocked("")

	if !cs.isPrimaryProposer || !cs.role.IsVoter(id, cs.myStatus.Epoch.Session) {
		return
	}

	now := cs.clock.Now()
	if begin, ok := cs.sentUnnotarizedProposalPeers[id]; ok {
		if now.Sub(begin) < sentUnnotarizedProposalCoolDownPeriod {
			// Skip to reduce network usage.
			return
		}
	}

	cs.sentUnnotarizedProposalPeers[id] = now

	cs.mutex.Unlock()
	defer cs.mutex.Lock()
	logger.Info("[%s] ChainSyncerClient.SendUnnotarizedProposals %s",
		cs.loggingId, cs.getShortName(id))
	cs.client.SendUnnotarizedProposals(id)
}

func (cs *ChainSyncer) SetHostAddress(id ConsensusId, addr string) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	cs.hostAddresses[id] = addr
}

// Only used internally.
func (cs *ChainSyncer) getAddress(id ConsensusId) string {
	cs.mutex.CheckIsLocked("")

	addr, ok := cs.hostAddresses[id]
	if !ok {
		return "unknown"
	}
	return addr
}

// Only used for logging.
func (cs *ChainSyncer) getShortName(id ConsensusId) string {
	return cs.role.GetShortName(id)
}

func (cs *ChainSyncer) IsBlockChainBehind() bool {
	if len(cs.peersStatus) == 0 {
		return true
	}
	for id, peerStatus := range cs.peersStatus {
		if _, ok := cs.peerInconsistentFinalizedHeads[id]; ok {
			continue
		}
		if peerStatus.Epoch.Compare(cs.myStatus.Epoch) > 0 {
			return true
		}
		if peerStatus.FncBlockSn.Compare(cs.myStatus.FncBlockSn) > 0 &&
			peerStatus.FncBlockSn.S-cs.myStatus.FncBlockSn.S > cs.rpcMaxDelayBlock {
			return true
		}
	}
	return false
}

//------------------------------------------------------------------------------

func NewRequest(reader chainReader) (blockchain.BlockSn, []BlockIdentifier, error) {
	var ids []BlockIdentifier
	begin := reader.GetFinalizedHead()
	beginSn := begin.GetBlockSn()
	stop := reader.GetLatestFinalizedStopBlock()
	if stop != nil {
		sn := stop.GetBlockSn()
		if sn.Epoch.Session == beginSn.Epoch.Session {
			// It's possible that there is a finalize chain fork after the stop block.
			// We need to make the request from the stop block; otherwise, we may fail
			// to sync new blocks.
			begin = stop
			beginSn = sn
		}
	}
	end := reader.GetFreshestNotarizedHead()
	for b := end; ; {
		id := BlockIdentifier{b.GetNumber(), b.GetHash()}
		ids = append(ids, id)
		if b.GetBlockSn() == beginSn {
			break
		}
		psn := b.GetParentBlockSn()
		b = reader.GetBlock(b.GetParentBlockSn())
		if b == nil {
			return blockchain.BlockSn{}, nil, xerrors.Errorf("block %s does not exist", psn)
		}
	}
	return end.GetBlockSn(), ids, nil
}

// FindNextBlocks finds notarized blocks which extend the peer's freshest notarized chain
// if possible.
func FindNextBlocks(
	reader chainReader, peerHead blockchain.BlockSn, request []BlockIdentifier, nExtended int,
) ([]NotarizedBlock, error) {
	// Find common ancestor. `request` is in reverse order.
	var baseHeader blockchain.Header
	for _, id := range request {
		h := reader.GetHeaderByNumber(id.Number)
		if h == nil || h.GetHash() != id.Hash {
			continue
		}
		sn := h.GetBlockSn()
		if sn.IsPala() { // implies !sn.IsGenesis()
			nota := reader.GetRawNotarization(sn)
			if len(nota) == 0 {
				continue
			}
		}
		baseHeader = h
		break
	}

	if baseHeader == nil {
		return nil, NewFinalizedHeadNotFoundError(
			request[len(request)-1], request[0], reader.GetFinalizedHead())
	}

	// Find next blocks which can extend the peer's freshest notarized chain.
	h := baseHeader
	var result []NotarizedBlock
	for {
		h = reader.GetHeaderByNumber(h.GetNumber() + 1)
		if h == nil {
			break
		}
		body := reader.GetRawBlockBody(h.GetHash())
		nota := reader.GetRawNotarization(h.GetBlockSn())
		if len(nota) == 0 {
			break
		}

		result = append(result, NotarizedBlock{
			Header:    h.GetBody(),
			BlockBody: body,
			Nota:      nota,
		})
		if h.GetBlockSn().Compare(peerHead) > 0 {
			nExtended--
			if nExtended == 0 {
				break
			}
		}
	}

	if len(result) == 0 {
		return nil, xerrors.Errorf("no new block after %s", baseHeader.GetBlockSn())
	}
	return result, nil
}

//------------------------------------------------------------------------------

func (r *requestManager) check(now time.Time) requestState {
	if r.id == "" {
		return none
	}
	if now.Sub(r.begin) >= r.maxWaitingPeriod {
		return timeout
	}
	return requesting
}

func (r *requestManager) getId() ConsensusId {
	return r.id
}

func (r *requestManager) setId(id ConsensusId, now time.Time) {
	r.id = id
	r.begin = now
}

func (r *requestManager) resetId() {
	r.id = ""
	r.begin = time.Time{}
}

func (r requestState) String() string {
	switch r {
	case none:
		return "none"
	case requesting:
		return "requesting"
	case timeout:
		return "timeout"
	default:
		return "unknown"
	}
}

//------------------------------------------------------------------------------

func NewBlockIdentifierFromBytes(bytes []byte) (BlockIdentifier, []byte, error) {
	var err error
	var id BlockIdentifier
	id.Number, bytes, err = utils.BytesToUint64(bytes)
	if err != nil {
		return BlockIdentifier{}, nil, err
	}
	if len(bytes) < blockchain.HashLength {
		return BlockIdentifier{}, nil, xerrors.Errorf(
			"illegal format: expect hash length is %d, but received %d",
			blockchain.HashLength, len(bytes))
	}
	id.Hash.SetBytes(bytes[:blockchain.HashLength])
	return id, bytes[blockchain.HashLength:], nil
}

func (bi BlockIdentifier) ToBytes() []byte {
	return append(utils.Uint64ToBytes(bi.Number), bi.Hash.Bytes()...)
}

func (bi BlockIdentifier) String() string {
	return fmt.Sprintf("%d-%s", bi.Number, hex.EncodeToString(bi.Hash[:]))
}

func NewBlockInfoFromBytes(bytes []byte) (BlockInfo, []byte, error) {
	var err error
	var info BlockInfo
	info.BlockIdentifier, bytes, err = NewBlockIdentifierFromBytes(bytes)
	if err != nil {
		return BlockInfo{}, nil, err
	}
	info.Sn, bytes, err = blockchain.NewBlockSnFromBytes(bytes)
	if err != nil {
		return BlockInfo{}, nil, err
	}
	return info, nil, nil
}

func (info BlockInfo) ToBytes() []byte {
	return append(info.BlockIdentifier.ToBytes(), info.Sn.ToBytes()...)
}

func (info BlockInfo) String() string {
	return fmt.Sprintf("%s %s", info.Sn, info.BlockIdentifier)
}

//------------------------------------------------------------------------------

func (e FinalizedHeadNotFoundError) Error() string {
	return fmt.Sprintf("cannot find any common ancestor between %s to %s "+
		"(my finalized head is %s %s)", e.peerBegin, e.peerEnd,
		e.myFinalizedHead.Sn, e.myFinalizedHead.BlockIdentifier)
}

func NewFinalizedHeadNotFoundError(
	peerBegin, peerEnd BlockIdentifier, myFinalizedHead blockchain.Block,
) FinalizedHeadNotFoundError {
	return FinalizedHeadNotFoundError{
		peerBegin: peerBegin,
		peerEnd:   peerEnd,
		myFinalizedHead: BlockInfo{
			BlockIdentifier: BlockIdentifier{
				myFinalizedHead.GetNumber(), myFinalizedHead.GetHash(),
			},
			Sn: myFinalizedHead.GetBlockSn(),
		},
	}
}

func (d DebugState) String() string {
	var sb strings.Builder
	var ids []ConsensusId
	for id := range d.peersStatus {
		ids = append(ids, id)
	}
	ConsensusIds(ids).Sort()
	sb.WriteString("{")
	for _, id := range ids {
		sb.WriteString(string(id) + ":")
		sb.WriteString(d.peersStatus[id].String())
		sb.WriteString(",")
	}
	sb.WriteString("}")

	return sb.String()
}

//------------------------------------------------------------------------------

// Len is part of sort.Interface.
func (s *idSorter) Len() int {
	return len(s.ids)
}

// Swap is part of sort.Interface.
func (s *idSorter) Swap(i, j int) {
	s.ids[i], s.ids[j] = s.ids[j], s.ids[i]
}

// Less is part of sort.Interface.
// It is implemented by calling the "by" closure in the sorter.
func (s *idSorter) Less(i, j int) bool {
	return s.by(s.ids[i], s.ids[j])
}
