package consensus

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	oldMetrics "github.com/ethereum/go-ethereum/thunder/thunderella/libs/analytics/metrics"

	"golang.org/x/xerrors"
)

type rpcRequest struct {
	name     string
	args     []interface{}
	response chan rpcResponse
}

type rpcResponse struct {
	result interface{}
	err    error
}

type shortName string

// RpcStatus must be public; otherwise, the RPC caller cannot get the values using reflection.
type RpcStatus struct {
	MyEpoch                 string
	MyFreshestNotarizedHead string
	MyFinalizedHead         string
	MyHeight                uint64
	NVoteInLastBlock        uint16
	Proposers               map[shortName]NodeStatus
	Voters                  map[shortName]NodeStatus
	Bootnodes               map[shortName]NodeStatus
	Fullnodes               map[shortName]NodeStatus
}

type NodeStatus struct {
	Identity              ConsensusId
	Epoch                 string
	FreshestNotarizedHead string
	NodeVersion           string
	BlockHeight           uint64
	Address               string
}

// filterVotedVoterIds returns the voterIds which filter only voted successfully
func filterVotedVoterIds(missingVoterIdxs []uint16, allVoters []ConsensusId) []ConsensusId {
	var voterIds []ConsensusId
	missingVoterSet := make(map[uint16]bool)
	for _, v := range missingVoterIdxs {
		missingVoterSet[v] = true
	}
	for i := uint16(0); i < uint16(len(allVoters)); i++ {
		if _, ok := missingVoterSet[i]; !ok {
			voterIds = append(voterIds, allVoters[i])
		}
	}
	return voterIds
}

// getCommInfoProposerIds returns CommInfo's proposerIds
func getCommInfoProposerIds(commInfo *committee.CommInfo) []ConsensusId {
	ids := []ConsensusId{}
	for _, proposer := range commInfo.AccelInfo {
		ids = append(ids, blockchain.ConsensusIdFromPubKey(proposer.PubVoteKey))
	}
	return ids
}

// getCommInfoVoterIds returns CommInfo's voterIds
func getCommInfoVoterIds(commInfo *committee.CommInfo) []ConsensusId {
	ids := []ConsensusId{}
	for _, voter := range commInfo.MemberInfo {
		ids = append(ids, blockchain.ConsensusIdFromPubKey(voter.PubVoteKey))
	}
	return ids
}

// Called in the handleEventLoop goroutine.
func (m *Mediator) handleRpcRequest(r rpcRequest) {
	switch r.name {
	case "GetStatus":
		s := RpcStatus{}
		epoch := m.epochManager.GetEpoch()
		s.MyEpoch = epoch.String()
		headInfo := m.chain.GetFreshestNotarizedHeadInfo()
		s.MyFreshestNotarizedHead = headInfo.Sn.String()
		s.MyFinalizedHead = m.chain.GetFinalizedHead().GetBlockSn().String()
		s.MyHeight = headInfo.Number
		nota := m.chain.GetNotarization(headInfo.Sn)
		if nota != nil {
			s.NVoteInLastBlock = nota.GetNVote()
		}
		// Fill all roles' status.
		s.Proposers = make(map[shortName]NodeStatus)
		s.Voters = make(map[shortName]NodeStatus)
		s.Bootnodes = make(map[shortName]NodeStatus)
		s.Fullnodes = make(map[shortName]NodeStatus)
		ps := m.syncer.GetPeersStatus()
		for id, status := range ps {
			isFullnode := true
			if m.role.IsProposer(id, epoch.Session) {
				isFullnode = false
				s.Proposers[shortName(m.role.GetShortName(id))] = NodeStatus{
					Identity:              id,
					Epoch:                 status.Epoch.String(),
					FreshestNotarizedHead: status.FncBlockSn.String(),
					Address:               m.host.GetAddress(id),
					BlockHeight:           status.BlockHeight,
					NodeVersion:           status.NodeVersion,
				}
			}
			if m.role.IsVoter(id, epoch.Session) {
				isFullnode = false
				s.Voters[shortName(m.role.GetShortName(id))] = NodeStatus{
					Identity:              id,
					Epoch:                 status.Epoch.String(),
					FreshestNotarizedHead: status.FncBlockSn.String(),
					Address:               m.host.GetAddress(id),
					BlockHeight:           status.BlockHeight,
					NodeVersion:           status.NodeVersion,
				}
			}
			if m.role.IsBootnode(id) {
				isFullnode = false
				s.Bootnodes[shortName(m.role.GetShortName(id))] = NodeStatus{
					Identity:              id,
					Epoch:                 status.Epoch.String(),
					FreshestNotarizedHead: status.FncBlockSn.String(),
					Address:               m.host.GetAddress(id),
					BlockHeight:           status.BlockHeight,
					NodeVersion:           status.NodeVersion,
				}
			}
			if isFullnode {
				s.Fullnodes[shortName(m.role.GetShortName(id))] = NodeStatus{
					Identity:              id,
					Epoch:                 status.Epoch.String(),
					FreshestNotarizedHead: status.FncBlockSn.String(),
					Address:               m.host.GetAddress(id),
					BlockHeight:           status.BlockHeight,
					NodeVersion:           status.NodeVersion,
				}
			}
		}
		r.response <- rpcResponse{result: s, err: nil}
	case "GetMetrics":
		met := make(map[string]interface{})
		obj := &m.palaMetrics
		objType := reflect.TypeOf(obj)
		structType := objType.Elem()
		structValue := reflect.ValueOf(obj).Elem()
		numFields := structType.NumField()
		roles := GetRoles(m.role, m.epochManager)
		filter := m.palaMetrics.GetMetricsFilter(roles)
		for i := 0; i < numFields; i++ {
			name := structValue.Type().Field(i).Name
			if filter[name] {
				met[name] = structValue.Field(i).Interface()
			}
		}
		// these are metrics created by legacy components(txpool, bidder)
		for _, v := range oldMetrics.GetMetricsAsList() {
			met[strings.TrimPrefix(v.Name(), "Thunder_")] = v.Get()
		}
		r.response <- rpcResponse{result: met, err: nil}
	case "GetTxPoolStatus":
		r.response <- rpcResponse{result: m.chain.GetTxPoolStatus(), err: nil}
	case "GetCommInfo":
		s := r.args[0].(uint32)
		session := blockchain.Session(s)
		r.response <- rpcResponse{result: m.chain.GetCommInfo(session), err: nil}
	case "GetCommInfoByNumber":
		seq := r.args[0].(int64)
		h := m.chain.GetHeaderByNumber(uint64(seq))
		if h == nil {
			r.response <- rpcResponse{result: nil, err: xerrors.Errorf("Invalid chain sequence")}
			return
		}
		session := h.GetBlockSn().Epoch.Session
		r.response <- rpcResponse{result: m.chain.GetCommInfo(session), err: nil}
	case "SetHead":
		newHead := r.args[0].(uint64)
		if newHead < 1 {
			r.response <- rpcResponse{err: xerrors.Errorf("height must >= 1")}
			return
		}
		m.chain.SetHead(newHead)
		r.response <- rpcResponse{err: nil}
		// Note that Stop() is async. We must stop now to avoid any new update after SetHead().
		m.stopNow()
	case "IsReadyForService":
		minHeightDiff := r.args[0].(uint64)
		result, err := isReadyForService(m, minHeightDiff)
		r.response <- rpcResponse{result: result, err: err}
	case "GetReward":
		seq := r.args[0].(int64)
		result, err := m.chain.GetReward(uint64(seq))
		r.response <- rpcResponse{result: result, err: err}
	case "TraceTxRoute":
		m.txDistributor.TraceRoutes()
		r.response <- rpcResponse{}
	case "GetBlockSnByNumber":
		n := r.args[0].(uint64)
		h := m.chain.GetHeaderByNumber(n)
		if h == nil {
			err := xerrors.Errorf("failed to get header for height=%d", n)
			r.response <- rpcResponse{result: nil, err: err}
		} else {
			r.response <- rpcResponse{result: h.GetBlockSn().String(), err: nil}
		}

	case "GetBlockInfo":
		resp, err := m.getBlockInfo(r.args[0].(rpc.BlockNumber))
		r.response <- rpcResponse{result: resp, err: err}

	case "GetNumberByBlockSn":
		session := r.args[0].(uint32)
		epoch := r.args[1].(uint32)
		s := r.args[2].(uint32)
		sn := blockchain.NewBlockSn(session, epoch, s)
		h := m.chain.GetHeader(sn)
		if h == nil {
			err := xerrors.Errorf("failed to get header for %s", sn)
			r.response <- rpcResponse{result: nil, err: err}
		} else {
			r.response <- rpcResponse{result: h.GetNumber(), err: nil}
		}
	case "GetTtTransfersByBlockNumber":
		number := r.args[0].(uint64)
		res, err := m.chain.(*blockchain.BlockChainImpl).GetTtTransfersByBlockNumber(number)
		if err != nil {
			r.response <- rpcResponse{result: nil, err: err}
		} else {
			r.response <- rpcResponse{result: res, err: nil}
		}

	case "GetPalaMetaForSnapshot":
		res, err := m.chain.(*blockchain.BlockChainImpl).GetPalaMetaForSnapshot()
		if err != nil {
			r.response <- rpcResponse{result: nil, err: err}
		} else {
			r.response <- rpcResponse{result: res, err: nil}
		}

	case "GetTrieStateForSnapshot":
		keys := []common.Hash{}
		for _, arg := range r.args {
			keys = append(keys, arg.(common.Hash))
		}
		res, err := m.chain.(*blockchain.BlockChainImpl).GetTrieStateForSnapshot(keys)
		if err != nil {
			r.response <- rpcResponse{result: nil, err: err}
		} else {
			r.response <- rpcResponse{result: res, err: nil}
		}

	case "GetTtBlockForSnapshot":
		res, err := m.chain.(*blockchain.BlockChainImpl).GetTtBlockForSnapshot(r.args[0].(uint64))
		if err != nil {
			r.response <- rpcResponse{result: nil, err: err}
		} else {
			r.response <- rpcResponse{result: res, err: nil}
		}

	case "GetTotalSupply":
		res, err := m.chain.(*blockchain.BlockChainImpl).GetTotalSupply(r.args[0].(rpc.BlockNumber))
		r.response <- rpcResponse{result: res, err: err}

	case "GetTotalInflation":
		res, err := m.chain.(*blockchain.BlockChainImpl).GetTotalInflation(r.args[0].(rpc.BlockNumber))
		r.response <- rpcResponse{result: res, err: err}

	case "GetTotalFeeBurned":
		res, err := m.chain.(*blockchain.BlockChainImpl).GetTotalFeeBurned(r.args[0].(rpc.BlockNumber))
		r.response <- rpcResponse{result: res, err: err}

	case "GetSessionStatus":
		res, err := m.getSessionStatus(r.args[0].(uint32))
		r.response <- rpcResponse{result: res, err: err}

	case "GetBidStatus":
		res, err := m.chain.(*blockchain.BlockChainImpl).GetBidStatus(r.args[0].(rpc.BlockNumber))
		r.response <- rpcResponse{result: res, err: err}

	default:
		msg := fmt.Sprintf("unknown RPC request %s (args=%s)", r.name, r.args)
		logger.Warn("[%s] %s", m.loggingId, msg)
		r.response <- rpcResponse{result: nil, err: xerrors.New(msg)}
	}
}

// isReadyForService returns whether a Thunder Bootnode or Fullnode is ready to be exposed
// to external users.
// If a Bootnode or Fullnode is exposed too early and their chain is their behind connected peers:
// 1. External chain-sync users might mistakenly think that they have already caught up with chain progress
// 2. External transaction transport service and JSON-RPC API users might mistakenly think their transactions are executable when they're not or vice versa.
//
// Behavior:
// * Proposer/Voter: always ready to be exposed.
// * Fullnode: ready if my freshest notarized head is close, i.e. within `minHeightDiff` to my connected peers
// * Bootnode: ready if my freshest notarized head is close to my connected peers and at
//   least one peer is a Proposer or Bootnode.
func isReadyForService(m *Mediator, minHeightDiff uint64) (bool, error) {
	session := m.epochManager.GetEpoch().Session
	if m.role.IsProposer(UseMyId, session) {
		logger.Info("[%s] isReadyForService: proposers are always ready for service",
			m.loggingId)
		return true, nil
	}
	if m.role.IsVoter(UseMyId, session) {
		logger.Info("[%s] isReadyForService: voters are always ready for service",
			m.loggingId)
		return true, nil
	}

	ps := m.syncer.GetPeersStatus()
	if len(ps) == 0 {
		return false, xerrors.New("no connected peers")
	}

	mine := m.chain.GetFreshestNotarizedHeadSn()
	var nb, np int
	for id, s := range ps {
		if m.role.IsProposer(id, session) {
			np++
		}
		if m.role.IsBootnode(id) {
			nb++
		}
		if mine.Compare(s.FncBlockSn) < 0 {
			if mine.Epoch.Compare(s.FncBlockSn.Epoch) < 0 ||
				mine.S+uint32(minHeightDiff) < s.FncBlockSn.S {
				return false, xerrors.Errorf("freshest notarized head %s is behind peer %q (%s)",
					mine, id, s.FncBlockSn)
			}
		}
	}
	if m.role.IsBootnode(UseMyId) {
		if nb+np <= 0 {
			return false, xerrors.New("I'm a bootnode but none of my connected peeers are bootnodes or proposers")
		} else {
			logger.Info("[%s] isReadyForService: bootnode ready for service (peers: %d proposers, %d bootnodes)",
				m.loggingId, np, nb)
			return true, nil
		}
	}
	logger.Info("[%s] isReadyForService: fullnode ready for service (peers: %d)", m.loggingId, len(ps))
	return true, nil
}

func GetRoles(r RoleAssigner, e blockchain.EpochManager) []string {
	s := e.GetEpoch().Session
	roles := make([]string, 0)
	if r.IsVoter(UseMyId, s) {
		roles = append(roles, "voter")
	}
	if r.IsProposer(UseMyId, s) {
		roles = append(roles, "proposer")
	}
	if r.IsBootnode(UseMyId) {
		roles = append(roles, "bootnode")
	}
	return roles
}

//
// Implement thunder.RpcDelegate - begin
//

func (m *Mediator) GetStatus() (interface{}, error) {
	ch := make(chan rpcResponse)
	m.selfChan <- rpcRequest{
		name:     "GetStatus",
		response: ch,
	}

	r := <-ch
	return r.result, r.err
}

func (m *Mediator) GetMetrics() (interface{}, error) {
	ch := make(chan rpcResponse)
	m.selfChan <- rpcRequest{
		name:     "GetMetrics",
		response: ch,
	}

	r := <-ch
	return r.result, r.err
}

func (m *Mediator) GetTxPoolStatus() (interface{}, error) {
	ch := make(chan rpcResponse)
	m.selfChan <- rpcRequest{
		name:     "GetTxPoolStatus",
		response: ch,
	}

	r := <-ch
	return r.result, r.err
}

func (m *Mediator) GetCommInfo(session uint32) (interface{}, error) {
	ch := make(chan rpcResponse)
	m.selfChan <- rpcRequest{
		name:     "GetCommInfo",
		args:     []interface{}{session},
		response: ch,
	}
	r := <-ch
	return r.result, r.err
}

func (m *Mediator) GetCommInfoByNumber(number int64) (interface{}, error) {
	ch := make(chan rpcResponse)
	m.selfChan <- rpcRequest{
		name:     "GetCommInfoByNumber",
		args:     []interface{}{number},
		response: ch,
	}
	r := <-ch
	return r.result, r.err
}

func (m *Mediator) SetHead(number uint64) error {
	ch := make(chan rpcResponse)
	m.selfChan <- rpcRequest{
		name:     "SetHead",
		args:     []interface{}{number},
		response: ch,
	}

	r := <-ch
	return r.err
}

func (m *Mediator) IsReadyForService(minHeightDiff uint64) (interface{}, error) {
	ch := make(chan rpcResponse)
	m.selfChan <- rpcRequest{
		name:     "IsReadyForService",
		args:     []interface{}{minHeightDiff},
		response: ch,
	}

	r := <-ch
	return r.result, r.err
}

func (m *Mediator) GetReward(number int64) (interface{}, error) {
	ch := make(chan rpcResponse)
	m.selfChan <- rpcRequest{
		name:     "GetReward",
		args:     []interface{}{number},
		response: ch,
	}
	r := <-ch
	return r.result, r.err
}

func (m *Mediator) TraceTxRoute(waitingSeconds uint8) (interface{}, error) {
	if m.txDistributor == nil {
		return "do not support transfering txs", nil
	}

	ch := make(chan rpcResponse)
	m.selfChan <- rpcRequest{
		name:     "TraceTxRoute",
		args:     nil,
		response: ch,
	}

	r := <-ch
	if r.err != nil {
		return nil, r.err
	}

	time.Sleep(time.Duration(waitingSeconds) * time.Second)
	logs := m.txDistributor.GetAliveRoutes()
	for _, log := range logs {
		for i := range log.Route {
			log.Route[i].ShortName = m.role.GetShortName(log.Route[i].Id)
		}
	}
	return logs, nil
}

func (m *Mediator) GetBlockSnByNumber(number uint64) (interface{}, error) {
	ch := make(chan rpcResponse)
	m.selfChan <- rpcRequest{
		name:     "GetBlockSnByNumber",
		args:     []interface{}{number},
		response: ch,
	}
	r := <-ch
	return r.result, r.err
}

func (m *Mediator) getSessionStatus(session uint32) (interface{}, error) {
	type block struct {
		BlockSn string
		Height  uint64
	}
	type respSessionStatus struct {
		StartBlock block
		StopBlock  block
		EndBlock   block
		K          uint32
	}
	resp := respSessionStatus{}
	// update K value
	status := m.chain.(*blockchain.BlockChainImpl).GetSessionParams(session)
	resp.K = status.K

	// update start block info
	sessionStartBlockSn := blockchain.NewBlockSn(session, 1, 1)
	sessionStartBlock := m.chain.GetBlock(sessionStartBlockSn)
	if sessionStartBlock == nil {
		return nil, xerrors.Errorf("failed to get session status for %v", session)
	}
	resp.StartBlock = block{
		BlockSn: sessionStartBlockSn.String(),
		Height:  sessionStartBlock.GetNumber(),
	}

	// update end block info
	nextSessionStartBlockSn := blockchain.NewBlockSn(session+1, 1, 1)
	nextSessionStartBlock := m.chain.GetBlock(nextSessionStartBlockSn)

	// current session end block is not Finalized
	if nextSessionStartBlock == nil {
		resp.EndBlock = block{
			BlockSn: m.chain.GetFinalizedHeadSn().String(),
			Height:  m.chain.GetFinalizedHead().GetNumber(),
		}
		return resp, nil
	}
	// normal case
	resp.EndBlock = block{
		BlockSn: nextSessionStartBlock.GetParentBlockSn().String(),
		Height:  nextSessionStartBlock.GetNumber() - 1,
	}

	// update stop block
	sessionStopblock := m.chain.GetBlockByNumber(sessionStartBlock.GetNumber() + uint64(status.StopBlockSessionOffset) - 1)
	resp.StopBlock = block{
		BlockSn: sessionStopblock.GetBlockSn().String(),
		Height:  sessionStopblock.GetNumber(),
	}
	return resp, nil
}

func (m *Mediator) getBlockInfo(number rpc.BlockNumber) (interface{}, error) {
	var b blockchain.Block
	if number == rpc.LatestBlockNumber {
		b = m.chain.GetFreshestNotarizedHead()
	} else {
		b = m.chain.GetBlockByNumber(uint64(number.Int64()))
	}
	if b == nil {
		return nil, xerrors.Errorf("Invalid chain sequence")
	}
	type commInfo struct {
		ProposerIds []ConsensusId
		VoterIds    []ConsensusId
	}
	type notarization struct {
		VoterIds []ConsensusId
		BlockSn  string
	}
	type respBlockInfo struct {
		BlockSn         string
		SessionCommInfo commInfo
		Notarizations   []notarization
	}
	resp := respBlockInfo{}
	mapSessionCommVoters := map[blockchain.Session][]blockchain.ConsensusId{}

	// get current status: BlockSn and CommInfo
	resp.BlockSn = b.GetBlockSn().String()
	currentSession := b.GetBlockSn().Epoch.Session
	currSessionComminfo := m.chain.GetCommInfo(currentSession)
	resp.SessionCommInfo = commInfo{
		ProposerIds: getCommInfoProposerIds(currSessionComminfo),
		VoterIds:    getCommInfoVoterIds(currSessionComminfo),
	}
	mapSessionCommVoters[currentSession] = resp.SessionCommInfo.VoterIds

	// get notarizations
	notas, _ := m.chain.DecodeBlock(b)
	for _, nota := range notas {
		session := nota.GetBlockSn().Epoch.Session
		// notarization's session may not the same as current block.
		// So, it need to query correct Committee's voters or get from cache
		var commVoteIds []blockchain.ConsensusId
		if _, ok := mapSessionCommVoters[session]; !ok {
			mapSessionCommVoters[session] = getCommInfoVoterIds(m.chain.GetCommInfo(session))
		}
		commVoteIds = mapSessionCommVoters[session]

		resp.Notarizations = append(resp.Notarizations, notarization{
			BlockSn:  nota.GetBlockSn().String(),
			VoterIds: filterVotedVoterIds(nota.GetMissingVoterIdxs(), commVoteIds),
		})
	}

	return resp, nil
}

func (m *Mediator) GetBlockInfo(number rpc.BlockNumber) (interface{}, error) {
	ch := make(chan rpcResponse)
	m.selfChan <- rpcRequest{
		name:     "GetBlockInfo",
		args:     []interface{}{number},
		response: ch,
	}
	r := <-ch
	return r.result, r.err
}

func (m *Mediator) GetNumberByBlockSn(session, epoch, s uint32) (interface{}, error) {
	ch := make(chan rpcResponse)
	m.selfChan <- rpcRequest{
		name:     "GetNumberByBlockSn",
		args:     []interface{}{session, epoch, s},
		response: ch,
	}
	r := <-ch
	return r.result, r.err
}

func (m *Mediator) GetTtTransfersByBlockNumber(number uint64) (interface{}, error) {
	ch := make(chan rpcResponse)
	m.selfChan <- rpcRequest{
		name:     "GetTtTransfersByBlockNumber",
		args:     []interface{}{number},
		response: ch,
	}
	r := <-ch
	return r.result, r.err
}

func (m *Mediator) GetPalaMetaForSnapshot() (interface{}, error) {
	ch := make(chan rpcResponse)
	m.selfChan <- rpcRequest{
		name:     "GetPalaMetaForSnapshot",
		args:     nil,
		response: ch,
	}
	r := <-ch
	return r.result, r.err
}
func (m *Mediator) GetTrieStateForSnapshot(keys []common.Hash) (interface{}, error) {
	args := make([]interface{}, len(keys))
	for i, key := range keys {
		args[i] = key
	}
	ch := make(chan rpcResponse)
	m.selfChan <- rpcRequest{
		name:     "GetTrieStateForSnapshot",
		args:     args,
		response: ch,
	}
	r := <-ch
	return r.result, r.err
}

func (m *Mediator) GetTtBlockForSnapshot(number uint64) (interface{}, error) {
	ch := make(chan rpcResponse)
	m.selfChan <- rpcRequest{
		name:     "GetTtBlockForSnapshot",
		args:     []interface{}{number},
		response: ch,
	}
	r := <-ch
	return r.result, r.err
}

func (m *Mediator) GetTotalSupply(number rpc.BlockNumber) (interface{}, error) {
	ch := make(chan rpcResponse)
	m.selfChan <- rpcRequest{
		name:     "GetTotalSupply",
		args:     []interface{}{number},
		response: ch,
	}
	r := <-ch
	return r.result, r.err
}

func (m *Mediator) GetTotalInflation(number rpc.BlockNumber) (interface{}, error) {
	ch := make(chan rpcResponse)
	m.selfChan <- rpcRequest{
		name:     "GetTotalInflation",
		args:     []interface{}{number},
		response: ch,
	}
	r := <-ch
	return r.result, r.err
}

func (m *Mediator) GetTotalFeeBurned(number rpc.BlockNumber) (interface{}, error) {
	ch := make(chan rpcResponse)
	m.selfChan <- rpcRequest{
		name:     "GetTotalFeeBurned",
		args:     []interface{}{number},
		response: ch,
	}
	r := <-ch
	return r.result, r.err
}

func (m *Mediator) GetSessionStatus(session uint32) (interface{}, error) {
	ch := make(chan rpcResponse)
	m.selfChan <- rpcRequest{
		name:     "GetSessionStatus",
		args:     []interface{}{session},
		response: ch,
	}
	r := <-ch
	return r.result, r.err
}

func (m *Mediator) GetBidStatus(bn rpc.BlockNumber) (interface{}, error) {
	ch := make(chan rpcResponse)
	m.selfChan <- rpcRequest{
		name:     "GetBidStatus",
		args:     []interface{}{bn},
		response: ch,
	}
	r := <-ch
	return r.result, r.err
}

//
// Implement thunder.RpcDelegate - end
//
