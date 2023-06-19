package consensus

import (
	"fmt"
	"math"
	"math/big"
	"path"
	"runtime"
	"sort"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"
)

var roleLogger = logger.NewChildLgr("role_assigner")

type Committee struct {
	members []ConsensusId
}

type CommitteeVoters struct {
	Committee
}

type CommitteeProposers struct {
	Committee
	stakes []*big.Int
}

func (c *Committee) Len() int {
	return len(c.members)
}

func (c *Committee) Find(id ConsensusId) bool {
	return c.Index(id) != -1
}

func (c *Committee) Index(id ConsensusId) int {
	for idx, p := range c.members {
		if p == id {
			return idx
		}
	}
	return -1
}

type RoleAssignerImplCfg struct {
	K                              *config.Int64HardforkConfig
	MyId                           ConsensusId
	IsBootnode                     bool
	SessionProposers               map[blockchain.Session]CommitteeProposers
	SessionVoters                  map[blockchain.Session]CommitteeVoters
	LoggingId                      string
	ElectionStopBlockSessionOffset *config.Int64HardforkConfig
}

type RoleAssignerImpl struct {
	k                              *config.Int64HardforkConfig
	mutex                          utils.CheckedLock
	myId                           ConsensusId
	isBootnode                     bool
	bootnodeShortNames             map[ConsensusId]ConsensusId
	sessionProposers               map[blockchain.Session]CommitteeProposers
	sessionVoters                  map[blockchain.Session]CommitteeVoters
	loggingId                      string
	electionStopBlockSessionOffset *config.Int64HardforkConfig
	epochMaxAllowedSeqs            map[blockchain.Session][]int64
}

func NewRoleAssignerImpl(cfg *RoleAssignerImplCfg) RoleAssigner {
	sessionProposers := cfg.SessionProposers
	if cfg.SessionProposers == nil {
		sessionProposers = make(map[blockchain.Session]CommitteeProposers)
	}
	sessionVoters := cfg.SessionVoters
	if cfg.SessionVoters == nil {
		sessionVoters = make(map[blockchain.Session]CommitteeVoters)
	}
	r := &RoleAssignerImpl{
		k:                              cfg.K,
		myId:                           cfg.MyId,
		isBootnode:                     cfg.IsBootnode,
		bootnodeShortNames:             make(map[ConsensusId]ConsensusId),
		sessionProposers:               sessionProposers,
		sessionVoters:                  sessionVoters,
		loggingId:                      cfg.LoggingId,
		electionStopBlockSessionOffset: cfg.ElectionStopBlockSessionOffset,
		epochMaxAllowedSeqs:            make(map[blockchain.Session][]int64),
	}
	return r
}

func (r *RoleAssignerImpl) IsProposer(id ConsensusId, s blockchain.Session) bool {
	if id == "" {
		function, file, line, _ := runtime.Caller(1)
		caller := fmt.Sprintf("%s:%d %s:", path.Base(file), line, runtime.FuncForPC(function).Name())
		logger.Warn("IsProposer receives empty id (caller: %s)", caller)
		return false
	}

	roleLogger.Debug("[%s] IsProposer(id:%q, session:%d)", r.loggingId, id, s)
	r.mutex.Lock()
	defer r.mutex.Unlock()

	return r.isProposer(id, s)
}

func (r *RoleAssignerImpl) isProposer(id ConsensusId, s blockchain.Session) bool {
	roleLogger.Debug("[%s] isProposer(id:%q, session:%d)", r.loggingId, id, s)
	r.mutex.CheckIsLocked("")

	if id == UseMyId {
		id = r.myId
	}

	ps, ok := r.sessionProposers[s]
	if !ok {
		return false
	}

	return ps.Find(id)
}

func (r *RoleAssignerImpl) IsPrimaryProposer(id ConsensusId, e blockchain.Epoch) bool {
	if id == "" {
		logger.Warn("IsPrimaryProposer receives empty id")
		return false
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	if id == UseMyId {
		id = r.myId
	}

	ps, ok := r.sessionProposers[e.Session]
	if !ok {
		return false
	}

	if idx := ps.Index(id); idx == -1 {
		return false
	} else {
		if uint32(idx) == blockchain.PrimaryProposerIndexer(e, uint32(ps.Len())) {
			return true
		} else {
			return false
		}
	}
}

func (r *RoleAssignerImpl) IsVoter(id ConsensusId, s blockchain.Session) bool {
	if id == "" {
		logger.Warn("IsVoter receives empty id")
		return false
	}

	roleLogger.Debug("[%s] IsVoter(id:%q, session:%d)", r.loggingId, id, s)
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if id == UseMyId {
		id = r.myId
	}

	vs, ok := r.sessionVoters[s]
	if !ok {
		return false
	}
	return vs.Find(id)
}

func (r *RoleAssignerImpl) IsBootnode(id ConsensusId) bool {
	if id == "" {
		logger.Warn("IsBootnode receives empty id")
		return false
	}

	roleLogger.Debug("[%s] IsBootnode(%q)", r.loggingId, id)
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if id == UseMyId || id == r.myId {
		return r.isBootnode
	}

	if _, ok := r.bootnodeShortNames[id]; ok {
		return true
	}
	return false
}

func (r *RoleAssignerImpl) GetMyId() ConsensusId {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	return r.myId
}

func (r *RoleAssignerImpl) AddBootnode(verifiedId, shortName ConsensusId) {
	roleLogger.Debug("[%s] SetBootnodResponseId(verifiedId:%q)", r.loggingId, verifiedId)
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.bootnodeShortNames[verifiedId] = shortName
}

func (r *RoleAssignerImpl) RemoveBootnode(verifiedId ConsensusId) {
	roleLogger.Debug("[%s] RemoveBootnodVerifiedId(%q)", r.loggingId, verifiedId)
	r.mutex.Lock()
	defer r.mutex.Unlock()

	delete(r.bootnodeShortNames, verifiedId)
}

func (r *RoleAssignerImpl) GetNumVoters(s blockchain.Session) int {
	roleLogger.Debug("[%s] GetNumVoters(session:%d)", r.loggingId, s)
	r.mutex.Lock()
	defer r.mutex.Unlock()

	vs, ok := r.sessionVoters[s]
	if !ok {
		return -1
	}

	return vs.Len()
}

func (r *RoleAssignerImpl) GetShortName(id ConsensusId) string {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	var ss []int
	for s := range r.sessionProposers {
		ss = append(ss, int(s))
	}
	sort.Sort(sort.Reverse(sort.IntSlice(ss)))

	// Start from the latest session.
	for _, s := range ss {
		session := blockchain.Session(s)
		ps := r.sessionProposers[session]
		if idx := ps.Index(id); idx != -1 {
			return fmt.Sprintf("session%d-proposer%d", session, idx)
		}

		vs := r.sessionVoters[session]
		if idx := vs.Index(id); idx != -1 {
			return fmt.Sprintf("session%d-voter%d", session, idx)
		}
	}

	for from, to := range r.bootnodeShortNames {
		if id == from {
			return string(to)
		}
	}

	return string(id)
}

func (r *RoleAssignerImpl) GetShortNameMapping() map[string]ConsensusId {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	var ss []int
	for s := range r.sessionProposers {
		ss = append(ss, int(s))
	}

	m := make(map[string]ConsensusId)
	for _, s := range ss {
		session := blockchain.Session(s)
		vs := r.sessionVoters[session]
		for idx, id := range vs.members {
			m[fmt.Sprintf("session%d-voter%d", s, idx)] = id
		}

		ps := r.sessionProposers[session]
		for idx, id := range ps.members {
			m[fmt.Sprintf("session%d-proposer%d", s, idx)] = id
		}
	}

	return m
}

func (r *RoleAssignerImpl) AddSessionCommittee(s blockchain.Session, proposers, voters []ConsensusId, stakes []*big.Int) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	roleLogger.Debug("[%s] AddSessionCommittee(session:%d)", r.loggingId, s)
	r.sessionProposers[s] = CommitteeProposers{
		Committee: Committee{
			members: proposers,
		},
		stakes: stakes,
	}
	r.sessionVoters[s] = CommitteeVoters{
		Committee: Committee{
			members: voters,
		},
	}
}

func (r *RoleAssignerImpl) AddElectionResult(e *blockchain.ElectionResultImpl) {
	roleLogger.Debug("[%s] AddElectionResult(session:%d)", r.loggingId, e.GetSession())
	r.AddSessionCommittee(e.GetSession(), e.GetProposers(), e.GetVoters(), e.GetStakes())
}

func (r *RoleAssignerImpl) CleanupElectionResult(s blockchain.Session) {
	roleLogger.Debug("[%s] CleanupElectionResult(session:%d)", r.loggingId, s)
	r.mutex.Lock()
	defer r.mutex.Unlock()

	for k, _ := range r.sessionProposers {
		if k <= s {
			delete(r.sessionProposers, k)
			delete(r.sessionVoters, k)
		}
	}
}

func (r *RoleAssignerImpl) GetCommitteeProposers(s blockchain.Session) []ConsensusId {
	if proposers, ok := r.sessionProposers[s]; ok {
		return proposers.members
	}
	return []ConsensusId{}
}

func (r *RoleAssignerImpl) GetCommitteeVoters(s blockchain.Session) []ConsensusId {
	if voters, ok := r.sessionVoters[s]; ok {
		return voters.members
	}
	return []ConsensusId{}
}

func (r *RoleAssignerImpl) getStakeList(s blockchain.Session) []*big.Int {
	return r.sessionProposers[s].stakes
}

func (r *RoleAssignerImpl) calculateEpochMaxAllowedSeq(s blockchain.Session, blockNumber uint64) []int64 {
	// We need additional k blocks to finalize stop block,
	// total blocks in this session would be offset + k.
	offset := r.electionStopBlockSessionOffset.GetValueAtSession(int64(s))

	k := r.k.GetValueAtSession(int64(s))
	offset += k

	stakes := r.getStakeList(s)
	totalStake := big.NewInt(0)
	for _, stake := range stakes {
		totalStake.Add(totalStake, stake)
	}

	offsetRat := new(big.Rat).SetInt64(int64(offset))

	epochMaxValidS := []int64{}
	totalSteps := int64(0)
	for i, stake := range stakes {
		// For last proposer, blk_boundary = offset - sum_of_other_proposers_boundary
		if i == len(stakes)-1 {
			epochMaxValidS = append(epochMaxValidS, offset-totalSteps)
			break
		}

		// blk_boundary = (proposer_stake / total_stke) * switch_offset
		ratio := big.NewRat(stake.Int64(), totalStake.Int64())
		blk_boundary, _ := ratio.Mul(ratio, offsetRat).Float64()
		blk := int64(math.Floor(blk_boundary))
		epochMaxValidS = append(epochMaxValidS, blk)
		totalSteps += blk
	}

	return epochMaxValidS
}

func (r *RoleAssignerImpl) updateEpochMaxAllowedSeq(s blockchain.Session, blockNumber uint64) []int64 {
	epochMaxValidS := r.calculateEpochMaxAllowedSeq(s, blockNumber)

	// Update current session
	r.epochMaxAllowedSeqs[s] = epochMaxValidS

	// Clean up previous session
	for k, _ := range r.epochMaxAllowedSeqs {
		if k < s {
			delete(r.epochMaxAllowedSeqs, k)
		}
	}

	return epochMaxValidS
}

func (r *RoleAssignerImpl) ExceedEpochMaxAllowedSeq(sn blockchain.BlockSn, blockNumber uint64) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	epochMaxValidS, ok := r.epochMaxAllowedSeqs[sn.Epoch.Session]
	if !ok {
		epochMaxValidS = r.updateEpochMaxAllowedSeq(sn.Epoch.Session, blockNumber)
	}

	// Only one proposer in this session, we don't need to rotate proposer.
	if len(epochMaxValidS) == 1 {
		return false
	}

	idx := blockchain.PrimaryProposerIndexer(sn.Epoch, uint32(len(epochMaxValidS)))
	roleLogger.Debug("[%s] ExceedEpochMaxAllowedSeq(sn:%v): %v[%v]", r.loggingId, sn, epochMaxValidS, idx)
	return int64(sn.S) > epochMaxValidS[idx]
}
