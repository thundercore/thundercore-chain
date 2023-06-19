package consensus

import (
	"math/big"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/metrics"
	"github.com/ethereum/go-ethereum/thunder/pala/network"
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"

	"golang.org/x/xerrors"
)

const numOfPreservedERs = 2

var reconfLogger = logger.NewChildLgr("reconfigurer")

type ReconfigurerImplCfg struct {
	LoggingId string
}

// ReconfigurerImpl's UpdateXXX function should only be called during reconfiguration
type ReconfigurerImpl struct {
	loggingId string
}

func NewReconfigurerImpl(cfg *ReconfigurerImplCfg) Reconfigurer {
	return &ReconfigurerImpl{
		loggingId: cfg.LoggingId,
	}
}

func (r *ReconfigurerImpl) getNextSession(bc blockchain.BlockChain) blockchain.Session {
	fc := bc.GetFinalizedHead()
	if fc == nil {
		debug.Bug("[%s] Failed to get finalized chain", r.loggingId)
	}

	return fc.GetBlockSn().Epoch.Session + 1
}

func (r *ReconfigurerImpl) getNextElectionResult(bc blockchain.BlockChain) (*blockchain.ElectionResultImpl, error) {
	s := r.getNextSession(bc)
	cInfo := bc.(*blockchain.BlockChainImpl).GetCommInfo(s)
	if cInfo == nil {
		return nil, xerrors.Errorf("[%s] Failed to get CommInfo for session %s", r.loggingId, s)
	}
	return blockchain.NewElectionResultImpl(cInfo, s), nil
}

func (r *ReconfigurerImpl) UpdateVerifier(bc blockchain.BlockChain, verifier blockchain.Verifier) error {
	reconfLogger.Debug("[%s] UpdateVerifier", r.loggingId)
	er, err := r.getNextElectionResult(bc)
	if err != nil {
		return err
	}

	v := verifier.(*blockchain.VerifierImpl)
	v.AddElectionResult(er)
	if er.GetSession() > numOfPreservedERs {
		v.CleanupElectionResult(er.GetSession() - numOfPreservedERs)
	}
	return nil
}

func (r *ReconfigurerImpl) UpdateRoleAssigner(bc blockchain.BlockChain, role RoleAssigner) error {
	reconfLogger.Debug("[%s] UpdateRoleAssigner", r.loggingId)
	er, err := r.getNextElectionResult(bc)
	if err != nil {
		return err
	}

	roleAssigner := role.(*RoleAssignerImpl)
	roleAssigner.AddElectionResult(er)
	if er.GetSession() > numOfPreservedERs {
		roleAssigner.CleanupElectionResult(er.GetSession() - numOfPreservedERs)
	}
	return nil
}

func (r *ReconfigurerImpl) UpdateHost(bc blockchain.BlockChain, host *network.Host, role RoleAssigner, listenAddr string) error {
	// Reference Mediator.connect().
	reconfLogger.Debug("[%s] UpdateHost", r.loggingId)
	session := r.getNextSession(bc)
	nr := NetworkRole(session, role)
	host.SetRole(nr)
	if nr == network.RoleHub {
		if len(listenAddr) == 0 {
			reconfLogger.Error("[%s] Address not given for listening")
		} else if err := host.StartAccepting(listenAddr); err != nil && err.Error() != "already accepting connections" {
			reconfLogger.Error("[%s] Failed to begin accepting connections, err: %s", r.loggingId, err)
		}
	}

	if IsConsensusNode(role, UseMyId, session) {
		addresses := bc.GetProposerAddresses(session)
		for id, addr := range addresses {
			if id == role.GetMyId() || addr == listenAddr ||
				(role.IsProposer(UseMyId, session) && id < role.GetMyId()) {
				delete(addresses, id)
			}
		}
		for id, addr := range addresses {
			reconfLogger.Info("[%s] connect to id:%q addr:%s", r.loggingId, id, addr)
			host.ConnectAsync(id, addr, network.OneInGroup)
		}
	}
	return nil
}

func (r *ReconfigurerImpl) UpdateEpochManager(bc blockchain.BlockChain, em blockchain.EpochManager) error {
	reconfLogger.Debug("[%s] UpdateEpochManager", r.loggingId)
	s := r.getNextSession(bc)
	return em.(*blockchain.EpochManagerImpl).UpdateByReconfiguration(s)
}

func (r *ReconfigurerImpl) UpdateMetrics(bc blockchain.BlockChain, m metrics.PalaMetrics) {
	s := r.getNextSession(bc)
	cInfo := bc.(*blockchain.BlockChainImpl).GetCommInfo(s)
	UpdateElectionResultMetrics(cInfo, m)
}

func (r *ReconfigurerImpl) UpdateSession(bc blockchain.BlockChain, reader SessionReader) {
	reconfLogger.Debug("[%s] UpdateSession", r.loggingId)
	s := r.getNextSession(bc)
	reader.UpdateSession(s)
}

func UpdateElectionResultMetrics(cInfo *committee.CommInfo, m metrics.PalaMetrics) {
	stake := cInfo.Stake()
	thunder, _ := big.NewInt(0).SetString("1000000000000000000", 10) // 1 thunder
	stake = stake.Div(stake, thunder)
	metrics.SetGauge(m.Proposer_CommitteeStake, stake.Int64())
	metrics.SetGauge(m.Proposer_CommitteeSize, int64(cInfo.NumCommittee()))
}
