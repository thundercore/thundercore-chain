// Put the fake implementations used by the production code for the integration test.
package consensus

import (
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/metrics"
	"github.com/ethereum/go-ethereum/thunder/pala/network"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/testutils"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"
)

const (
	// A large value never timeout.
	forever = 10 * 365 * 24 * time.Hour
)

// ActorClientFake implements ActorClient and relays Broadcast and Reply calls to MessageChan
type ActorClientFake struct {
	id          ConsensusId
	MessageChan chan blockchain.Message
	CatchUpChan chan blockchain.BlockSn
}

type ReconfigurerFake struct {
	loggingId       string
	configs         map[blockchain.Session]*ReconfigurationFake
	networkCallback NetworkCallback
}

type ReconfigurationFake struct {
	ProposerList blockchain.ElectionResultFake
	VoterList    blockchain.ElectionResultFake
}

type NetworkCallback func(
	session blockchain.Session, bc blockchain.BlockChain, host *network.Host) error

type TimerFake struct {
	mutex        utils.CheckedLock
	timer        *time.Timer
	ch           chan time.Time
	stopCh       chan interface{}
	currentEpoch blockchain.Epoch
	targetEpoch  blockchain.Epoch
}

//--------------------------------------------------------------------

func NewActorClientFake(id ConsensusId) ActorClient {
	return &ActorClientFake{
		id:          id,
		MessageChan: make(chan blockchain.Message, 1024),
		CatchUpChan: make(chan blockchain.BlockSn, 1024),
	}
}

func (m *ActorClientFake) Broadcast(msg blockchain.Message) {
	logger.Debug("[%s] Broadcast: %T", m.id, msg)
	m.MessageChan <- msg
}

func (m *ActorClientFake) Reply(source *network.Message, msg blockchain.Message) {
	logger.Debug("[%s] Reply: %T (%s)", m.id, msg, source.GetSourceDebugInfo())
	m.MessageChan <- msg
}

func (m *ActorClientFake) CatchUp(source *network.Message, sn blockchain.BlockSn) {
	logger.Debug("[%s] CatchUp: %T %s", m.id, source, sn)
	m.CatchUpChan <- sn
}

func (m *ActorClientFake) UpdateEpoch(cNota blockchain.ClockMsgNota) {
	logger.Debug("[%s] UpdateEpoch: %s", m.id, cNota.GetEpoch())
	m.MessageChan <- cNota
}

//--------------------------------------------------------------------

func NewReconfigurerFake(loggingId string) *ReconfigurerFake {
	return &ReconfigurerFake{
		loggingId: loggingId,
		configs:   make(map[blockchain.Session]*ReconfigurationFake),
		networkCallback: func(
			session blockchain.Session, bc blockchain.BlockChain, host *network.Host,
		) error {
			return nil
		},
	}
}

func (r *ReconfigurerFake) AddReconfiguration(
	session blockchain.Session, config *ReconfigurationFake) {
	r.configs[session] = config
}

func (r *ReconfigurerFake) getConfiguration(session blockchain.Session) *ReconfigurationFake {
	// If the test didn't register a new session, use the latest configuration.
	// This is convenient for tests.
	for s := session; s > 0; s-- {
		if cfg, ok := r.configs[s]; ok {
			return cfg
		}
	}
	return nil
}

func (r *ReconfigurerFake) UpdateVerifier(
	bc blockchain.BlockChain, verifier blockchain.Verifier) error {
	cfg := r.getConfiguration(bc.GetFinalizedHeadSn().Epoch.Session + 1)

	vf := verifier.(*blockchain.VerifierFake)
	vf.AddElectionResult(cfg.ProposerList, cfg.VoterList)
	return nil
}

func (r *ReconfigurerFake) UpdateRoleAssigner(
	bc blockchain.BlockChain, role RoleAssigner) error {
	newSession := bc.GetFinalizedHeadSn().Epoch.Session + 1
	cfg := r.getConfiguration(blockchain.Session(newSession))

	stakes := MakeStakes(len(cfg.ProposerList.GetConsensusIds()), big.NewInt(int64(100)))
	role.(*RoleAssignerImpl).AddSessionCommittee(newSession, cfg.ProposerList.GetConsensusIds(), cfg.VoterList.GetConsensusIds(), stakes)
	return nil
}

func (r *ReconfigurerFake) UpdateHost(
	bc blockchain.BlockChain, host *network.Host, role RoleAssigner, listenAddr string) error {
	session := bc.GetFinalizedHeadSn().Epoch.Session + 1
	return r.networkCallback(session, bc, host)
}

func (r *ReconfigurerFake) UpdateEpochManager(bc blockchain.BlockChain, em blockchain.EpochManager) error {
	e := bc.GetFinalizedHeadSn().Epoch
	return em.(*blockchain.EpochManagerFake).SetEpochDueToReconfiguration(e.NextSession())
}

func (r *ReconfigurerFake) SetNetworkReconfiguration(callback NetworkCallback) {
	r.networkCallback = callback
}

func (r *ReconfigurerFake) UpdateMetrics(bc blockchain.BlockChain, m metrics.PalaMetrics) {
}

func (r *ReconfigurerFake) UpdateSession(bc blockchain.BlockChain, reader SessionReader) {
	b := bc.GetFreshestNotarizedHead()

	reader.UpdateSession(b.GetBlockSn().Epoch.NextSession().Session)
}

//--------------------------------------------------------------------

func NewTimerFake(epoch blockchain.Epoch) Timer {
	t := &TimerFake{
		currentEpoch: epoch,
		ch:           make(chan time.Time, 1),
		timer:        time.NewTimer(forever),
	}
	t.Reset(0, epoch)
	return t
}

func (t *TimerFake) startTimerGoroutine() chan interface{} {
	stopCh := make(chan interface{})
	go func() {
		select {
		case now := <-t.timer.C:
			t.ch <- now
		case <-stopCh:
		}
	}()
	return stopCh
}

func (t *TimerFake) GetChannel() <-chan time.Time {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	return t.ch
}

func (t *TimerFake) Stop() {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.stop()
}

func (t *TimerFake) stop() {
	t.mutex.CheckIsLocked("")
	t.timer.Stop()
	if t.stopCh != nil {
		close(t.stopCh)
		t.stopCh = nil
	}
	select {
	case <-t.timer.C:
	default:
	}
}

func (t *TimerFake) Reset(duration time.Duration, epoch blockchain.Epoch) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.reset(duration, epoch)
}

func (t *TimerFake) reset(duration time.Duration, epoch blockchain.Epoch) {
	t.mutex.CheckIsLocked("")

	t.currentEpoch = epoch
	t.stop()

	// restart the timer if needed
	if t.currentEpoch.Compare(t.targetEpoch) < 0 && duration > 0 {
		t.timer.Reset(duration)
		t.stopCh = t.startTimerGoroutine()
	}
}

// TODO semantics of this function changed, check everywhere pls
func (t *TimerFake) AllowAdvancingEpochTo(epoch blockchain.Epoch, d time.Duration) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.targetEpoch = epoch

	t.reset(d, t.currentEpoch)
}

func CreateRoleAssignerForTest(
	loggingId string,
	id ConsensusId,
	isBootnode bool,
	k *config.Int64HardforkConfig,
	elecOffsetVal int64,
) RoleAssigner {
	utils.EnsureRunningInTestCode()
	cfg := &RoleAssignerImplCfg{
		K:                              k,
		MyId:                           id,
		IsBootnode:                     isBootnode,
		LoggingId:                      loggingId,
		ElectionStopBlockSessionOffset: testutils.NewElectionStopBlockSessionOffsetForTest(elecOffsetVal, 0),
	}

	return NewRoleAssignerImpl(cfg)
}

func CreateRoleAssignerForTestFromElectionResult(
	loggingId string, er *blockchain.ElectionResultImpl, id ConsensusId,
	isBootnode bool, k *config.Int64HardforkConfig, elecOffsetVal int64,
) RoleAssigner {
	ra := CreateRoleAssignerForTest(loggingId, id, isBootnode, k, elecOffsetVal)
	ra.(*RoleAssignerImpl).AddElectionResult(er)
	return ra
}

func CreateRoleAssignerForTestWithCommittee(
	loggingId string,
	id ConsensusId,
	isBootnode bool,
	session blockchain.Session,
	proposerIds []ConsensusId,
	voterIds []ConsensusId,
	stakes []*big.Int,
	k *config.Int64HardforkConfig,
	elecOffsetVal int64,
) RoleAssigner {
	utils.EnsureRunningInTestCode()
	ra := CreateRoleAssignerForTest(loggingId, id, isBootnode, k, elecOffsetVal)
	ra.(*RoleAssignerImpl).AddSessionCommittee(session, proposerIds, voterIds, stakes)
	return ra
}

func MakeStakes(num int, val *big.Int) []*big.Int {
	stakes := []*big.Int{}
	for i := 0; i < num; i++ {
		stakes = append(stakes, big.NewInt(val.Int64()))
	}

	return stakes
}
