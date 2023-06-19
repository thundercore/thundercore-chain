package blockchain

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/thunder/pala/types"

	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"golang.org/x/crypto/sha3"
	"golang.org/x/xerrors"
)

type ConsensusId = types.ConsensusId

var ConsensusIds = types.ConsensusIds

var ConsensusIdFromPubKey = types.ConsensusIdFromPubKey

var ConsensusIdFromBytes = types.ConsensusIdFromBytes

var MakeConsensusIds = types.MakeConsensusIds

const (
	fakeSignature = 0
	blsSignature  = 1
)

type proof interface {
	GetBlockSn() BlockSn
	GetVoterId() ConsensusId
	GetSignature() *bls.Signature
	GetType() Type
}

type voteCountingScheme interface {
	PassThreshold(votedIds []ConsensusId) (bool, error)
}

var (
	vLogger                            = logger.NewChildLgr("verifier")
	ErrNotEnoughVotes                  = xerrors.New("not enough votes")
	ErrNotEnoughVotesAfterVerification = xerrors.New("not enough votes after verification")
	ErrBadSig                          = xerrors.New("bad signature")
	ErrMissingElectionResult           = xerrors.New("missing election result")
	ErrNoProposingKey                  = xerrors.New("no proposing key")
	ErrNoVotingKey                     = xerrors.New("no voting key")
	ErrBlockNotFound                   = xerrors.New("block not found")
	ErrNoSigningKey                    = xerrors.New("no signing key available")
)

type ElectionResultImpl struct {
	committee.CommInfo
	session Session

	// maps for ConsensusId -> idx
	voterIdxMap    map[ConsensusId]uint16
	proposerIdxMap map[ConsensusId]uint16

	voters         []ConsensusId
	proposers      []ConsensusId
	proposerStakes []*big.Int
}

//------------------------------------------------------------------------------

func NewElectionResultImpl(cInfo *committee.CommInfo, s Session) *ElectionResultImpl {
	ci := *cInfo.Clone()
	voterIdxMap := make(map[ConsensusId]uint16)
	voters := []ConsensusId{}
	for i, v := range ci.MemberInfo {
		id := ConsensusIdFromPubKey(v.PubVoteKey)
		voterIdxMap[id] = uint16(i)
		voters = append(voters, id)
	}

	proposerIdxMap := make(map[ConsensusId]uint16)
	proposers := []ConsensusId{}
	proposerStakes := []*big.Int{}
	for i, p := range ci.AccelInfo {
		id := ConsensusIdFromPubKey(p.PubVoteKey)
		proposerIdxMap[id] = uint16(i)
		proposers = append(proposers, id)
		proposerStakes = append(proposerStakes, p.Stake)
	}
	return &ElectionResultImpl{
		CommInfo:       *cInfo,
		session:        s,
		voterIdxMap:    voterIdxMap,
		proposerIdxMap: proposerIdxMap,
		voters:         voters,
		proposers:      proposers,
		proposerStakes: proposerStakes,
	}
}

func (er *ElectionResultImpl) GetVoterById(id ConsensusId) (*committee.MemberInfo, error) {
	if idx, err := er.GetVoterIdxById(id); err != nil {
		return nil, err
	} else {
		return &er.MemberInfo[idx], nil
	}
}

func (er *ElectionResultImpl) GetProposerById(id ConsensusId) (*committee.AccelInfo, error) {
	if idx, err := er.GetProposerIdxById(id); err != nil {
		return nil, err
	} else {
		return &er.AccelInfo[idx], nil
	}
}

func (er *ElectionResultImpl) GetVoterIdxById(id ConsensusId) (uint16, error) {
	if idx, ok := er.voterIdxMap[id]; ok {
		return idx, nil
	} else {
		return 0, xerrors.Errorf("voter %s not found", id)
	}
}

func (er *ElectionResultImpl) GetProposerIdxById(id ConsensusId) (uint16, error) {
	if idx, ok := er.proposerIdxMap[id]; ok {
		return idx, nil
	} else {
		return 0, xerrors.Errorf("proposer %s not found", id)
	}
}

func (er *ElectionResultImpl) PrimaryProposer(e Epoch) (*committee.AccelInfo, error) {
	if e.Session != er.session {
		return nil, xerrors.New("session mismatch")
	}
	return &er.AccelInfo[0], nil
}

func (er *ElectionResultImpl) GetAggregatedPublicKey(proposerIdx uint16, voterIdxs []uint16) (*bls.PublicKey, error) {
	p, err := er.getProposerByIdx(proposerIdx)
	if err != nil {
		return nil, err
	}
	aggPk := p.PubVoteKey
	for _, i := range voterIdxs {
		voter, err := er.getVoterByIdx(i)
		if err != nil {
			return nil, err
		}
		aggPk = bls.CombinePublicKeys(aggPk, voter.PubVoteKey)
	}
	return aggPk, nil
}

func (er *ElectionResultImpl) getProposerByIdx(idx uint16) (*committee.AccelInfo, error) {
	if idx > uint16(er.NumAccel()) {
		return nil, xerrors.Errorf("ProposerIdx out-of-bound: %d > %d", idx, er.NumAccel())
	}
	return &er.CommInfo.AccelInfo[idx], nil
}

func (er *ElectionResultImpl) getVoterByIdx(idx uint16) (*committee.MemberInfo, error) {
	if idx > uint16(er.NumCommittee()) {
		return nil, xerrors.Errorf("VoterIdx out-of-bound: %d > %d", idx, er.NumCommittee())
	}
	return &er.CommInfo.MemberInfo[idx], nil
}

func (er *ElectionResultImpl) GetSession() Session {
	return er.session
}

func (er *ElectionResultImpl) NumberOfProposers() uint32 {
	return uint32(len(er.CommInfo.AccelInfo))
}

func (er *ElectionResultImpl) GetVoters() []ConsensusId {
	return er.voters
}

func (er *ElectionResultImpl) GetProposers() []ConsensusId {
	return er.proposers
}

func (er *ElectionResultImpl) GetStakes() []*big.Int {
	return er.proposerStakes
}

type VerifierImpl struct {
	mutex                    sync.RWMutex
	electionResults          map[Session]*ElectionResultImpl
	signer                   bls.BlsSigner
	id                       ConsensusId
	loggingId                string
	voteCountingSchemes      map[Session]voteCountingScheme
	voteCountingSchemeConfig *config.StringHardforkConfig
}

type VerifierImplCfg struct {
	ElectionResult     *ElectionResultImpl
	Signer             bls.BlsSigner
	LoggingId          string
	VoteCountingScheme *config.StringHardforkConfig
}

func NewVerifierImpl(cfg *VerifierImplCfg) Verifier {
	vLogger.Debug("NewVerifierImpl")
	v := &VerifierImpl{
		electionResults:          make(map[Session]*ElectionResultImpl),
		signer:                   cfg.Signer,
		id:                       ConsensusIdFromPubKey(cfg.Signer.GetPublicKey()),
		loggingId:                cfg.LoggingId,
		voteCountingSchemes:      make(map[Session]voteCountingScheme),
		voteCountingSchemeConfig: config.NewStringHardforkConfig("committee.voteCountingScheme", ""),
	}

	v.AddElectionResult(cfg.ElectionResult)
	return v
}

func (v *VerifierImpl) getElectionResult(s Session) (*ElectionResultImpl, error) {
	er, ok := v.electionResults[s]
	if !ok {
		return nil, ErrMissingElectionResult
	}
	return er, nil
}

func (v *VerifierImpl) Propose(b Block) (Proposal, error) {
	vLogger.Debug("[%s] Propose %s", v.loggingId, b.GetBlockSn())
	v.mutex.RLock()
	defer v.mutex.RUnlock()

	sig := v.signer.Sign(b.GetHash().Bytes())
	p := &proposalImpl{
		block:      b,
		signature:  sig,
		proposerId: v.id,
	}
	return p, nil
}

func (v *VerifierImpl) IsReadyToPropose(ids []ConsensusId, session Session) bool {
	vLogger.Debug("[%s] IsReadyToPropose %s", v.loggingId, ids)
	v.mutex.Lock()
	defer v.mutex.Unlock()
	pass, err := v.passThreshold(ids, session)
	if err != nil {
		vLogger.Info("[%s] pass threshold err=%+v", v.loggingId, err)
		return false
	}
	return pass
}

func (v *VerifierImpl) VerifyProposal(p Proposal) error {
	vLogger.Debug("[%s] VerifyProposal %s", v.loggingId, p.GetBlockSn())
	v.mutex.RLock()
	defer v.mutex.RUnlock()

	er, err := v.getElectionResult(p.GetBlockSn().Epoch.Session)
	if err != nil {
		return err
	}

	proposer, err := er.GetProposerById(p.GetProposerId())
	if err != nil {
		return err
	}

	ppIdx := PrimaryProposerIndexer(p.GetBlockSn().Epoch, er.NumberOfProposers())
	primaryProposer, err := er.getProposerByIdx(uint16(ppIdx))
	if err != nil {
		return err
	}
	if primaryProposer != proposer {
		return xerrors.Errorf("proposer [%s] is not the right primary proposer %s at %s",
			ConsensusIdFromPubKey(proposer.PubVoteKey), ConsensusIdFromPubKey(primaryProposer.PubVoteKey), p.GetBlockSn())
	}

	pi := p.(*proposalImpl)
	if !proposer.PubVoteKey.VerifySignature(pi.GetBlock().GetHash().Bytes(), pi.signature) {
		return ErrBadSig
	}
	return nil
}

func (v *VerifierImpl) Vote(p Proposal) (Vote, error) {
	vLogger.Debug("[%s] Vote %s", v.loggingId, p.GetBlockSn())
	v.mutex.RLock()
	defer v.mutex.RUnlock()

	sig := v.signer.Sign(p.GetBlock().GetHash().Bytes())
	vote := &voteImpl{
		sn:        p.GetBlockSn(),
		blockHash: p.GetBlock().GetHash(),
		signature: sig,
		voterId:   v.id,
	}
	return vote, nil
}

func (v *VerifierImpl) VerifyVote(vote Vote, r ChainReader) error {
	vLogger.Debug("[%s] VerifyVote %s", v.loggingId, vote.GetBlockSn())
	v.mutex.RLock()
	defer v.mutex.RUnlock()

	er, err := v.getElectionResult(vote.GetBlockSn().Epoch.Session)
	if err != nil {
		return err
	}

	voter, err := er.GetVoterById(vote.GetVoterId())
	if err != nil {
		return err
	}

	b := r.GetBlock(vote.GetBlockSn())
	if b == nil {
		return ErrBlockNotFound
	}

	vi := vote.(*voteImpl)
	if b.GetHash() != vi.GetBlockHash() {
		return xerrors.Errorf("Blockhash mismatch: %s != %s", b.GetHash(), vi.GetBlockHash())
	}

	if !voter.PubVoteKey.VerifySignature(b.GetHash().Bytes(), vi.signature) {
		return ErrBadSig
	}

	return nil
}

func (v *VerifierImpl) Notarize(votes []Vote, r ChainReader) (Notarization, error) {
	vLogger.Debug("[%s] Notarize %d", v.loggingId, len(votes))
	v.mutex.RLock()
	defer v.mutex.RUnlock()

	if len(votes) < 1 {
		return nil, ErrNotEnoughVotes
	}
	blockSn := votes[0].GetBlockSn()
	b := r.GetBlock(blockSn)
	if b == nil {
		return nil, ErrBlockNotFound
	}

	proofs := make([]proof, 0, len(votes))
	for _, vote := range votes {
		proofs = append(proofs, vote.(*voteImpl))
	}
	aggSig, pIdx, nVote, missingVoterIdxs, err := v.prepareNotarization(blockSn, b.GetHash().Bytes(), proofs)
	if err != nil {
		return nil, err
	}

	nota := &notarizationImpl{
		aggSig:           aggSig,
		blockHash:        b.GetHash(),
		sn:               blockSn,
		proposerIdx:      pIdx,
		nVote:            nVote,
		missingVoterIdxs: missingVoterIdxs,
	}

	return nota, nil
}

func (v *VerifierImpl) VerifyNotarization(n Notarization, r ChainReader) error {
	vLogger.Debug("[%s] VerifyNotarization %s", v.loggingId, n.GetBlockSn())
	v.mutex.RLock()
	defer v.mutex.RUnlock()

	b := r.GetBlock(n.GetBlockSn())
	if b == nil {
		return ErrBlockNotFound
	}

	return v.verifyNotarization(n, b)
}

func (v *VerifierImpl) VerifyNotarizationWithBlock(n Notarization, b Block) error {
	vLogger.Debug("[%s] VerifyNotarizationWithBlock %s", v.loggingId, n.GetBlockSn())
	v.mutex.RLock()
	defer v.mutex.RUnlock()

	return v.verifyNotarization(n, b)
}

func (v *VerifierImpl) verifyNotarization(n Notarization, b Block) error {
	ni := n.(*notarizationImpl)
	if !utils.InBenchmark() {
		if s := ni.getStatus(); s != unknown {
			if s == invalid {
				return ErrBadSig
			}
			return nil
		}
	}

	if b.GetHash() != ni.GetBlockHash() {
		// We don't cached here because it's not so CPU-bound and error message should matched
		return xerrors.Errorf("Blockhash mismatch: %s != %s", b.GetHash(), ni.GetBlockHash())
	}

	er, err := v.getElectionResult(n.GetBlockSn().Epoch.Session)
	if err != nil {
		return err
	}

	voterIdxs := voterIdxsToMissingVoterIdxs(ni.missingVoterIdxs, er)
	aggPk, err := er.GetAggregatedPublicKey(ni.proposerIdx, voterIdxs)
	if err != nil {
		return err
	}

	if !aggPk.VerifySignature(b.GetHash().Bytes(), ni.aggSig) {
		ni.setStatus(invalid)
		return ErrBadSig
	}
	if !utils.InBenchmark() {
		ni.setStatus(valid)
	}

	return nil
}

func (v *VerifierImpl) NewClockMsg(e Epoch) (ClockMsg, error) {
	vLogger.Debug("[%s] NewClockMsg %s", v.loggingId, e)
	v.mutex.RLock()
	defer v.mutex.RUnlock()

	sig := v.signer.Sign(e.ToBytes())
	c := &clockMsgImpl{
		epoch:     e,
		signature: sig,
		voterId:   v.id,
	}
	return c, nil
}

func (v *VerifierImpl) VerifyClockMsg(c ClockMsg) error {
	vLogger.Debug("[%s] VerifyClockMsg %s", v.loggingId, c.GetEpoch())
	v.mutex.RLock()
	defer v.mutex.RUnlock()

	er, err := v.getElectionResult(c.GetBlockSn().Epoch.Session)
	if err != nil {
		return err
	}

	voter, err := er.GetVoterById(c.GetVoterId())
	if err != nil {
		return err
	}

	ci := c.(*clockMsgImpl)
	if !voter.PubVoteKey.VerifySignature(ci.GetEpoch().ToBytes(), ci.signature) {
		return ErrBadSig
	}

	return nil
}

func (v *VerifierImpl) NewClockMsgNota(clocks []ClockMsg) (ClockMsgNota, error) {
	vLogger.Debug("[%s] NewClockMsgNota %d", v.loggingId, len(clocks))
	v.mutex.RLock()
	defer v.mutex.RUnlock()

	if len(clocks) < 1 {
		return nil, ErrNotEnoughVotes
	}
	e := clocks[0].GetEpoch()

	proofs := make([]proof, 0, len(clocks))
	for _, clk := range clocks {
		proofs = append(proofs, clk.(*clockMsgImpl))
	}
	aggSig, pIdx, nVote, missingVoterIdxs, err := v.prepareNotarization(clocks[0].GetBlockSn(), e.ToBytes(), proofs)
	if err != nil {
		return nil, err
	}

	clockMsgNota := &clockMsgNotaImpl{
		aggSig:           aggSig,
		epoch:            e,
		proposerIdx:      pIdx,
		nVote:            nVote,
		missingVoterIdxs: missingVoterIdxs,
	}

	return clockMsgNota, nil
}

func (v *VerifierImpl) VerifyClockMsgNota(cn ClockMsgNota) error {
	vLogger.Debug("[%s] VerifyClockMsgNota %s", v.loggingId, cn.GetEpoch())
	v.mutex.RLock()
	defer v.mutex.RUnlock()

	ci := cn.(*clockMsgNotaImpl)
	if !utils.InBenchmark() {
		if s := ci.getStatus(); s != unknown {
			if s == invalid {
				return ErrBadSig
			}
			return nil
		}
	}

	er, err := v.getElectionResult(cn.GetBlockSn().Epoch.Session)
	if err != nil {
		return err
	}

	cni := cn.(*clockMsgNotaImpl)
	voterIdxs := voterIdxsToMissingVoterIdxs(cni.missingVoterIdxs, er)
	aggPk, err := er.GetAggregatedPublicKey(cni.proposerIdx, voterIdxs)
	if err != nil {
		return err
	}

	if !aggPk.VerifySignature(cn.GetEpoch().ToBytes(), cni.aggSig) {
		ci.setStatus(invalid)
		return ErrBadSig
	}
	if !utils.InBenchmark() {
		ci.setStatus(valid)
	}

	return nil
}

func (v *VerifierImpl) Sign(bytes []byte) (ConsensusId, []byte, error) {
	vLogger.Debug("[%s] Sign %s", v.loggingId, hex.EncodeToString(bytes))
	v.mutex.Lock()
	defer v.mutex.Unlock()

	// Sign by the consensus role.
	bs := []byte{blsSignature}
	pubkey := v.signer.GetPublicKey().ToBytes()
	bs = append(bs, utils.Uint16ToBytes(uint16(len(pubkey)))...)
	bs = append(bs, pubkey...)
	bs = append(bs, v.signer.Sign(bytes).ToBytes()...)
	return v.id, bs, nil
}

func hashByKeccak256(bytes []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	_, err := h.Write(bytes)
	if err != nil {
		debug.Bug("sha3.LegacyKeccak256.Write failed: %s", err)
	}
	//t := make([]byte, 0, h.Size())
	return h.Sum(nil)
}

func (v *VerifierImpl) VerifySignature(
	signature []byte, expected []byte,
) (ConsensusId, bool, error) {
	vLogger.Debug("[%s] VerifySignature %s", v.loggingId, hex.EncodeToString(signature))
	v.mutex.Lock()
	defer v.mutex.Unlock()

	if len(signature) < 2 {
		return "", false, ErrBadSig
	}
	scheme := signature[0]
	if scheme == blsSignature {
		n, bytes, err := utils.BytesToUint16(signature[1:])
		if err != nil {
			return "", false, xerrors.Errorf("consensus node signature format error: %w", err)
		}
		if len(bytes) < int(n) {
			return "", false, xerrors.Errorf("consensus node signature format error: %d < %d",
				len(bytes), n)
		}
		pubkey, err := bls.PublicKeyFromBytes(bytes[:n])
		if err != nil {
			return "", false, xerrors.Errorf("consensus node signature format error: %w", err)
		}
		id := ConsensusIdFromPubKey(pubkey)
		signature = bytes[n:]

		sig, err := bls.SignatureFromBytes(signature)
		if err != nil {
			return "", false, xerrors.Errorf("consensus node signature format error: %w", err)
		}

		if !pubkey.VerifySignature(expected, sig) {
			return "", false, xerrors.Errorf("failed to verify the signature (id=%s)", id)
		}

		var isConsensusNode bool
		for _, er := range v.electionResults {
			if _, err := er.GetVoterById(id); err == nil {
				isConsensusNode = true
				break
			}
			if _, err := er.GetProposerById(id); err == nil {
				isConsensusNode = true
				break
			}
		}

		return id, isConsensusNode, nil
	}

	return "", false, xerrors.Errorf("unexpected signature scheme %d: %w", scheme, ErrBadSig)
}

func (v *VerifierImpl) AddElectionResult(e *ElectionResultImpl) {
	vLogger.Debug("[%s] AddElectionResult %s", v.loggingId, e.GetSession())
	v.mutex.Lock()
	defer v.mutex.Unlock()

	session := e.GetSession()
	v.electionResults[session] = e

	// create vote counting scheme by hard fork config
	var scheme voteCountingScheme
	s := v.voteCountingSchemeConfig.GetValueAtSession(int64(session))
	switch strings.ToLower(s) {
	case "stake":
		scheme = newCountVoteByStake(e)
	case "seat":
		scheme = newCountVoteBySeat(e)
	default:
		debug.Bug("[%s] unknown vote counting scheme (%s), please set the hardfork config correctly", v.loggingId, s)
	}
	v.voteCountingSchemes[session] = scheme
}

func (v *VerifierImpl) CleanupElectionResult(s Session) {
	vLogger.Debug("[%s] CleanupElectionResult %d", v.loggingId, s)
	v.mutex.Lock()
	defer v.mutex.Unlock()

	for k, _ := range v.electionResults {
		if k <= s {
			delete(v.electionResults, k)
			delete(v.voteCountingSchemes, k)
		}
	}
}

func (v *VerifierImpl) GetElectionResultsForTest() map[Session]*ElectionResultImpl {
	utils.EnsureRunningInTestCode()
	return v.electionResults
}

func (v *VerifierImpl) prepareNotarization(blockSn BlockSn, b []byte, proofs []proof) (*bls.Signature, uint16, uint16, []uint16, error) {
	er, err := v.getElectionResult(blockSn.Epoch.Session)
	if err != nil {
		return nil, 0, 0, nil, err
	}

	ids := make([]ConsensusId, len(proofs))
	for i, proof := range proofs {
		ids[i] = proof.GetVoterId()
	}

	pass, err := v.passThreshold(ids, er.GetSession())
	if err != nil {
		return nil, 0, 0, nil, err
	}
	if !pass {
		return nil, 0, 0, nil, ErrNotEnoughVotes
	}

	aggSig, proposerIdx, nVote, missingVoterIdxs, err := v.notarize(blockSn, b, proofs, er, true)
	if err != nil {
		return v.notarize(blockSn, b, proofs, er, false)
	}
	return aggSig, proposerIdx, nVote, missingVoterIdxs, nil
}

func (v *VerifierImpl) notarize(sn BlockSn, b []byte, proofs []proof, er *ElectionResultImpl, optimistic bool) (*bls.Signature, uint16, uint16, []uint16, error) {
	proposerIdx, err := er.GetProposerIdxById(v.id)
	if err != nil {
		return nil, 0, 0, nil, err
	}

	type notaInfo struct {
		sig        *bls.Signature
		pubVoteKey *bls.PublicKey
		idx        uint16
	}
	notaInfoChan := make(chan notaInfo)
	wg := sync.WaitGroup{}
	for _, vote := range proofs {
		wg.Add(1)
		go func(vote proof) {
			defer wg.Done()
			if vote.GetBlockSn().Compare(sn) != 0 {
				vLogger.Warn("[%s] Dropping %s(%s) due to 'BlockSn mismatch: %s != %s'", v.loggingId, vote.GetType(), vote, vote.GetBlockSn(), sn)
				return
			}
			voterIdx, err := er.GetVoterIdxById(vote.GetVoterId())
			if err != nil {
				vLogger.Warn("[%s] Dropping %s(%s) due to '%s'", v.loggingId, vote.GetType(), vote, err)
				return
			}
			voter, err := er.GetVoterById(vote.GetVoterId())
			if err != nil {
				vLogger.Warn("[%s] Dropping %s(%s) due to '%s'", v.loggingId, vote.GetType(), vote, err)
				return
			}
			if !optimistic && !voter.PubVoteKey.VerifySignature(b, vote.GetSignature()) {
				vLogger.Warn("[%s] Dropping %s(%s) due to '%s'", v.loggingId, vote.GetType(), vote, ErrBadSig)
				return
			}
			notaInfoChan <- notaInfo{
				sig:        vote.GetSignature(),
				pubVoteKey: voter.PubVoteKey,
				idx:        voterIdx,
			}
		}(vote)

	}
	go func() {
		wg.Wait()
		close(notaInfoChan)
	}()

	aggSig, aggPk := v.signer.Sign(b), v.signer.GetPublicKey()
	voterIdxs := make([]uint16, 0, er.NumCommittee())
	votedVoterIds := make([]ConsensusId, 0, er.NumCommittee())
	votedVoters := make(map[uint16]bool)
	for t := range notaInfoChan {
		if _, ok := votedVoters[t.idx]; ok {
			continue
		}
		votedVoters[t.idx] = true
		voterIdxs = append(voterIdxs, t.idx)
		votedVoterIds = append(votedVoterIds, ConsensusIdFromPubKey(t.pubVoteKey))
		aggSig, aggPk = bls.CombineSignatures(aggSig, t.sig, aggPk, t.pubVoteKey)
	}

	pass, err := v.passThreshold(votedVoterIds, er.GetSession())
	if err != nil {
		return nil, 0, 0, nil, err
	}
	if !pass {
		return nil, 0, 0, nil, ErrNotEnoughVotesAfterVerification
	}

	if !aggPk.VerifySignature(b, aggSig) {
		return nil, 0, 0, nil, ErrBadSig
	}
	return aggSig, proposerIdx, uint16(len(voterIdxs)), voterIdxsToMissingVoterIdxs(voterIdxs, er), nil
}

func (v *VerifierImpl) passThreshold(votedIds []ConsensusId, s Session) (bool, error) {
	er, err := v.getElectionResult(s)
	if err != nil {
		return false, err
	}

	// Filter out invalid and duplicate ids
	var ids []ConsensusId
	m := map[ConsensusId]struct{}{}
	for _, id := range votedIds {
		if _, ok := m[id]; !ok {
			if _, err := er.GetVoterIdxById(id); err == nil {
				m[id] = struct{}{}
				ids = append(ids, id)
			}
		}
	}

	scheme, err := v.getVoteCountingScheme(s)
	if err != nil {
		return false, err
	}
	pass, err := scheme.PassThreshold(ids)
	if err != nil {
		debug.Bug(fmt.Sprintf("%+v", err))
	}
	return pass, nil
}

func (v *VerifierImpl) getVoteCountingScheme(s Session) (voteCountingScheme, error) {
	if scheme, ok := v.voteCountingSchemes[s]; ok {
		return scheme, nil
	}
	return nil, ErrMissingElectionResult
}

func voterIdxsToMissingVoterIdxs(voterIdxs []uint16, er *ElectionResultImpl) []uint16 {
	var missingVoterIdxs []uint16
	voterSet := make(map[uint16]bool)
	for _, v := range voterIdxs {
		voterSet[v] = true
	}
	for i := uint16(0); i < uint16(er.NumCommittee()); i++ {
		if _, ok := voterSet[i]; !ok {
			missingVoterIdxs = append(missingVoterIdxs, i)
		}
	}
	return missingVoterIdxs
}
