// Class Has-A Relations:
// https://docs.google.com/presentation/d/1AY-GiujqkzRdfdleDSrj516d48-3w-z70w4DQiy_3HY/edit?usp=sharing
//
// Data flow:
// https://docs.google.com/presentation/d/1vQ1Kh5O_kNXe0y0GK9c26UTmblPIdx8DDoKmPhrrr3c/edit?usp=sharing

package consensus

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/consensus/startstopwaiter"
	"github.com/ethereum/go-ethereum/thunder/pala/metrics"
	"github.com/ethereum/go-ethereum/thunder/pala/network"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/petar/GoLLRB/llrb"
	"golang.org/x/xerrors"
)

var logger = lgr.NewLgr("/consensus")

type Role int

const (
	RoleFullNode = Role(1 << 0)
	RoleProposer = Role(1 << 1)
	RoleVoter    = Role(1 << 2)
)

type ActorConfig struct {
	LoggingId   string
	K           *config.Int64HardforkConfig
	Chain       blockchain.BlockChain
	ActorClient ActorClient
	Role        RoleAssigner
	Verifier    blockchain.Verifier
	Epoch       blockchain.Epoch
	Metrics     metrics.PalaMetrics
}

// Note that all methods do not return error. This allows the client to execute asynchronously.
// If Actor really needs to know whether the execution succeeds, use some other way
// to get the result.
type ActorClient interface {
	Broadcast(m blockchain.Message)
	// Reply sends |m| to the one who sent |source|.
	Reply(source *network.Message, m blockchain.Message)
	CatchUp(source *network.Message, sn blockchain.BlockSn)
	// UpdateEpoch updates the epoch by clock message notarization.
	UpdateEpoch(cNota blockchain.ClockMsgNota)
}

// Actor follows PaLa's rules to process consensus data. All methods are *NOT* goroutine-safe.
// Expect it is used in a designated goroutine.
type Actor struct {
	startstopwaiter.StartStopWaiterImpl

	// Immutable after set.
	loggingId string
	k         *config.Int64HardforkConfig

	// Only used in the worker goroutine.
	chain            blockchain.BlockChain
	client           ActorClient
	role             RoleAssigner
	verifier         blockchain.Verifier
	epoch            blockchain.Epoch
	metrics          metrics.PalaMetrics
	lastEpochMetrics *metrics.PalaMetrics
	// Run in the worker goroutine and only used by internal tests.
	byzantineClient byzantineClient
	// Only used by the primary proposer. Expect there are at most k objects in the maps.
	votes            map[blockchain.BlockSn]map[ConsensusId]blockchain.Vote
	broadcastedNotas map[blockchain.BlockSn]bool
	proposalSentTime map[blockchain.BlockSn]time.Time
	// Only used by proposers.
	clockMsgs map[ConsensusId]blockchain.ClockMsg
	// Only used by voters.
	voted            *llrb.LLRB
	unvotedProposals *llrb.LLRB
}

// byzantineClient is called at the beginning of every internal callback of Node.
// If it returns error, the corresponding callback ends; otherwise, the callback continues.
// We can use byzantineClient to simulate a byzantine node.
type byzantineClient interface {
	onTimeout(a *Actor) error
	onReceivedBlock(a *Actor, b blockchain.Block, creator BlockCreator, replaceable bool) error
	onReceivedProposal(a *Actor, p blockchain.Proposal, ctx proposalContext) error
	onReceivedVote(a *Actor, v blockchain.Vote) error
	onReceivedNotarization(a *Actor, nota blockchain.Notarization) error
	onReceivedClockMsg(a *Actor, c blockchain.ClockMsg) error
	onReceivedClockMsgNota(a *Actor, cNota blockchain.ClockMsgNota) error
	onReceivedFreshestNotarizedChainExtendedEvent(
		n *Actor, e blockchain.FreshestNotarizedChainExtendedEvent) error
	onReceivedFinalizedChainExtendedEvent(
		n *Actor, e blockchain.FinalizedChainExtendedEvent) error
	onReceivedNotarizedBlock(a *Actor, nota blockchain.Notarization, b blockchain.Block) error
}

type BlockCreator int

const (
	BlockCreatedByOther = BlockCreator(0)
	BlockCreatedBySelf  = BlockCreator(1)
)

type work struct {
	// The main data.
	blob interface{}
	// The aux data for blob
	context interface{}
	// Return the result via ch
	ch chan error
}

type proposalContext struct {
	source  *network.Message
	creator BlockCreator
}

type proposalArguments struct {
	p   blockchain.Proposal
	ctx proposalContext
}

// RoleAssigner determines the role of the node. All methods must be goroutine-safe.
// A node can have multiple roles. When doing the proposer/voter reconfiguration,
// need |id| to determine whether to establish/drop the connection.
type RoleAssigner interface {
	// IsProposer returns true if |id| is a proposer at |session|.
	// If |id| is UseMyId, it means asking whether itself is a proposer.
	IsProposer(id ConsensusId, session blockchain.Session) bool
	// IsPrimaryProposer returns true if |id| is the primary proposer at |epoch|.
	// If |id| is UseMyId, it means asking whether itself is a proposer.
	IsPrimaryProposer(id ConsensusId, epoch blockchain.Epoch) bool
	// IsVoter returns true if |id| is a voter at |session|.
	// If |id| is UseMyId, it means asking whether itself is a voter.
	IsVoter(id ConsensusId, session blockchain.Session) bool
	// IsBootnode() returns true if |id| is a bootnode. Bootnodes are special nodes assigned
	// in the configurations/code without a term of office.
	// If |id| is UseMyId, it means asking whether itself is a bootnode.
	IsBootnode(id ConsensusId) bool
	GetMyId() ConsensusId
	GetNumVoters(session blockchain.Session) int
	// GetShortName returns the short name of |id|.
	GetShortName(id ConsensusId) string
	// GetShortNameMapping() returns the mapping from short names to identities.
	GetShortNameMapping() map[string]ConsensusId
	AddBootnode(verifiedId, shortName ConsensusId)
	RemoveBootnode(verifiedId ConsensusId)

	// Should force rotate proposer
	ExceedEpochMaxAllowedSeq(sn blockchain.BlockSn, blockNumber uint64) bool
}

// UseMyId is used when calling RoleAssigner to ask e.g. "Is my id
// acting as a certain role for the specified time period?""
const UseMyId = ConsensusId("__use_my_id__")

func IsConsensusNode(role RoleAssigner, id ConsensusId, session blockchain.Session) bool {
	return role.IsProposer(id, session) || role.IsVoter(id, session)
}

// The item used with the ordered map (LLRB).
type Item struct {
	key   blockchain.BlockSn
	value interface{}
}

//--------------------------------------------------------------------

func NewActor(cfg ActorConfig) Actor {
	a := Actor{
		loggingId: cfg.LoggingId,
		k:         cfg.K,
		chain:     cfg.Chain,
		client:    cfg.ActorClient,
		role:      cfg.Role,
		verifier:  cfg.Verifier,
		metrics:   cfg.Metrics,
	}
	a.reset(cfg.Epoch)
	return a
}

func (a *Actor) reset(e blockchain.Epoch) {
	a.epoch = e
	a.votes = make(map[blockchain.BlockSn]map[ConsensusId]blockchain.Vote)
	a.broadcastedNotas = make(map[blockchain.BlockSn]bool)
	a.proposalSentTime = make(map[blockchain.BlockSn]time.Time)
	a.clockMsgs = make(map[ConsensusId]blockchain.ClockMsg)
	a.voted = llrb.New()
	a.unvotedProposals = llrb.New()
}

func (a *Actor) ResetForTest(e blockchain.Epoch) {
	a.reset(e)
}

func (a *Actor) setByzantineClient(c byzantineClient) {
	utils.EnsureRunningInTestCode()
	a.byzantineClient = c
}

// Run in the worker goroutine
// This function is only called on voters.
func (a *Actor) onTimeout() error {
	metrics.IncCounter(a.metrics.Timeout)
	if a.byzantineClient != nil {
		if err := a.byzantineClient.onTimeout(a); err != nil {
			return err
		}
	}
	return a.createAndbroadcastClockMsg()
}

// Run in the worker goroutine
// This function is only called on voters.
func (a *Actor) createAndbroadcastClockMsg() error {
	// The node may not be a voter after the timeout.
	if !a.role.IsVoter(UseMyId, a.epoch.Session) {
		return nil
	}

	epoch := a.epoch.NextEpoch()
	if c, err := a.verifier.NewClockMsg(epoch); err != nil {
		logger.Error("[%s] a timeout happened but failed to create clock(%d); err=%s",
			a.loggingId, epoch, err)
		return err
	} else {
		a.client.Broadcast(c)
		logger.Info("[%s] broadcast clock(%d) due to timeout", a.loggingId, epoch)
		if a.role.IsProposer(UseMyId, epoch.Session) {
			return a.onReceivedClockMsg(c)
		}
		return nil
	}
}

// Run in the worker goroutine
func (a *Actor) onReceivedBlock(
	b blockchain.Block, creator BlockCreator, replaceable bool,
) error {
	logger.Info("[%s] onReceivedBlock: %s, creator=%d",
		a.loggingId, b.GetBlockSn(), creator)

	if a.byzantineClient != nil {
		if err := a.byzantineClient.onReceivedBlock(a, b, creator, replaceable); err != nil {
			return err
		}
	}

	parentSn := b.GetParentBlockSn()
	sn := b.GetBlockSn()
	if sn.Epoch != parentSn.Epoch {
		if sn.S != 1 || sn.Epoch.Compare(parentSn.Epoch) < 0 {
			return xerrors.Errorf("invalid block sequence number %s with parent %s (our epoch=%s)",
				sn, parentSn, sn.Epoch)
		}
	} else if sn.S != parentSn.S+1 {
		return xerrors.Errorf("invalid block sequence number %s with parent %s", sn, parentSn)
	}

	if creator == BlockCreatedByOther {
		notas, cNota := a.chain.DecodeBlock(b)
		// The first block of every epoch except the first epoch of a session
		// has the proof of entering that epoch. We must advance the local epoch
		// before extending the freshest notarized head.
		if cNota != nil {
			if err := a.AddClockMsgNota(cNota); err != nil {
				logger.Info("[%s] failed to add ClockMsgNota %s; err=%s",
					a.loggingId, cNota.GetBlockSn().Epoch, err)
			}
		}

		for _, nota := range notas {
			err := a.onReceivedNotarization(nota)
			if err != nil {
				logger.Warn("%s", err)
			}
		}

		if err := a.chain.InsertBlock(b, replaceable); err != nil {
			return err
		}
		return nil
	}

	if b.GetBlockSn().Epoch != a.epoch ||
		!a.role.IsPrimaryProposer(UseMyId, b.GetBlockSn().Epoch) ||
		a.role.ExceedEpochMaxAllowedSeq(b.GetBlockSn(), b.GetNumber()) {
		logger.Info("[%s] received block %s and tried to stop the blockchain "+
			"creating new blocks (epoch=%d)", a.loggingId, b.GetBlockSn(), a.epoch)
		if err := a.chain.StopCreatingNewBlocks(blockchain.WaitingPeriodForStopingNewBlocks); err != nil {
			logger.Warn("[%s] received block %s and tried to stop the blockchain "+
				"creating new blocks but failed (epoch=%d); err=%s",
				a.loggingId, b.GetBlockSn(), a.epoch, err)
		}
		return nil
	}

	if a.chain.GetBlock(b.GetBlockSn()) == nil {
		return xerrors.Errorf("%s does not exist in the blockchain", b.GetBlockSn())
	}

	p, err := a.verifier.Propose(b)
	if err != nil {
		return err
	}
	metrics.IncCounter(a.metrics.Proposer_ProposalsCreated)
	a.proposalSentTime[p.GetBlockSn()] = time.Now()
	a.client.Broadcast(p)
	if a.role.IsVoter(UseMyId, b.GetBlockSn().Epoch.Session) {
		ctx := proposalContext{&network.Message{}, BlockCreatedBySelf}
		return a.onReceivedProposal(p, ctx)
	}
	return nil
}

func (a *Actor) ForceTimeoutToRotateProposers(sn blockchain.BlockSn) error {
	logger.Note("[%s] try to force rotate the proposer at %s", a.loggingId, sn)
	metrics.IncCounter(a.metrics.ForceRotateProposer)
	return a.createAndbroadcastClockMsg()
}

// Run in the worker goroutine
func (a *Actor) onReceivedProposal(p blockchain.Proposal, ctx proposalContext) error {
	logger.Info("[%s] onReceivedProposal: %s", a.loggingId, p.GetBlockSn())

	if a.byzantineClient != nil {
		if err := a.byzantineClient.onReceivedProposal(a, p, ctx); err != nil {
			return err
		}
	}

	if a.epoch.Compare(p.GetBlockSn().Epoch) != 0 {
		msg := fmt.Sprintf("skip proposal %s because local epoch=%d is different",
			p.GetBlockSn(), a.epoch)
		logger.Info("[%s] %s", a.loggingId, msg)
		return xerrors.New(msg)
	}

	isVoter := a.role.IsVoter(UseMyId, p.GetBlockSn().Epoch.Session)
	if isVoter && a.isVoted(p.GetBlockSn()) {
		metrics.IncCounter(a.metrics.Voter_ProposalsDup)
		return xerrors.Errorf("have voted %s", p.GetBlockSn())
	}
	if isVoter && a.role.ExceedEpochMaxAllowedSeq(p.GetBlockSn(), p.GetBlock().GetNumber()) {
		a.ForceTimeoutToRotateProposers(p.GetBlockSn())
		return xerrors.Errorf("[%s] %s is bigger than max valid S.", a.loggingId, p.GetBlockSn())
	}

	if err := a.verifier.VerifyProposal(p); err != nil {
		metrics.IncCounter(a.metrics.Voter_ProposalsBad)
		return err
	}

	b := p.GetBlock()
	if b == nil {
		metrics.IncCounter(a.metrics.Voter_ProposalsBad)
		return xerrors.New("invalid proposal")
	}
	metrics.IncCounter(a.metrics.Voter_ProposalsGood)

	// If the proposal comes from outside, add it to our local blockchain if needed.
	if ctx.creator == BlockCreatedByOther {
		sn := b.GetBlockSn()
		if a.chain.ContainsBlock(sn) {
			if b2 := a.chain.GetBlock(sn); b2 == nil {
				debug.Bug("BlockChain's ContainsBlock() and GetBlock() are inconsistent at %s", sn)
			} else if b.GetHash() != b2.GetHash() {
				// We only store blocks with "proofs", i.e., either a notarized block or a proposal.
				// There is no way to have a different proposal at the same BlockSn.
				h1 := b.GetHash()
				h2 := b2.GetHash()
				return xerrors.Errorf("two proposal at %s have different hash; new vs. old: "+
					"%s != %s; reject the new one", sn, hex.EncodeToString(h1[:]), hex.EncodeToString(h2[:]))
			}
		} else {
			// To avoid double voting on the same BlockSn, insert the block before voting on the proposal.
			if err := a.onReceivedBlock(b, ctx.creator, false); err != nil {
				if utils.IsTemporaryError(err) {
					a.addUnvotedProposal(p, ctx)
					a.client.CatchUp(ctx.source, b.GetParentBlockSn())
					return err
				}
				logger.Warn("[%s] onReceivedProposal: failed to insert block %s; err=%s",
					a.loggingId, p.GetBlockSn(), err)
				return err
			}
		}
	}

	if !isVoter {
		return nil
	}

	fnSn := a.chain.GetFreshestNotarizedHeadSn()
	sn := b.GetBlockSn()
	r := fnSn.Epoch.Compare(sn.Epoch)
	k := uint32(a.k.GetValueAtSession(int64(sn.Epoch.Session)))
	if r == 0 {
		if sn.S > fnSn.S+k {
			a.addUnvotedProposal(p, ctx)
			return xerrors.Errorf("Exceed the outstanding window (%d): %s > %s",
				k, sn, fnSn)
		}
	} else if r > 0 {
		debug.Bug("the epoch of the freshest notarized block %s"+
			"is newer than proposal %s and local epoch %s", fnSn, sn, a.epoch)
	} else {
		// Our freshest notarized head is at a previous epoch.
		if sn.S > k {
			// The voting period has ended.
			a.client.CatchUp(ctx.source, b.GetParentBlockSn())
			return xerrors.Errorf("skip proposal %s because S > k=%d and local epoch=%s is different",
				sn, k, a.epoch)
		}
		// We may have a chance to vote. Ensure blocks before the proposal's epoch (sn.Epoch)
		// are already notarized.
		firstSn := blockchain.BlockSn{Epoch: sn.Epoch, S: 1}
		first := a.chain.GetBlock(firstSn)
		if first == nil {
			a.client.CatchUp(ctx.source, b.GetParentBlockSn())
			return xerrors.Errorf(
				"skip proposal %s because we don't have the first block at this epoch", sn)
		}
		lastSnInPreviousEpoch := first.GetParentBlockSn()
		r := lastSnInPreviousEpoch.Compare(fnSn)
		if r != 0 {
			if r < 0 {
				return xerrors.Errorf("skip proposal %s because the parent of %s is %s which "+
					"is older than our freshest notarized head %s", sn, firstSn, lastSnInPreviousEpoch, fnSn)
			} else {
				a.client.CatchUp(ctx.source, lastSnInPreviousEpoch)
				return xerrors.Errorf("skip proposal %s because the parent of %s is %s which "+
					"is newer than our freshest notarized head %s", sn, firstSn, lastSnInPreviousEpoch, fnSn)
			}
		}
	}

	vote, err := a.verifier.Vote(p)
	if err != nil {
		return err
	}
	metrics.IncCounter(a.metrics.Voter_ProposalsVoted)
	a.voted.ReplaceOrInsert(&Item{p.GetBlockSn(), true})

	if a.role.IsPrimaryProposer(UseMyId, p.GetBlockSn().Epoch) {
		return a.onReceivedVote(vote)
	}
	a.client.Reply(ctx.source, vote)
	return nil
}

func (a *Actor) addUnvotedProposal(p blockchain.Proposal, ctx proposalContext) {
	a.unvotedProposals.ReplaceOrInsert(&Item{
		p.GetBlockSn(),
		&proposalArguments{p, ctx},
	})
	k := a.k.GetValueAtSession(int64(p.GetBlockSn().Epoch.Session))
	if a.unvotedProposals.Len() > int(k) {
		a.unvotedProposals.DeleteMin()
	}
}

// Run in the worker goroutine
// This function is only called on proposers.
func (a *Actor) onReceivedVote(v blockchain.Vote) error {
	logger.Info("[%s] onReceivedVote: %s by %s",
		a.loggingId, v.GetBlockSn(), a.role.GetShortName(v.GetVoterId()))

	if a.byzantineClient != nil {
		if err := a.byzantineClient.onReceivedVote(a, v); err != nil {
			return err
		}
	}

	if a.epoch != v.GetBlockSn().Epoch {
		return xerrors.Errorf("skip vote %s because epoch=%d is different", v.GetBlockSn(), a.epoch)
	}

	if !a.role.IsPrimaryProposer(UseMyId, v.GetBlockSn().Epoch) {
		return xerrors.Errorf("received unexpected vote: %s", v.GetBlockSn())
	}

	// Check whether Actor has received it before verifying it
	// because the computation cost of verifying is higher than the check.
	votes, ok := a.votes[v.GetBlockSn()]
	if !ok {
		votes = make(map[ConsensusId]blockchain.Vote)
		a.votes[v.GetBlockSn()] = votes
	}
	if _, ok := votes[v.GetVoterId()]; ok {
		// Have received.
		return nil
	}
	// TODO(anthony): how to update vote-related metrics since its not verified?
	if proposalSentTime, ok := a.proposalSentTime[v.GetBlockSn()]; ok {
		metrics.ObserveHistogram(a.metrics.Proposer_ProposalResponseTime, time.Since(proposalSentTime).Seconds())
	}
	votes[v.GetVoterId()] = v
	var vs []blockchain.Vote
	for _, t := range votes {
		vs = append(vs, t)
	}

	nota, err := a.verifier.Notarize(vs, a.chain)
	if err != nil {
		// Votes are not enough to create the notarization.
		return nil
	}
	if !a.isNotarizationBroadcasted(nota.GetBlockSn()) {
		// Broadcast the notarization to minimize the chance of losing the last K blocks
		// when a propose switch occurs. Otherwise, only the primary proposer knows the
		// notarizations of the last K blocks.
		a.client.Broadcast(nota)
		a.broadcastedNotas[nota.GetBlockSn()] = true
	}
	// To collect late votes, always add the notarization to the chain.
	return a.onReceivedNotarization(nota)
}

// Possible callers:
// * Received enough votes -> a new notarization.
// * Received a new block which contains some notarizations.
// * Actively pull notarization from the other nodes.
//
// Run in the worker goroutine
func (a *Actor) onReceivedNotarization(nota blockchain.Notarization) error {
	logger.Info("[%s] onReceivedNotarization: %s", a.loggingId, nota.GetBlockSn())

	if a.byzantineClient != nil {
		if err := a.byzantineClient.onReceivedNotarization(a, nota); err != nil {
			return err
		}
	}

	// Ensure the node stores the block before the notarization. This ensures the freshest
	// notarized chain grows in order. Maybe this is not necessary.
	if !a.chain.ContainsBlock(nota.GetBlockSn()) {
		logger.Debug("[%s] onReceivedNotarization: %s (reject early notarization)",
			a.loggingId, nota.GetBlockSn())
		return nil
	}

	existedNota := a.chain.GetNotarization(nota.GetBlockSn())
	if existedNota != nil && existedNota.GetNVote() >= nota.GetNVote() {
		metrics.IncCounter(a.metrics.Voter_NotarizationsDup)
		return nil
	}
	if err := a.verifier.VerifyNotarization(nota, a.chain); err != nil {
		metrics.IncCounter(a.metrics.Voter_NotarizationsBad)
		return xerrors.Errorf("invalid notarization %s (received notarization); err=%s",
			nota.GetBlockSn(), err)
	}
	metrics.IncCounter(a.metrics.Voter_NotarizationsGood)
	metrics.SetGauge(a.metrics.FastPathHeight, int64(a.chain.GetBlock(nota.GetBlockSn()).GetNumber()))
	if proposalSentTime, ok := a.proposalSentTime[nota.GetBlockSn()]; ok {
		metrics.ObserveHistogram(a.metrics.Proposer_ProposalNotarizedTime, time.Since(proposalSentTime).Seconds())
	}
	return a.chain.AddNotarization(nota)
}

// Only called by proposer
// This function is only called on proposers.
func (a *Actor) onReceivedClockMsg(c blockchain.ClockMsg) error {
	logger.Info("[%s] onReceivedClockMsg: %d by %s", a.loggingId, c.GetEpoch(), c.GetVoterId())

	if a.byzantineClient != nil {
		if err := a.byzantineClient.onReceivedClockMsg(a, c); err != nil {
			return err
		}
	}

	nextEpoch := c.GetEpoch()
	if a.epoch.Compare(nextEpoch) > 0 {
		return xerrors.Errorf("skip clock(%d) by %s because epoch=%d is larger",
			nextEpoch, c.GetVoterId(), a.epoch)
	}

	if !a.role.IsProposer(UseMyId, a.epoch.Session) &&
		!a.role.IsProposer(UseMyId, nextEpoch.Session) {
		return xerrors.Errorf("a node not a proposer received an unexpected clock(%d) by %s "+
			"(local epoch=%d)", nextEpoch, c.GetVoterId(), a.epoch)
	}

	// Check whether Actor has received it before verifying it
	// because the computation cost of verifying is high.
	if t, ok := a.clockMsgs[c.GetVoterId()]; ok && t.GetEpoch().Compare(nextEpoch) >= 0 {
		// Have received.
		return nil
	}
	if err := a.verifier.VerifyClockMsg(c); err != nil {
		return err
	}
	a.clockMsgs[c.GetVoterId()] = c

	var cs []blockchain.ClockMsg
	for _, t := range a.clockMsgs {
		if t.GetEpoch() == nextEpoch {
			cs = append(cs, t)
		}
	}
	if cNota, err := a.verifier.NewClockMsgNota(cs); err != nil {
		if err == blockchain.ErrNotEnoughVotes {
			// ClockMsgs are not enough to create the notarization.
			logger.Info("[%s] received %d of %d clock(%d) messages "+
				"(not enough to make a clock message notarization)",
				a.loggingId, len(cs), a.role.GetNumVoters(nextEpoch.Session), c.GetEpoch())
		} else {
			logger.Warn("[%s] Failed to create ClockMsgNota: %s", a.loggingId, err)
		}
		return nil
	} else {
		// NOTE:
		// 1. ClockMsgNota is important. It's okay to broadcast multiple times
		// whenever we have more ClockMsg, although this is not necessary.
		// 2. The proposer should perform reconciliation *after* advancing the epoch,
		// so call Broadcast() before onReceivedClockMsgNota().
		a.client.Broadcast(cNota)
		logger.Info("[%s] broadcast notarization of clock(%d)", a.loggingId, cNota.GetEpoch())
		return a.onReceivedClockMsgNota(cNota)
	}
}

// Run in the worker goroutine
func (a *Actor) onReceivedClockMsgNota(cNota blockchain.ClockMsgNota) error {
	logger.Info("[%s] onReceivedClockMsgNota: %d", a.loggingId, cNota.GetEpoch())

	if a.byzantineClient != nil {
		if err := a.byzantineClient.onReceivedClockMsgNota(a, cNota); err != nil {
			return err
		}
	}

	if err := a.verifier.VerifyClockMsgNota(cNota); err != nil {
		return xerrors.Errorf("invalid clock message notarization for epoch=%d; err=%s",
			cNota.GetEpoch(), err)
	} else if cNota.GetEpoch().Compare(a.epoch) <= 0 {
		return nil
	} else {
		a.client.UpdateEpoch(cNota)
		return nil
	}
}

// Run in the worker goroutine
func (a *Actor) onReceivedFreshestNotarizedChainExtendedEvent(
	e blockchain.FreshestNotarizedChainExtendedEvent) error {
	logger.Info("[%s] onReceivedFreshestNotarizedChainExtendedEvent: %s", a.loggingId, e.Sn)

	if a.byzantineClient != nil {
		if err := a.byzantineClient.onReceivedFreshestNotarizedChainExtendedEvent(a, e); err != nil {
			return err
		}
	}

	ps := a.unvotedProposals
	var lastVoted blockchain.BlockSn
	ps.AscendGreaterOrEqual(ps.Min(), func(item llrb.Item) bool {
		args := item.(*Item).value.(*proposalArguments)
		if err := a.onReceivedProposal(args.p, args.ctx); err != nil {
			return false
		}
		lastVoted = args.p.GetBlockSn()
		return true
	})

	cleanUpOldData(ps, lastVoted)

	return nil
}

// Run in the worker goroutine
func (a *Actor) onReceivedFinalizedChainExtendedEvent(
	e blockchain.FinalizedChainExtendedEvent) error {
	logger.Info("[%s] onReceivedFinalizedChainExtendedEvent: %s", a.loggingId, e.Sn)

	if a.byzantineClient != nil {
		if err := a.byzantineClient.onReceivedFinalizedChainExtendedEvent(a, e); err != nil {
			return err
		}
	}

	if proposalSentTime, ok := a.proposalSentTime[e.Sn]; ok {
		metrics.ObserveHistogram(a.metrics.Proposer_ProposalFinalizedTime, time.Since(proposalSentTime).Seconds())
	}

	// Clean up unnecessary data.
	for sn := range a.votes {
		if sn.Compare(e.Sn) <= 0 {
			delete(a.votes, sn)
		}
	}
	for sn := range a.broadcastedNotas {
		if sn.Compare(e.Sn) <= 0 {
			delete(a.broadcastedNotas, sn)
		}
	}
	for sn := range a.proposalSentTime {
		if sn.Compare(e.Sn) <= 0 {
			delete(a.proposalSentTime, sn)
		}
	}
	for id, c := range a.clockMsgs {
		if c.GetEpoch().Compare(e.Sn.Epoch) <= 0 {
			delete(a.clockMsgs, id)
		}
	}
	cleanUpOldData(a.voted, e.Sn)

	// TODO(thunder): delete out-of-date data in n.chain.

	return nil
}

func (a *Actor) onReceivedNotarizedBlock(nota blockchain.Notarization, b blockchain.Block) error {
	logger.Info("[%s] onReceivedNotarizedBlock: %s %s", a.loggingId, nota.GetBlockSn(), b.GetBlockSn())

	if a.byzantineClient != nil {
		if err := a.byzantineClient.onReceivedNotarizedBlock(a, nota, b); err != nil {
			return err
		}
	}

	if nota.GetBlockSn() != b.GetBlockSn() {
		return xerrors.Errorf("BlockSn mismatched %s != %s", nota.GetBlockSn(), b.GetBlockSn())
	}
	if nota.GetBlockHash() != b.GetHash() {
		h1 := nota.GetBlockHash()
		h2 := b.GetHash()
		return xerrors.Errorf("hash mismatched %s != %s",
			hex.EncodeToString(h1[:]), hex.EncodeToString(h2[:]))
	}

	if err := a.verifier.VerifyNotarizationWithBlock(nota, b); err != nil {
		return xerrors.Errorf("invalid notarization %s (received notarized block): %w",
			nota.GetBlockSn(), err)
	}

	if !a.chain.ContainsBlock(b.GetBlockSn()) {
		if err := a.onReceivedBlock(b, BlockCreatedByOther, false); err != nil {
			return err
		}
	} else {
		b2 := a.chain.GetBlock(b.GetBlockSn())
		if b2.GetHash() != b.GetHash() {
			h1 := b.GetHash()
			h2 := b2.GetHash()
			logger.Warn("block %s: old hash is %s but new hash is %s; override the old one",
				b.GetBlockSn(), hex.EncodeToString(h2[:]), hex.EncodeToString(h1[:]))
			if err := a.onReceivedBlock(b, BlockCreatedByOther, true); err != nil {
				return err
			}
		}
	}
	return a.onReceivedNotarization(nota)
}

func (a *Actor) Timeout() error {
	logger.Note("[%s] timeout at epoch %d", a.loggingId, a.epoch)
	if !a.role.IsVoter(UseMyId, a.epoch.Session) {
		return nil
	}
	return a.onTimeout()
}

func (a *Actor) SetEpoch(epoch blockchain.Epoch) error {
	if epoch.Compare(a.epoch) <= 0 {
		msg := fmt.Sprintf("skip update epoch %s <= %s", epoch, a.epoch)
		logger.Info("[%s] %s", a.loggingId, msg)
		return xerrors.New(msg)
	}

	logger.Info("[%s] update epoch %s -> %s", a.loggingId, a.epoch, epoch)
	a.epoch = epoch
	a.LogMetrics()
	a.lastEpochMetrics = a.metrics.AdvanceLocalEpoch(uint32(epoch.Session), uint32(epoch.E))
	return nil
}

func (a *Actor) AddBlock(b blockchain.Block, creator BlockCreator) error {
	return a.onReceivedBlock(b, creator, false)
}

func (a *Actor) AddProposal(
	p blockchain.Proposal, msg *network.Message, creator BlockCreator) error {
	return a.onReceivedProposal(p, proposalContext{msg, creator})
}

func (a *Actor) AddVote(v blockchain.Vote) error {
	return a.onReceivedVote(v)
}

func (a *Actor) AddNotarization(nota blockchain.Notarization) error {
	return a.onReceivedNotarization(nota)
}

func (a *Actor) AddClockMsg(c blockchain.ClockMsg) error {
	return a.onReceivedClockMsg(c)
}

func (a *Actor) AddClockMsgNota(cn blockchain.ClockMsgNota) error {
	return a.onReceivedClockMsgNota(cn)
}

// AddNotarizedBlocks assumes notarizations in `notas` and blocks in `bs` are in order
// and `notas[i]` matches `bs[i]`. The operation verify notarizations and blocks and
// add valid ones into the chain.
func (a *Actor) AddNotarizedBlocks(notas []blockchain.Notarization, bs []blockchain.Block,
) ([]blockchain.Notarization, []blockchain.Block, error) {
	// TODO(thunder): verify notas in parallel.
	if len(notas) != len(bs) {
		return nil, nil, xerrors.Errorf("# of notas (%d) != # of bs (%d)", len(notas), len(bs))
	}

	for i := 0; i < len(notas); i++ {
		if err := a.onReceivedNotarizedBlock(notas[i], bs[i]); err != nil {
			if i > 0 && xerrors.Is(err, blockchain.ErrMissingElectionResult) {
				err = utils.NewTemporaryError(err, true)
			}
			return notas[i:], bs[i:], err
		}
	}
	return nil, nil, nil
}

func (a *Actor) AddFreshestNotarizedChainExtendedEvent(
	event blockchain.FreshestNotarizedChainExtendedEvent) error {
	return a.onReceivedFreshestNotarizedChainExtendedEvent(event)
}

func (a *Actor) AddFinalizedChainExtendedEvent(
	event blockchain.FinalizedChainExtendedEvent) error {
	return a.onReceivedFinalizedChainExtendedEvent(event)
}

func (a *Actor) isVoted(sn blockchain.BlockSn) bool {
	return LLRBItemToBool(a.voted.Get(ToItem(sn)))
}

func (a *Actor) isNotarizationBroadcasted(sn blockchain.BlockSn) bool {
	return a.broadcastedNotas[sn]
}

// LogMetrics logs current state of metrics if available or fails silently otherwise
func (a *Actor) LogMetrics() {
	metricsOut, err := metrics.PrintMetricsUsingReflection(a.loggingId, &a.metrics, a.lastEpochMetrics)
	if err == nil {
		logger.Note(metricsOut)
	}
}

//--------------------------------------------------------------------

func (i *Item) Less(other llrb.Item) bool {
	return i.key.Compare(other.(*Item).key) < 0
}

func ToItem(sn blockchain.BlockSn) *Item {
	return &Item{sn, nil}
}

func LLRBItemToBool(item llrb.Item) bool {
	if item == nil {
		return false
	}
	return item.(*Item).value.(bool)
}

func cleanUpOldData(tree *llrb.LLRB, sn blockchain.BlockSn) int {
	count := 0
	min := tree.Min()
	for min != nil && min.(*Item).key.Compare(sn) <= 0 {
		count++
		tree.DeleteMin()
		min = tree.Min()
	}
	return count
}
