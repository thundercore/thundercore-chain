package chainsync

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/stretchr/testify/require"
)

// Simulate the ChainSyncerClient in the node under test.
// It reads data in `reader ` and get data from `peers`.
type clientFake struct {
	// When the freshest notarized chain extends, notify the observer via `chainEvent`.
	// This is used to simulate getting data asynchronously.
	chainEvent chan blockchain.BlockSn
	epochEvent chan blockchain.Epoch
	errorEvent chan interface{}

	// The node's data.
	chain *chainFake
	// Simulate data stored in the other nodes.
	peers map[ConsensusId]chainReader
	// Simulate no response
	pausedPeers    map[ConsensusId]bool
	pausedRequests map[ConsensusId][]request
	// Record this node sends unnotarized proposals to which peers.
	proposalToPeers []ConsensusId
}

type requestType int

const (
	requestEpoch = requestType(1)
	requestBlock = requestType(2)
)

type request struct {
	typ  requestType
	args interface{}
}

// chainFake implements chainReader
// To simplify the code, chainFake does not check the rules when updating the data.
// The testing code must use it correctly.
type chainFake struct {
	blocks        map[blockchain.BlockSn]blockchain.Block
	notas         map[blockchain.BlockSn]blockchain.Notarization
	clockMsgNotas map[blockchain.Session]blockchain.ClockMsgNota
	freshestHead  blockchain.BlockSn
	finalizedHead blockchain.BlockSn
	stopBlock     blockchain.Block
	// Pala's consensus parameter
	k uint32
}

type clockFake struct {
	now time.Time
}

type roleFake struct {
	voters map[ConsensusId]bool
}

type peerIsInconsistent struct {
	id            ConsensusId
	finalizedHead BlockInfo
}

var genesisBlockFake = newBlockFake(
	blockchain.GetGenesisBlockSn(), blockchain.GetGenesisBlockSn(), 0)

//--------------------------------------------------------------------

func newBlockSn(session, epoch, s uint32) blockchain.BlockSn {
	return blockchain.NewBlockSn(session, epoch, s)
}

func newEpoch(session, e uint32) blockchain.Epoch {
	return blockchain.NewEpoch(session, e)
}

func newBlockFake(sn blockchain.BlockSn, parentSn blockchain.BlockSn, nBlock uint64,
) blockchain.Block {
	return blockchain.NewBlockFake(sn, parentSn, nBlock, nil, nil, sn.String())
}

func newConsecutiveBlocks(
	chain []blockchain.Block, e blockchain.Epoch, endS int,
) []blockchain.Block {
	parentSn := chain[len(chain)-1].GetBlockSn()
	parentHeight := chain[len(chain)-1].GetNumber()
	sn := newBlockSn(uint32(e.Session), e.E, 1)
	for i := 1; i <= endS; i++ {
		chain = append(chain, newBlockFake(sn, parentSn, parentHeight+uint64(i)))
		parentSn = sn
		sn.S++
	}
	return chain
}

func newChainSyncer(client ChainSyncerClient) *ChainSyncer {
	return NewChainSyncer(Config{
		LoggingId:               "me",
		Client:                  client,
		Role:                    newRoleFake(nil),
		Clock:                   &clockFake{},
		MaxRequestWaitingPeriod: time.Second,
		TimeoutToRetryPeriod:    time.Second,
		RpcMaxDelayBlock:        1,
	})
}

func verifyEpoch(
	req *require.Assertions, syncer *ChainSyncer, client *clientFake, target blockchain.Epoch,
) {
	for {
		select {
		case e := <-client.epochEvent:
			syncer.SetMyEpoch(e)
			if e.Compare(target) == 0 {
				return
			}
		default:
			req.FailNow(fmt.Sprintf("failed to sync up to epoch %s", target))
		}
	}
}

func verifyChain(
	req *require.Assertions, syncer *ChainSyncer, client *clientFake, target blockchain.BlockSn,
) {
	for {
		select {
		case sn := <-client.chainEvent:
			if sn.S == 1 {
				// NOTE: We enter a new epoch. In the real implementation, there is a
				// ClockMsgNota in the first block of each epoch, so we'll also update the epoch.
				syncer.SetMyEpoch(sn.Epoch)
			}
			syncer.SetMyFreshestNotarizedHead(sn)
			if sn.Compare(target) == 0 {
				return
			}
		default:
			req.FailNow(fmt.Sprintf("failed to sync up to block %s", target))
		}
	}
}

func verifyError(req *require.Assertions, syncer *ChainSyncer, client *clientFake) {
	select {
	case e := <-client.errorEvent:
		if p, ok := e.(peerIsInconsistent); ok {
			syncer.SetPeerIsInconsistent(p.id, p.finalizedHead)
		} else {
			req.FailNow("unexpected error %v", e)
		}
	default:
		req.FailNow("no error")
	}
}

func blockAdvanced(syncer *ChainSyncer, client *clientFake, addToChain bool) bool {
	select {
	case sn := <-client.chainEvent:
		if addToChain {
			syncer.SetMyFreshestNotarizedHead(sn)
		}
		return true
	default:
		return false
	}
}

func epochAdvanced(syncer *ChainSyncer, client *clientFake, addToChain bool) bool {
	select {
	case e := <-client.epochEvent:
		if addToChain {
			client.chain.advanceEpoch(e)
		}
		return true
	default:
		return false
	}
}

func verifyNoProgress(req *require.Assertions, client *clientFake) {
	select {
	case e := <-client.epochEvent:
		req.FailNow("got epoch event %s", e)
	case sn := <-client.chainEvent:
		req.FailNow("got chain event %s", sn)
	default:
		return
	}
}

func setOffline(syncer *ChainSyncer, client *clientFake, id ConsensusId) {
	syncer.SetPeerOffline(id)
	client.setOffline(id)
}

//------------------------------------------------------------------------------

func newClientFake(chain *chainFake, peers map[ConsensusId]chainReader) *clientFake {
	return &clientFake{
		chainEvent:     make(chan blockchain.BlockSn, 1024),
		epochEvent:     make(chan blockchain.Epoch, 1024),
		errorEvent:     make(chan interface{}, 1024),
		chain:          chain,
		peers:          peers,
		pausedPeers:    make(map[ConsensusId]bool),
		pausedRequests: make(map[ConsensusId][]request),
	}
}

// RequestEpoch is the implementation reference for the real usage.
func (c *clientFake) RequestEpoch(id ConsensusId, session blockchain.Session) {
	logger.Info("Client.RequestEpoch id=%s, session=%d", id, session)

	if c.pausedPeers[id] {
		c.pausedRequests[id] = append(c.pausedRequests[id], request{requestEpoch, session})
		return
	}

	// Requesting the epoch is straightforward.
	// Skip the network transmission and simulate that we get the data from the peer.
	var cNota blockchain.ClockMsgNota
	if reader, ok := c.peers[id]; ok {
		cNota = reader.(*chainFake).getLatestClockMsgNota(session)
	}

	// Skip the verification and simulate that we added the data into our local chain.
	if cNota != nil {
		if c.chain.advanceEpoch(cNota.GetEpoch()) {
			c.epochEvent <- cNota.GetEpoch()
		}
	}
}

func (c *clientFake) SendUnnotarizedProposals(id ConsensusId) {
	logger.Info("Client.SendUnnotarizedProposals id=%s", id)

	c.proposalToPeers = append(c.proposalToPeers, id)
}

// RequestNotarizedBlocks is the implementation reference for the real usage.
func (c *clientFake) RequestNotarizedBlocks(id ConsensusId) {
	// Build the request.
	logger.Info("Client.RequestNotarizedBlocks id=%s", id)

	if c.pausedPeers[id] {
		c.pausedRequests[id] = append(c.pausedRequests[id], request{requestBlock, nil})
		return
	}

	head, ids, err := NewRequest(c.chain)
	if err != nil {
		logger.Info("> newRequest: id=%s, err=%s", id, err)
		return
	}

	// Skip the network transmission and simulate that we get the data from the peer.
	nExtended := 1
	nbs, err := FindNextBlocks(c.peers[id], head, ids, nExtended)
	if err != nil {
		logger.Info("> FindNextBlocks: id=%s, err=%s", id, err)
		if fe, ok := err.(FinalizedHeadNotFoundError); ok {
			c.errorEvent <- peerIsInconsistent{id, fe.myFinalizedHead}
		}
		return
	}

	unmarshaller := blockchain.DataUnmarshallerFake{}
	blockDecoder := blockchain.BlockFakeDecoder{}

	// Skip the verification and simulate that we added the data into our local chain.
	for _, nb := range nbs {
		rawBlock, err := blockDecoder.ToRawBlock(nb.Header, nb.BlockBody)
		if err != nil {
			logger.Error("err=%v", err)
			return
		}

		block, _, err := unmarshaller.UnmarshalBlock(rawBlock)
		if err != nil {
			logger.Error("err=%v", err)
			return
		}

		nota, _, err := unmarshaller.UnmarshalNotarization(nb.Nota)
		if err != nil {
			logger.Error("err=%v", err)
			return
		}

		if c.chain.add(block, nota) {
			c.chainEvent <- block.GetBlockSn()
		}
	}
}

// pause is used to simulate the peer doesn't respond the message in time.
func (c *clientFake) pause(id ConsensusId) {
	c.pausedPeers[id] = true
}

// resume is used to simulate the peer responds or skips the message after a while.
func (c *clientFake) resume(id ConsensusId, skip bool) {
	delete(c.pausedPeers, id)
	rs := c.pausedRequests[id]
	delete(c.pausedRequests, id)
	if skip {
		return
	}
	for _, r := range rs {
		switch r.typ {
		case requestEpoch:
			c.RequestEpoch(id, r.args.(blockchain.Session))
		case requestBlock:
			c.RequestNotarizedBlocks(id)
		}
	}
}

func (c *clientFake) setOffline(id ConsensusId) {
	delete(c.pausedPeers, id)
	delete(c.pausedRequests, id)
}

func (c *clientFake) getSentUnnotarizedProposalPeers() []ConsensusId {
	return c.proposalToPeers
}

func (c *clientFake) resetSentUnnotarizedProposalPeers() {
	c.proposalToPeers = nil
}

//------------------------------------------------------------------------------

func newChainFake(
	blocks []blockchain.Block, finalizedHead blockchain.BlockSn,
	stopBlock blockchain.Block, k uint32,
) *chainFake {
	c := chainFake{
		blocks:        make(map[blockchain.BlockSn]blockchain.Block),
		notas:         make(map[blockchain.BlockSn]blockchain.Notarization),
		clockMsgNotas: make(map[blockchain.Session]blockchain.ClockMsgNota),
		freshestHead:  blocks[len(blocks)-1].GetBlockSn(),
		finalizedHead: finalizedHead,
		stopBlock:     stopBlock,
		k:             k,
	}
	for _, b := range blocks {
		sn := b.GetBlockSn()
		c.blocks[sn] = b
		// The genesis block has no notarization.
		if sn.IsPala() {
			c.notas[sn] = blockchain.NewNotarizationFake(sn, nil)
		}
		c.advanceEpoch(sn.Epoch)
	}
	return &c
}

// add adds `nb` and return true if `nb` does not exist before.
// Note that add only check the minimal necessary consensus rules.
func (c *chainFake) add(block blockchain.Block, nota blockchain.Notarization) bool {
	logger.Info("chainFake add %s", block.GetDebugString())
	sn := block.GetBlockSn()
	if _, ok := c.blocks[sn]; ok {
		return false
	}

	c.blocks[sn] = block
	c.notas[sn] = nota
	// We don't verify the "freshest notarized chain" rule for simplicity.
	if sn.Compare(c.freshestHead) > 0 {
		c.freshestHead = sn
		logger.Info("freshestHead %s", c.freshestHead)
		if sn.S > c.k {
			newHead := sn
			newHead.S -= c.k
			if newHead.Compare(c.finalizedHead) > 0 {
				c.finalizedHead = newHead
				logger.Info("> finalizedHead %s", c.finalizedHead)
			}
		}
	}
	return true
}

// chainFake advance the local epoch to `e` if `e` is newer.
// Note that advanceEpoch only check the minimal necessary consensus rules.
func (c *chainFake) advanceEpoch(e blockchain.Epoch) bool {
	// Create ClockMsgNota if not existed.
	cNota, ok := c.clockMsgNotas[e.Session]
	if !ok || e.Compare(cNota.GetEpoch()) > 0 {
		c.clockMsgNotas[e.Session] = blockchain.NewClockMsgNotaFake(e, nil)
		return true
	}
	return false
}

func (c *chainFake) GetFreshestNotarizedHead() blockchain.Block {
	return c.blocks[c.freshestHead]
}

func (c *chainFake) GetFinalizedHead() blockchain.Block {
	return c.blocks[c.finalizedHead]
}

func (c *chainFake) GetBlock(s blockchain.BlockSn) blockchain.Block {
	return c.blocks[s]
}

func (c *chainFake) GetBlockByNumber(n uint64) blockchain.Block {
	for _, b := range c.blocks {
		if b.GetNumber() == n {
			return b
		}
	}
	return nil
}

func (c *chainFake) GetHeaderByNumber(n uint64) blockchain.Header {
	block := c.GetBlockByNumber(n)
	if block == nil {
		return nil
	}
	return &blockchain.HeaderFake{*block.(*blockchain.BlockFake)}
}

func (c *chainFake) GetRawBlockBody(hash blockchain.Hash) []byte {
	for _, b := range c.blocks {
		if b.GetHash() == hash {
			body := b.(*blockchain.BlockFake).GetBodyString()
			var out [][]byte
			out = append(out, utils.Uint32ToBytes(uint32(len(body))))
			out = append(out, []byte(body))
			return utils.ConcatCopyPreAllocate(out)
		}
	}
	return nil
}

func (c *chainFake) GetRawNotarization(s blockchain.BlockSn) []byte {
	if nota, ok := c.notas[s]; ok {
		return nota.GetBody()
	}
	return nil
}

func (c *chainFake) GetNotarization(s blockchain.BlockSn) blockchain.Notarization {
	return c.notas[s]
}

func (c *chainFake) GetLatestFinalizedStopBlock() blockchain.Block {
	return c.stopBlock
}

func (c *chainFake) getLatestClockMsgNota(session blockchain.Session) blockchain.ClockMsgNota {
	return c.clockMsgNotas[session]
}

//------------------------------------------------------------------------------

func (c *clockFake) Now() time.Time {
	return c.now
}

func (c *clockFake) addDuration(t time.Duration) {
	c.now = c.now.Add(t)
	logger.Info("clockFake advances to %s", c.now)
}

//------------------------------------------------------------------------------

func newRoleFake(ids []ConsensusId) *roleFake {
	r := &roleFake{voters: make(map[ConsensusId]bool)}
	for _, id := range ids {
		r.voters[id] = true
	}
	return r
}

func (r *roleFake) IsVoter(id ConsensusId, session blockchain.Session) bool {
	_, ok := r.voters[id]
	return ok
}

func (r *roleFake) IsReadyToPropose(ids []ConsensusId, session blockchain.Session) bool {
	return true
}

func (r *roleFake) GetShortName(id ConsensusId) string {
	return string(id)
}

//--------------------------------------------------------------------

func TestSyncEpoch(t *testing.T) {
	t.Run("peers are in the same session", func(t *testing.T) {
		// Setting:
		// me: (1, 1)
		// p1: (1, 2)
		// p2: (1, 3)
		req := require.New(t)

		k := uint32(1)
		chain := newConsecutiveBlocks(
			[]blockchain.Block{genesisBlockFake}, newEpoch(1, 1), 2)
		me := newChainFake(chain, newBlockSn(1, 1, 1), nil, k)
		p1 := newChainFake(chain, newBlockSn(1, 1, 1), nil, k)
		p2 := newChainFake(chain, newBlockSn(1, 1, 1), nil, k)
		me.advanceEpoch(newEpoch(1, 1))
		p1.advanceEpoch(newEpoch(1, 2))
		p2.advanceEpoch(newEpoch(1, 3))
		client := newClientFake(
			me,
			map[ConsensusId]chainReader{
				"p1": p1,
				"p2": p2,
			},
		)

		syncer := NewChainSyncer(Config{
			LoggingId:               "me",
			Client:                  client,
			Role:                    newRoleFake(nil),
			Clock:                   &clockFake{},
			MaxRequestWaitingPeriod: time.Second,
			TimeoutToRetryPeriod:    time.Second,
			RpcMaxDelayBlock:        1,
		})

		// Update status.
		syncer.SetMyStatus(NewStatus(1, 1, 2, "", 0))
		syncer.SetPeerStatus("p1", Status{
			FncBlockSn: newBlockSn(1, 1, 2),
			Epoch:      newEpoch(1, 2),
		})
		syncer.SetPeerStatus("p2", Status{
			FncBlockSn: newBlockSn(1, 1, 2),
			Epoch:      newEpoch(1, 3),
		})

		// Expect there is progress.
		verifyEpoch(req, syncer, client, newEpoch(1, 3))
	})

	t.Run("peers are in different sessions", func(t *testing.T) {
		// Setting:
		// me: (1, 1)
		// p1: (2, 1)
		req := require.New(t)

		targetEpoch := newEpoch(1, 5)
		k := uint32(1)
		chain := newConsecutiveBlocks(
			[]blockchain.Block{genesisBlockFake}, newEpoch(1, 1), 2)
		me := newChainFake(chain, newBlockSn(1, 1, 1), nil, k)
		p1 := newChainFake(chain, newBlockSn(1, 1, 1), nil, k)
		me.advanceEpoch(newEpoch(1, 1))
		p1.advanceEpoch(targetEpoch)
		p1.advanceEpoch(newEpoch(2, 1))
		client := newClientFake(
			me,
			map[ConsensusId]chainReader{"p1": p1},
		)

		syncer := NewChainSyncer(Config{
			LoggingId:               "me",
			Client:                  client,
			Role:                    newRoleFake(nil),
			Clock:                   &clockFake{},
			MaxRequestWaitingPeriod: time.Second,
			TimeoutToRetryPeriod:    time.Second,
			RpcMaxDelayBlock:        1,
		})

		// Update status.
		syncer.SetMyStatus(NewStatus(1, 1, 2, "", 0))
		syncer.SetPeerStatus("p1", Status{
			FncBlockSn: newBlockSn(1, 1, 2),
			Epoch:      newEpoch(2, 1),
		})

		// my epoch: (1,1), p1 epoch:(2,1)
		req.True(syncer.IsBlockChainBehind(), "block chain should be behind")
		// Verify.
		verifyEpoch(req, syncer, client, targetEpoch)
		// my epoch: (1,5), p1 epoch:(2,1)
		req.True(syncer.IsBlockChainBehind(), "block chain should be behind")

		// Try again: ensure ChainSyncer does not request an epoch in a newer session.
		p1.advanceEpoch(newEpoch(3, 1))
		syncer.SetPeerStatus("p1", Status{
			FncBlockSn: newBlockSn(1, 1, 2),
			Epoch:      newEpoch(3, 1),
		})

		// my epoch: (1,5), p1 epoch:(3,1)
		req.True(syncer.IsBlockChainBehind(), "block chain should be behind")
		// Verify.
		verifyNoProgress(req, client)
	})
}

func TestSyncNotarizedBlocks(t *testing.T) {
	t.Run("sync from genesis block", func(t *testing.T) {
		req := require.New(t)

		chain := newConsecutiveBlocks(
			[]blockchain.Block{genesisBlockFake}, newEpoch(1, 1), 4)

		k := uint32(1)
		client := newClientFake(
			newChainFake(chain[:1], blockchain.GetGenesisBlockSn(), nil, k),
			map[ConsensusId]chainReader{
				"p1": newChainFake(chain, newBlockSn(1, 1, 3), nil, k),
			},
		)
		syncer := NewChainSyncer(Config{
			LoggingId:               "me",
			Client:                  client,
			Role:                    newRoleFake(nil),
			Clock:                   &clockFake{},
			MaxRequestWaitingPeriod: time.Second,
			TimeoutToRetryPeriod:    time.Second,
			RpcMaxDelayBlock:        1,
		})

		// Update status.
		syncer.SetMyStatus(NewStatus(0, 0, 1, "", 0))
		syncer.SetPeerStatus("p1", NewStatus(1, 1, 4, "", 0))

		// Expect there is progress.
		req.True(syncer.IsBlockChainBehind(), "block chain should be behind")
		verifyChain(req, syncer, client, newBlockSn(1, 1, 4))
		req.False(syncer.IsBlockChainBehind(), "block chain should not be behind")
	})

	t.Run("freshest notarized head is in the other's freshest notarized chain", func(t *testing.T) {
		// Setting:
		//
		//   chain: (1,1,1) <- (1,1,2) <- (1,1,3) <- (1,1,4)
		//   node                [me]       [p1]       [p2]
		req := require.New(t)

		chain := newConsecutiveBlocks(
			[]blockchain.Block{genesisBlockFake}, newEpoch(1, 1), 4)

		k := uint32(1)
		client := newClientFake(
			newChainFake(chain[:1+2], newBlockSn(1, 1, 1), nil, k),
			map[ConsensusId]chainReader{
				"p1": newChainFake(chain[:1+3], newBlockSn(1, 1, 2), nil, k),
				"p2": newChainFake(chain, newBlockSn(1, 1, 3), nil, k),
			},
		)
		syncer := NewChainSyncer(Config{
			LoggingId:               "me",
			Client:                  client,
			Role:                    newRoleFake(nil),
			Clock:                   &clockFake{},
			MaxRequestWaitingPeriod: time.Second,
			TimeoutToRetryPeriod:    time.Second,
			RpcMaxDelayBlock:        1,
		})

		// Update status.
		syncer.SetMyStatus(NewStatus(1, 1, 2, "", 0))
		syncer.SetPeerStatus("p1", NewStatus(1, 1, 3, "", 0))
		syncer.SetPeerStatus("p2", NewStatus(1, 1, 4, "", 0))

		// Expect there is progress.
		req.True(syncer.IsBlockChainBehind(), "block chain should be behind")
		verifyChain(req, syncer, client, newBlockSn(1, 1, 4))
		req.False(syncer.IsBlockChainBehind(), "block chain should not be behind")
	})

	t.Run("freshest notarized head is not in the other's freshest notarized chain", func(t *testing.T) {
		// Setting (k=1):
		//                           [me]
		//   (1,1,1) <- (1,1,2) <- (1,1,3)
		//                 ^
		//                 |
		//              (1,2,1)
		//                [p1]
		req := require.New(t)

		myChain := newConsecutiveBlocks(
			[]blockchain.Block{genesisBlockFake}, newEpoch(1, 1), 3)
		p1Chain := newConsecutiveBlocks(
			[]blockchain.Block{genesisBlockFake}, newEpoch(1, 1), 2)
		p1Chain = newConsecutiveBlocks(p1Chain, newEpoch(1, 2), 1)

		k := uint32(1)
		client := newClientFake(
			newChainFake(myChain, newBlockSn(1, 1, 2), nil, k),
			map[ConsensusId]chainReader{
				"p1": newChainFake(p1Chain, newBlockSn(1, 1, 1), nil, k),
			},
		)
		syncer := newChainSyncer(client)

		// Update status.
		syncer.SetMyStatus(NewStatus(1, 1, 3, "", 0))
		syncer.SetPeerStatus("p1", NewStatus(1, 2, 1, "", 0))

		// Expect there is progress.
		req.True(syncer.IsBlockChainBehind(), "block chain should be behind")
		verifyEpoch(req, syncer, client, newEpoch(1, 2))
		req.True(syncer.IsBlockChainBehind(), "block chain should be behind")
		verifyChain(req, syncer, client, newBlockSn(1, 2, 1))
		req.False(syncer.IsBlockChainBehind(), "block chain should not be behind")
	})

	t.Run("freshest notarized head is not in the other's freshest notarized chain (2)", func(t *testing.T) {
		// Setting (k=1):
		//
		//   (1,1,1) <- (1,1,2) <- (1,1,3)
		//                 ^          ^
		//                 |          |
		//                 |       (1,2,1)
		//                 |         [me]
		//                 |
		//                 |
		//              (1,3,1)
		//                [p1]
		req := require.New(t)

		myChain := newConsecutiveBlocks(
			[]blockchain.Block{genesisBlockFake}, newEpoch(1, 1), 3)
		myChain = newConsecutiveBlocks(myChain, newEpoch(1, 2), 1)
		p1Chain := newConsecutiveBlocks(
			[]blockchain.Block{genesisBlockFake}, newEpoch(1, 1), 2)
		p1Chain = newConsecutiveBlocks(p1Chain, newEpoch(1, 3), 1)

		k := uint32(1)
		client := newClientFake(
			newChainFake(myChain, newBlockSn(1, 1, 2), nil, k),
			map[ConsensusId]chainReader{
				"p1": newChainFake(p1Chain, newBlockSn(1, 1, 1), nil, k),
			},
		)
		syncer := newChainSyncer(client)

		// Update status.
		syncer.SetMyStatus(NewStatus(1, 2, 1, "", 0))
		syncer.SetPeerStatus("p1", NewStatus(1, 3, 1, "", 0))

		// Expect there is progress.
		req.True(syncer.IsBlockChainBehind(), "block chain should be behind")
		verifyEpoch(req, syncer, client, newEpoch(1, 3))
		req.False(syncer.IsBlockChainBehind(), "block chain should not be behind")
		verifyChain(req, syncer, client, newBlockSn(1, 3, 1))
		req.False(syncer.IsBlockChainBehind(), "block chain should not be behind")
	})

	t.Run("freshest notarized head is older but finalized head is newer", func(t *testing.T) {
		// Setting (k=2):
		//                                      [me]
		//   (1,1,1) <- (1,1,2) <- (1,1,3) <- (1,1,4)
		//                 ^
		//                 |
		//              (1,2,1)
		//                [p1]
		req := require.New(t)

		myChain := newConsecutiveBlocks(
			[]blockchain.Block{genesisBlockFake}, newEpoch(1, 1), 4)
		p1Chain := newConsecutiveBlocks(
			[]blockchain.Block{genesisBlockFake}, newEpoch(1, 1), 2)
		p1Chain = newConsecutiveBlocks(p1Chain, newEpoch(1, 2), 1)

		k := uint32(2)
		client := newClientFake(
			newChainFake(myChain, newBlockSn(1, 1, 2), nil, k),
			map[ConsensusId]chainReader{
				"p1": newChainFake(p1Chain, p1Chain[0].GetBlockSn(), nil, k),
			},
		)
		syncer := newChainSyncer(client)

		// Update status.
		syncer.SetMyStatus(NewStatus(1, 1, 4, "", 0))
		syncer.SetPeerStatus("p1", NewStatus(1, 2, 1, "", 0))

		// Expect there is progress.
		req.True(syncer.IsBlockChainBehind(), "block chain should be behind")
		verifyEpoch(req, syncer, client, newEpoch(1, 2))
		req.True(syncer.IsBlockChainBehind(), "block chain should be behind")
		verifyChain(req, syncer, client, newBlockSn(1, 2, 1))
		req.False(syncer.IsBlockChainBehind(), "block chain should not be behind")
	})

	t.Run("finalized head is not in the other's finalized chain", func(t *testing.T) {
		// Setting (k=1):
		//                                      [me]
		//   (1,1,1) <- (1,1,2) <- (1,1,3) <- (1,1,4)
		//                 ^          ^
		//                 |          |
		//                 |       (1,2,1)
		//                 |         [p2]
		//              (1,3,1)
		//                [p1]
		req := require.New(t)

		myChain := newConsecutiveBlocks(
			[]blockchain.Block{genesisBlockFake}, newEpoch(1, 1), 4)
		p1Chain := newConsecutiveBlocks(
			[]blockchain.Block{genesisBlockFake}, newEpoch(1, 1), 2)
		p1Chain = newConsecutiveBlocks(p1Chain, newEpoch(1, 3), 1)
		p2Chain := newConsecutiveBlocks(
			[]blockchain.Block{genesisBlockFake}, newEpoch(1, 1), 3)
		p2Chain = newConsecutiveBlocks(p2Chain, newEpoch(1, 2), 1)

		k := uint32(1)
		client := newClientFake(
			newChainFake(myChain, newBlockSn(1, 1, 3), nil, k),
			map[ConsensusId]chainReader{
				"p1": newChainFake(p1Chain, newBlockSn(1, 1, 1), nil, k),
				"p2": newChainFake(p2Chain, newBlockSn(1, 1, 2), nil, k),
			},
		)
		syncer := newChainSyncer(client)

		// The node's finalized head is not in p1's finalized chain,
		// so the node won't fetch any new notarized block from p1.
		syncer.SetMyStatus(NewStatus(1, 1, 4, "", 0))
		syncer.SetPeerStatus("p1", NewStatus(1, 3, 1, "", 0))
		req.True(syncer.IsBlockChainBehind(), "block chain should be behind")
		verifyEpoch(req, syncer, client, newEpoch(1, 3))
		req.True(syncer.IsBlockChainBehind(), "block chain should be behind")
		verifyNoProgress(req, client)
		// Simulate getting the "inconsistent finalized head error".
		verifyError(req, syncer, client)

		// Expect requesting the block from p2 and have new progress.
		syncer.SetPeerStatus("p2", NewStatus(1, 2, 1, "", 0))
		req.True(syncer.IsBlockChainBehind(), "block chain should be behind")
		verifyChain(req, syncer, client, newBlockSn(1, 2, 1))
		req.False(syncer.IsBlockChainBehind(), "block chain should not be behind")
	})

	t.Run("there is a finalized chain fork after the stop block", func(t *testing.T) {
		// Setting (k=1, stop block is (1,1,3)):
		//
		//   (1,1,1) <- (1,1,2) <- (1,1,3) <- (1,1,4)
		//                            ^          ^
		//                            |          |
		//                            |          +-- (2,1,1) <- (2,1,2)
		//                            |                           [p1]
		//                            |
		//                            |         [me]
		//                         (1,2,1) <- (1,2,2)
		req := require.New(t)

		setup := func(stopBlock blockchain.Block) (*clientFake, *ChainSyncer) {
			myChain := newConsecutiveBlocks(
				[]blockchain.Block{genesisBlockFake}, newEpoch(1, 1), 3)
			myChain = newConsecutiveBlocks(myChain, newEpoch(1, 2), 2)
			p1Chain := newConsecutiveBlocks(
				[]blockchain.Block{genesisBlockFake}, newEpoch(1, 1), 4)
			p1Chain = newConsecutiveBlocks(p1Chain, newEpoch(2, 1), 2)

			k := uint32(1)
			client := newClientFake(
				newChainFake(myChain, newBlockSn(1, 2, 1), stopBlock, k),
				map[ConsensusId]chainReader{
					"p1": newChainFake(p1Chain, newBlockSn(2, 1, 1), stopBlock, k),
				},
			)
			syncer := newChainSyncer(client)
			syncer.SetMyStatus(Status{
				FncBlockSn: newBlockSn(1, 2, 2),
				Epoch:      newEpoch(2, 1),
			})
			syncer.SetPeerStatus("p1", Status{
				FncBlockSn: newBlockSn(2, 1, 2),
				Epoch:      newEpoch(2, 1),
			})
			return client, syncer
		}

		// Case 1: Stop block is not set. Expect error due to the finalize chain fork.
		client, syncer := setup(nil)
		verifyError(req, syncer, client)

		// Case 2: Set the stop block. Expect it works.
		client, syncer = setup(newBlockFake(newBlockSn(1, 1, 3), newBlockSn(1, 1, 2), 3))
		verifyChain(req, syncer, client, newBlockSn(2, 1, 2))
	})

	t.Run("sync from pointfive", func(t *testing.T) {
		// Setting (k=1):
		//                           [me]
		//   (0,1,1) <- (0,1,2) <- (0,1,3)
		//                            ^
		//                            |
		//                         (1,1,1) <- (1,1,2) <- (1,1,3)
		//                                                 [p1]
		req := require.New(t)

		myChain := newConsecutiveBlocks(
			[]blockchain.Block{genesisBlockFake}, newEpoch(0, 1), 3)
		p1Chain := newConsecutiveBlocks(
			[]blockchain.Block{genesisBlockFake}, newEpoch(0, 1), 3)
		p1Chain = newConsecutiveBlocks(p1Chain, newEpoch(1, 1), 3)

		k := uint32(1)
		client := newClientFake(
			newChainFake(myChain, newBlockSn(0, 1, 3), nil, k),
			map[ConsensusId]chainReader{
				"p1": newChainFake(p1Chain, newBlockSn(1, 1, 1), nil, k),
			},
		)
		syncer := newChainSyncer(client)

		// Update status.
		syncer.SetMyStatus(NewStatus(0, 1, 3, "", 0))
		syncer.SetPeerStatus("p1", NewStatus(1, 1, 3, "", 0))

		// Expect there is progress.
		verifyChain(req, syncer, client, newBlockSn(1, 1, 3))
	})

}

func TestSyncTimeout(t *testing.T) {
	t.Run("syncing is timeout after a while", func(t *testing.T) {
		// This may happen due to many reasons. E.g.,
		// * We cannot deliver the request to the designated node.
		// * The designated node has not enough resource to respond.
		// * The designated node is dishonest.
		//
		// Setting:
		//
		//   chain: (1,1,1) <- (1,1,2) <- (1,1,3) <- (1,1,4)
		//   node                [me]       [p1]       [p2]
		req := require.New(t)

		chain := newConsecutiveBlocks(
			[]blockchain.Block{genesisBlockFake}, newEpoch(1, 1), 4)

		k := uint32(1)
		client := newClientFake(
			newChainFake(chain[:1+2], newBlockSn(1, 1, 1), nil, k),
			map[ConsensusId]chainReader{
				"p1": newChainFake(chain[:1+3], newBlockSn(1, 1, 2), nil, k),
				"p2": newChainFake(chain, newBlockSn(1, 1, 3), nil, k),
			},
		)
		clock := &clockFake{}
		max := time.Second
		syncer := NewChainSyncer(Config{
			LoggingId:               "me",
			Client:                  client,
			Role:                    newRoleFake(nil),
			Clock:                   clock,
			MaxRequestWaitingPeriod: max,
			TimeoutToRetryPeriod:    max,
			RpcMaxDelayBlock:        1,
		})

		// Expect there is no progress because p2 does not respond.
		client.pause("p2")
		syncer.SetMyStatus(NewStatus(1, 1, 2, "", 0))
		syncer.SetPeerStatus("p2", NewStatus(1, 1, 4, "", 0))
		verifyNoProgress(req, client)

		// Expect there is still no progress because timeout does not happen yet.
		syncer.SetPeerStatus("p1", NewStatus(1, 1, 3, "", 0))
		syncer.DoSomethingIfNeeded()
		verifyNoProgress(req, client)

		// Expect fetching blocks from p1 because timeout happens.
		clock.addDuration(max)
		syncer.DoSomethingIfNeeded()
		verifyChain(req, syncer, client, newBlockSn(1, 1, 3))
	})

	t.Run("epoch timeout would not effect block syncing", func(t *testing.T) {
		//   chain: (1,1,1) <- (1,1,2) <- (1,1,3) <- (1,1,4) <- (1,1,5)
		//                       [me]                              |
		//                                                         ------- (1,2,1) <- (1,2,2)
		//                                                                             [p1]
		req := require.New(t)

		chain := newConsecutiveBlocks(
			[]blockchain.Block{genesisBlockFake}, newEpoch(1, 1), 2)
		p1Chain := newConsecutiveBlocks(
			[]blockchain.Block{genesisBlockFake}, newEpoch(1, 1), 5)
		p1Chain = newConsecutiveBlocks(p1Chain, newEpoch(1, 2), 2)

		k := uint32(1)
		client := newClientFake(
			newChainFake(chain, newBlockSn(1, 1, 2), nil, k),
			map[ConsensusId]chainReader{
				"p1": newChainFake(p1Chain, newBlockSn(1, 2, 1), nil, k),
			},
		)
		clock := &clockFake{}
		syncer := NewChainSyncer(Config{
			LoggingId:               "me",
			Client:                  client,
			Role:                    newRoleFake(nil),
			Clock:                   clock,
			MaxRequestWaitingPeriod: 2 * time.Second,
			TimeoutToRetryPeriod:    2 * time.Second,
			RpcMaxDelayBlock:        1,
		})

		syncer.SetMyStatus(NewStatus(1, 1, 2, "", 0))
		syncer.SetPeerStatus("p1", NewStatus(1, 2, 2, "", 0))

		// At the first second, block and epoch have progress.
		clock.addDuration(time.Second)
		syncer.DoSomethingIfNeeded()
		req.True(blockAdvanced(syncer, client, true))
		req.True(epochAdvanced(syncer, client, false))

		// At the second second, epoch should timeout.
		clock.addDuration(time.Second)
		syncer.DoSomethingIfNeeded()
		req.False(epochAdvanced(syncer, client, false))
		// block syncer still has progress because status=requesting so far.
		// after `ChainSyncer.SetMyFreshestNotarizedHead`, it will reset the peer status.
		req.True(blockAdvanced(syncer, client, true))

		// epoch syncer status=timeout and block syncer status=none
		// block syncer should not be blocked by the timeout of epoch syncer
		syncer.DoSomethingIfNeeded()
		req.False(epochAdvanced(syncer, client, false))
		req.True(blockAdvanced(syncer, client, true))
	})

	t.Run("peer is offline while requesting", func(t *testing.T) {
		// Setting:
		//
		//   chain: (1,1,1) <- (1,1,2) <- (1,1,3) <- (1,1,4)
		//   node                [me]       [p1]       [p2]
		req := require.New(t)

		chain := newConsecutiveBlocks(
			[]blockchain.Block{genesisBlockFake}, newEpoch(1, 1), 4)

		k := uint32(1)
		client := newClientFake(
			newChainFake(chain[:1+2], newBlockSn(1, 1, 1), nil, k),
			map[ConsensusId]chainReader{
				"p1": newChainFake(chain[:1+3], newBlockSn(1, 1, 2), nil, k),
				"p2": newChainFake(chain, newBlockSn(1, 1, 3), nil, k),
			},
		)
		syncer := newChainSyncer(client)

		// Expect there is no progress because p2 does not respond.
		client.pause("p2")
		syncer.SetMyStatus(NewStatus(1, 1, 2, "", 0))
		syncer.SetPeerStatus("p2", NewStatus(1, 1, 4, "", 0))
		verifyNoProgress(req, client)

		// Expect there is still no progress because timeout does not happen yet.
		syncer.SetPeerStatus("p1", NewStatus(1, 1, 3, "", 0))
		verifyNoProgress(req, client)

		// Expect fetching data from p1 after we know p2 is offline
		// even if timeout does not happen.
		setOffline(syncer, client, "p2")
		verifyChain(req, syncer, client, newBlockSn(1, 1, 3))
		verifyNoProgress(req, client)
	})

	t.Run("reset the timeout list after the penalty time", func(t *testing.T) {
		// Setting:
		//
		//   chain: (1,1,1) <- (1,1,2) <- (1,1,3)
		//   node                [me]       [p1]
		req := require.New(t)

		chain := newConsecutiveBlocks(
			[]blockchain.Block{genesisBlockFake}, newEpoch(1, 1), 3)

		k := uint32(1)
		client := newClientFake(
			newChainFake(chain[:1+2], newBlockSn(1, 1, 1), nil, k),
			map[ConsensusId]chainReader{
				"p1": newChainFake(chain, newBlockSn(1, 1, 2), nil, k),
			},
		)
		clock := &clockFake{}
		max1 := 2 * time.Second
		max2 := time.Second
		syncer := NewChainSyncer(Config{
			LoggingId:               "me",
			Client:                  client,
			Role:                    newRoleFake(nil),
			Clock:                   clock,
			MaxRequestWaitingPeriod: max1,
			TimeoutToRetryPeriod:    max2,
			RpcMaxDelayBlock:        1,
		})

		// Expect there is no progress because p1 does not respond.
		client.pause("p1")
		syncer.SetMyStatus(NewStatus(1, 1, 2, "", 0))
		syncer.SetPeerStatus("p1", NewStatus(1, 1, 3, "", 0))
		verifyNoProgress(req, client)
		req.False(syncer.IsBlockChainBehind(), "block chain should not be behind")

		// Expect p1 is marked as temporarily unavailable, so there is still no progress.
		client.resume("p1", true)
		clock.addDuration(max1)
		syncer.DoSomethingIfNeeded()
		verifyNoProgress(req, client)
		req.False(syncer.IsBlockChainBehind(), "block chain should not be behind")

		// Expect p1 is available after the penalty time, so there is progress.
		clock.addDuration(max2)
		syncer.DoSomethingIfNeeded()
		verifyChain(req, syncer, client, newBlockSn(1, 1, 3))
		req.False(syncer.IsBlockChainBehind(), "block chain should not be behind")
	})
}

func TestSyncOtherCornerCases(t *testing.T) {
	t.Run("the latest head is updated while syncing", func(t *testing.T) {
		// Setting:
		//
		//   chain: (1,1,1) <- (1,1,2) <- (1,1,3) <- (1,1,4)
		//   node                [me]       [p1]       [p2]'
		//                       [p2]
		req := require.New(t)

		chain := newConsecutiveBlocks(
			[]blockchain.Block{genesisBlockFake}, newEpoch(1, 1), 4)

		k := uint32(1)
		client := newClientFake(
			newChainFake(chain[:1+2], newBlockSn(1, 1, 1), nil, k),
			map[ConsensusId]chainReader{
				"p1": newChainFake(chain[:1+3], newBlockSn(1, 1, 2), nil, k),
				"p2": newChainFake(chain, newBlockSn(1, 1, 3), nil, k),
			},
		)
		clock := &clockFake{}
		syncer := NewChainSyncer(Config{
			LoggingId:               "me",
			Client:                  client,
			Role:                    newRoleFake(nil),
			Clock:                   clock,
			MaxRequestWaitingPeriod: time.Second,
			RpcMaxDelayBlock:        1,
		})

		// Expect there is no progress because p1 does not respond.
		client.pause("p1")
		syncer.SetMyStatus(NewStatus(1, 1, 2, "", 0))
		syncer.SetPeerStatus("p1", NewStatus(1, 1, 3, "", 0))
		// Simulate p2 is not fresher than us.
		syncer.SetPeerStatus("p2", NewStatus(1, 1, 2, "", 0))
		verifyNoProgress(req, client)
		req.False(syncer.IsBlockChainBehind(), "block chain should not be behind")

		// Simulate there is a new progress in p2.
		syncer.SetPeerStatus("p2", NewStatus(1, 1, 4, "", 0))
		// Expect there is still no progress because timeout does not happen yet,
		// so we are still requesting blocks from p1.
		verifyNoProgress(req, client)
		req.True(syncer.IsBlockChainBehind(), "block chain should be behind")

		// Expect there is progress because p1 is resumed.
		// Also, expect we keep fetching new blocks from p2.
		client.resume("p1", false)
		verifyChain(req, syncer, client, newBlockSn(1, 1, 4))
		req.False(syncer.IsBlockChainBehind(), "block chain should not be behind")
	})
}

func TestSyncUnnotarizedProposalsToVoters(t *testing.T) {
	// Setting:
	//
	//   chain: (1,1,1) <- (1,1,2) <- (1,1,3)
	//   node                [me]     [v1,v2,x]
	chain := newConsecutiveBlocks(
		[]blockchain.Block{genesisBlockFake}, newEpoch(1, 1), 3)

	k := uint32(1)
	client := newClientFake(
		newChainFake(chain[:1+2], newBlockSn(1, 1, 1), nil, k),
		map[ConsensusId]chainReader{
			"v1": newChainFake(chain, newBlockSn(1, 1, 2), nil, k),
			"v2": newChainFake(chain, newBlockSn(1, 1, 2), nil, k),
			"x":  newChainFake(chain, newBlockSn(1, 1, 2), nil, k),
		},
	)
	voters := []ConsensusId{"v1", "v2"}
	clock := &clockFake{}
	syncer := NewChainSyncer(Config{
		LoggingId:               "me",
		Client:                  client,
		Role:                    newRoleFake(voters),
		Clock:                   clock,
		MaxRequestWaitingPeriod: time.Second,
		RpcMaxDelayBlock:        1,
	})

	t.Run("normal case", func(t *testing.T) {
		req := require.New(t)

		syncer.SetMyStatus(NewStatus(1, 1, 2, "", 0))
		syncer.SetIAmPrimaryProposer(true)
		syncer.SetPeerStatus("v1", NewStatus(1, 1, 3, "", 0))
		syncer.SetPeerStatus("v2", NewStatus(1, 1, 3, "", 0))
		syncer.SetPeerStatus("x", NewStatus(1, 1, 3, "", 0))

		req.Equal(voters, client.getSentUnnotarizedProposalPeers())
	})

	t.Run("no repeat", func(t *testing.T) {
		req := require.New(t)

		client.resetSentUnnotarizedProposalPeers()
		syncer.SetPeerStatus("v1", NewStatus(1, 1, 3, "", 0))

		req.Equal([]ConsensusId(nil), client.getSentUnnotarizedProposalPeers())
	})

	t.Run("offline", func(t *testing.T) {
		req := require.New(t)

		client.resetSentUnnotarizedProposalPeers()
		setOffline(syncer, client, "v1")
		syncer.SetPeerStatus("v1", NewStatus(1, 1, 3, "", 0))

		// Expect none because we don't send twice within a period.
		req.Equal([]ConsensusId(nil), client.getSentUnnotarizedProposalPeers())

		// Try again after 10s.
		clock.addDuration(sentUnnotarizedProposalCoolDownPeriod)
		setOffline(syncer, client, "v1")
		syncer.SetPeerStatus("v1", NewStatus(1, 1, 3, "", 0))

		// It's okay to send again after a while.
		req.Equal([]ConsensusId{"v1"}, client.getSentUnnotarizedProposalPeers())
	})
}

//------------------------------------------------------------------------------

func TestMain(m *testing.M) {
	// Uncomment this to show details.
	//lgr.SetLogLevel("/", lgr.LvlInfo)
	os.Exit(m.Run())
}
