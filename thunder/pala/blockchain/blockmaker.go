package blockchain

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chain"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/clock"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/protocol"
	"github.com/ethereum/go-ethereum/thunder/thunderella/thundervm"
	"github.com/ethereum/go-ethereum/thunder/thunderella/txutils"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/ethereum/go-ethereum/thunder/pala/metrics"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"golang.org/x/xerrors"
)

var (
	clk clock.Clock
)

func init() {
	clk = clock.NewRealClock()
}

type BlockMakerImpl struct {
	bc               *core.BlockChain
	k                *config.Int64HardforkConfig
	timePerBlock     time.Duration
	txpool           *core.TxPool
	stopChan         chan struct{}
	notaChan         chan Notarization
	storage          *StorageImpl
	makingEmptyBlock bool
	key              *ecdsa.PrivateKey // key and address for consensus info
	address          common.Address
	metrics          metrics.PalaMetrics
}

func NewBlockMaker(storage Storage, k *config.Int64HardforkConfig, timePerBlock time.Duration, txpool *core.TxPool, me metrics.PalaMetrics) *BlockMakerImpl {
	bc := storage.(*StorageImpl).bc
	key, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		debug.Bug("Cannot generate key for the consensus info.")
	}
	address := crypto.PubkeyToAddress(key.PublicKey)
	metrics.SetGauge(me.Proposer_Blockmaker_TimePerBlockInSec, timePerBlock.Nanoseconds())
	return &BlockMakerImpl{
		bc:           bc,
		k:            k,
		timePerBlock: timePerBlock,
		txpool:       txpool,
		key:          key,
		address:      address,
		metrics:      me,
		storage:      storage.(*StorageImpl),
	}
}

func getHeader(block Block) *types.Header {
	return block.(*blockImpl).B.Header()
}

func (bm *BlockMakerImpl) KeepCreatingNewBlocks(
	bc *BlockChainImpl,
	parent Block,
	epoch Epoch,
	cNota ClockMsgNota,
	outputChan chan BlockMadeEvent,
	stopChan chan struct{},
	notaChan chan Notarization,
	stopEvent chan struct{}) {

	bm.stopChan = stopChan
	bm.notaChan = notaChan

	// blockmaker should not include any transaction after stop block within the same session.
	bm.makingEmptyBlock = epoch.Session == parent.GetBlockSn().Epoch.Session && bc.storage.IsAfterStopBlock(parent, true)

	defer close(stopEvent)

	var (
		prevHeader = getHeader(parent)
	)

	bm.txpool.StartMakingThunderBlock()
	defer func() {
		bm.txpool.StopMakingThunderBlock()

		block := bm.storage.GetBlock(bm.storage.GetFreshestNotarizedHeadSn())
		bm.txpool.LockedReset(prevHeader, getHeader(block))
	}()

	for s := uint32(1); ; s++ {
		blkStartTime := clk.Now()
		sn := BlockSn{
			Epoch: epoch,
			S:     s,
		}

		newBlock, err := bm.MakeSingleBlock(parent, sn, cNota, stopEvent)

		if err != nil {
			return
		}

		newHeader := getHeader(newBlock)
		logger.Debug("Block made %s with stateRoot %s", sn, newHeader.Root.Hex())

		bm.txpool.LockedReset(prevHeader, newHeader)
		prevHeader = newHeader

		if bm.storage.IsAfterStopBlockHeader(newHeader, true) {
			bm.makingEmptyBlock = true
		}

		outputChan <- BlockMadeEvent{newBlock}

		logger.Debug("Block sent %s...", sn)
		metrics.ObserveHistogram(bm.metrics.Proposer_Blockmaker_E2EBlockMakingTimeMs, clk.Now().Sub(blkStartTime).Seconds()*1000)
		txPoolStatus := bm.txpool.GetStatus()
		metrics.SetGauge(bm.metrics.Proposer_TxPool_NumNonProcessableTxs, int64(txPoolStatus.QueueCount))
		metrics.SetGauge(bm.metrics.Proposer_TxPool_NumProcessableTxs, int64(txPoolStatus.PendingCount))
		metrics.SetGauge(bm.metrics.Proposer_TxPool_NumTotalTxs, int64(txPoolStatus.TotalCount))
		metrics.SetGauge(bm.metrics.Proposer_TxPool_TotalAvailableSlots, int64(txPoolStatus.Available))
		metrics.SetGauge(bm.metrics.Proposer_TxPool_TxsBad, txPoolStatus.InvalidTxCount)

		parent = newBlock
	}
}

func (bm *BlockMakerImpl) MakeSingleBlock(parentBlock Block, sn BlockSn, cNota ClockMsgNota, stopEvent chan struct{}) (Block, error) {
	var (
		isRunning      = true
		ethParent      = parentBlock.(*blockImpl).B
		parentSn       = parentBlock.GetBlockSn()
		consensusTxGas = uint64(0)
		ethGenerated   *types.Block
		session        = uint32(0)
	)

	header := bm.prepareHeader(ethParent, parentSn, sn)
	session = bm.bc.Config().Thunder.GetSessionFromDifficulty(header.Difficulty, header.Number, bm.bc.Config().Thunder)
	k := uint32(bm.k.GetValueAtSession(int64(session)))

	if bm.bc.Config().Thunder.IsLondon(session) {
		if err := misc.VerifyEip1559Header(bm.bc.Config(), ethParent.Header(), header); err != nil {
			logger.Error("verify eip1559 error: %v", err)
			return nil, err
		}
	}

	// Reserve gas for the consensus transaction which stores a notarization.

	if !bm.bc.Config().Thunder.IsConsensusInfoInHeader.GetValueAtSession(int64(session)) {
		consensusTxGas = getMaxConsensusTxGas(k)
	}

	gp := new(core.GasPool).AddGas(header.GasLimit - consensusTxGas)
	state, err := bm.bc.StateAt(ethParent.Root())
	if err != nil {
		debug.Bug("Cannot get state from parent hash %s, parent %s, sn %s", ethParent.Hash().String(), parentSn, sn)
	}

	signer := types.MakeSigner(bm.bc.Config(), header.Number, session)
	context := &blockContext{
		header:     header,
		gp:         gp,
		state:      state,
		nonceCache: make(map[common.Address]uint64),
		signer:     signer,
	}
	if sn.S > 1 {
		isRunning, ethGenerated = bm.makeOneBlock(context, sn)
	} else {
		isRunning, ethGenerated = bm.makeFirstBlock(context, cNota, parentSn, sn)
	}

	if !isRunning {
		return nil, xerrors.New("Stopped by outside")
	}

	bm.updatePerBlockMetrics(ethGenerated)
	generatedBlock := newBlock(ethGenerated, bm.bc.Config().Thunder)

	if err := bm.storage.writeBlockWithState(generatedBlock, context.receipts, context.logs, context.state); err != nil {
		logger.Error("Cannot write into storage. stop.")
		return nil, err
	}

	return generatedBlock, err
}

func (bm *BlockMakerImpl) updatePerBlockMetrics(blk *types.Block) {
	txs := blk.Transactions()
	metrics.SetGauge(bm.metrics.Proposer_Blockmaker_GasUsedPerBlock, int64(blk.GasUsed()))
	metrics.SetGauge(bm.metrics.Proposer_Blockmaker_TxPerBlock, int64(txs.Len()))
	minGasPrice := big.NewInt(0)
	if len(txs) > 1 { // includes non-consensus transactions
		// last tx in blk is consensus-transaction
		for k, tx := range txs[:len(txs)-1] {
			if k == 0 || minGasPrice.Cmp(tx.GasPrice()) > 0 {
				minGasPrice.Set(tx.GasPrice())
			}
		}
	}
	metrics.SetGauge(bm.metrics.Proposer_Blockmaker_MinGasPricePerBlock, minGasPrice.Int64())
	metrics.SetGauge(bm.metrics.Proposer_Blockmaker_MaxGas, protocol.BlockGasLimit.GetValueAt(chain.Seq(blk.Number().Int64())))
}

type blockContext struct {
	header              *types.Header
	gp                  *core.GasPool
	state               *state.StateDB
	transactions        []*types.Transaction
	receipts            []*types.Receipt
	logs                []*types.Log
	pendingTransactions *types.TransactionsByPriceAndNonce
	tCount              int
	consensusInfo       *consensusInfo
	nonceCache          map[common.Address]uint64
	signer              types.Signer
}

func (bm *BlockMakerImpl) makeFirstBlock(
	context *blockContext, clockNota ClockMsgNota, parentSn BlockSn, sn BlockSn,
) (bool, *types.Block) {
	var notas []Notarization

	//	if !parentSn.IsGenesis() && parentSn.Epoch.Session != sn.Epoch.Session {
	if sn.Epoch.E > 1 {
		if clockNota == nil {
			debug.Bug("Consensus should call me after it have clock nota. parentSn=%s, sn=%s", parentSn, sn)
		}
	}

	k := uint32(bm.k.GetValueAtSession(int64(sn.Epoch.Session)))

	if parentSn.IsPala() {
		for i := uint32(0); i < k && parentSn.S > 0; i++ {
			nota := bm.storage.GetNotarization(parentSn)
			if nota == nil {
				debug.Bug("Consensus should call bm after it gather notas.")
			}
			notas = append(notas, nota)
			parentSn.S--
		}
	}

	// reverse the order
	for i, j := 0, len(notas)-1; i < j; i, j = i+1, j-1 {
		notas[i], notas[j] = notas[j], notas[i]
	}

	if context != nil {
		context.consensusInfo = makeConsensusInfo(notas, clockNota)
	}

	return bm.makeOneBlock(context, sn)
}

type StopCondition int

const (
	StopMaking StopCondition = iota
	ContinueMaking
	DeliverNow
)

func (bm *BlockMakerImpl) checkStopCondition(ticker <-chan time.Time,
	blockOutOfGas bool,
	notaChan <-chan Notarization,
	stopChan <-chan struct{},
	context *blockContext,
	sn BlockSn) (StopCondition, <-chan time.Time) {

	k := uint32(bm.k.GetValueAtSession(int64(sn.Epoch.Session)))

	if blockOutOfGas {
		select {
		case <-stopChan:
			return StopMaking, ticker
		case <-ticker:
			logger.Debug("Hit block timer, wait for nota %s", sn)
			if sn.S > k {
				for {
					select {
					case nota := <-notaChan:
						expectedNotaSn := BlockSn{
							Epoch: sn.Epoch,
							S:     sn.S - k,
						}
						if nota.GetBlockSn().Compare(expectedNotaSn) != 0 {
							logger.Info("Get unexpected Nota from channel with sn = %s, usually this happens when fork", expectedNotaSn)
							break // break select
						}

						if context != nil {
							nota = bm.storage.GetNotarization(expectedNotaSn)
							context.consensusInfo = notarizationToConsensusInfo(nota)
						}
						logger.Info("Got nota %s! insert into block %s ", nota.GetBlockSn(), sn)
						return DeliverNow, ticker
					case <-stopChan:
						return StopMaking, ticker
					}
				}
			} else {
				return DeliverNow, ticker
			}
		}
	}

	select {
	case <-stopChan:
		return StopMaking, ticker
	case <-ticker:
		logger.Debug("Hit block timer, wait for nota %s", sn)
		if sn.S > k {
			select {
			case nota := <-notaChan:
				expectedNotaSn := BlockSn{
					Epoch: sn.Epoch,
					S:     sn.S - k,
				}
				if nota.GetBlockSn().Compare(expectedNotaSn) != 0 {
					logger.Info("Get unexpected Nota from channel with sn = %s, usually this happens when fork", expectedNotaSn)
					break // break select
				}

				if context != nil {
					nota = bm.storage.GetNotarization(expectedNotaSn)
					context.consensusInfo = notarizationToConsensusInfo(nota)
				}

				logger.Info("Got nota %s! insert into block %s ", nota.GetBlockSn(), sn)
				return DeliverNow, ticker
			case <-stopChan:
				return StopMaking, ticker
			default:
			}

			nt := clk.NewTimer(10 * time.Millisecond)
			ticker = nt.C
		} else {
			return DeliverNow, ticker
		}
	default:
	}

	return ContinueMaking, ticker
}

func (bm *BlockMakerImpl) makeOneBlock(context *blockContext, sn BlockSn) (bool, *types.Block) {
	blockOutOfGas := false
	blkTime := time.Unix(int64(context.header.Time), 0)
	timeSlot := bm.timePerBlock
	currentTime := clk.Now()
	if blkTime.After(currentTime) {
		blkTimeDiff := blkTime.Sub(currentTime)
		if timeSlot > blkTimeDiff {
			timeSlot = blkTimeDiff
		}
	}

	logger.Info("Making block within %s", timeSlot)

	timer := clk.NewTimer(timeSlot)
	ticker := timer.C
	condition := ContinueMaking
	localCounter := 0
	loopCounter := 0

	defer func() {
		logger.Info("Looping %d times iterate %d times", loopCounter, localCounter)
	}()

	for condition == ContinueMaking {
		loopCounter++
		getPendingTxStartTime := clk.Now()
		numTx, txs := bm.getPendingTransactions(context)

		metrics.ObserveHistogram(bm.metrics.Proposer_Blockmaker_GetPendingTxnsTimeMs, clk.Now().Sub(getPendingTxStartTime).Seconds()*1000)

		if numTx == 0 {
			condition, ticker = bm.checkStopCondition(ticker, blockOutOfGas, bm.notaChan, bm.stopChan, context, sn)

			if condition == DeliverNow {
				return true, bm.mustFinalizeAndSealBlock(context)
			} else if condition == ContinueMaking {
				// If we don't sleep here, it's busy looping.
				time.Sleep(time.Millisecond)
				continue
			}
		}
		for numTx > 0 && condition == ContinueMaking {
			localCounter++
			tx := txs.Peek()
			if tx == nil {
				// NOTE: this can still happend when some account is skipped by nonce.
				break
			}

			context.pendingTransactions = txs

			bm.applyTransaction(context, tx)
			numTx--
			if context.gp.Gas() < params.TxGas {
				logger.Info("Block gas limit exhausted, remained %d", context.gp.Gas())
				blockOutOfGas = true
			}

			context.pendingTransactions = nil
			condition, ticker = bm.checkStopCondition(ticker, blockOutOfGas, bm.notaChan, bm.stopChan, context, sn)

			if condition == DeliverNow {
				return true, bm.mustFinalizeAndSealBlock(context)
			}
		}
	}

	return false, nil
}

type consensusInfo struct {
	notas     []Notarization
	clockNota ClockMsgNota
}

func (ci *consensusInfo) ToBytes() []byte {
	l := uint32(len(ci.notas))
	ret := utils.Uint32ToBytes(l)

	for _, nota := range ci.notas {
		ret = append(ret, nota.GetBody()...)
	}

	if ci.clockNota != nil {
		ret = append(ret, ci.clockNota.GetBody()...)
	}

	return ret
}

func notarizationToConsensusInfo(nota Notarization) *consensusInfo {
	notas := make([]Notarization, 1)
	notas[0] = nota
	return &consensusInfo{
		notas: notas,
	}
}

func makeConsensusInfo(notas []Notarization, cmn ClockMsgNota) *consensusInfo {
	return &consensusInfo{
		notas:     notas,
		clockNota: cmn,
	}
}

func bytesToConsensusInfo(data []byte, unmarshaller DataUnmarshaller) (*consensusInfo, error) {
	length, data, err := utils.BytesToUint32(data)
	if err != nil {
		return nil, err
	}
	var (
		ret = &consensusInfo{
			notas: make([]Notarization, length),
		}
	)

	for i := uint32(0); i < length; i++ {
		ret.notas[i], data, err = unmarshaller.UnmarshalNotarization(data)
		if err != nil {
			return ret, err
		}
	}

	if len(data) != 0 {
		ret.clockNota, _, err = unmarshaller.UnmarshalClockMsgNota(data)
		if err != nil {
			return ret, err
		}
	}

	return ret, nil
}

var (
	cachedMaxConsensusTxGas = uint64(0)
	unnotarizedWindow       = uint32(1)
	nMaxVoters              = 512
)

func getMaxConsensusTxGas(queriedK uint32) uint64 {
	if cachedMaxConsensusTxGas == 0 || queriedK != unnotarizedWindow {
		var err error
		key, err := bls.NewSigningKey()
		if err != nil {
			debug.Bug(err.Error())
		}
		sig := key.Sign([]byte{})
		nota := &notarizationImpl{
			aggSig:           sig,
			missingVoterIdxs: make([]uint16, nMaxVoters-1),
		}
		cNota := &clockMsgNotaImpl{
			aggSig:           sig,
			missingVoterIdxs: make([]uint16, nMaxVoters-1),
		}
		notas := make([]Notarization, queriedK)
		for i := range notas {
			notas[i] = nota
		}

		bytes := makeConsensusInfo(notas, cNota).ToBytes()
		for i := 0; i < len(bytes); i++ {
			// 1 cost more gas compared to 0.
			bytes[i] = 1
		}

		cachedMaxConsensusTxGas, err = core.IntrinsicGas(bytes, nil, false, false, false)
		logger.Debug("Setting max nota bytes size = %d, gas = %d for %d voters",
			len(bytes), cachedMaxConsensusTxGas, nMaxVoters)
		if err != nil {
			debug.Bug(err.Error())
		}
		unnotarizedWindow = queriedK
	}
	return cachedMaxConsensusTxGas
}

func (bm *BlockMakerImpl) applyConsensusTransaction(context *blockContext) {
	if context == nil {
		return
	}
	if context.consensusInfo == nil {
		return
	}

	notaData := context.consensusInfo.ToBytes()

	// store consensus info in Extra field of block header
	session := bm.bc.Config().Thunder.GetSessionFromDifficulty(context.header.Difficulty, context.header.Number, bm.bc.Config().Thunder)
	if bm.bc.Config().Thunder.IsConsensusInfoInHeader.GetValueAtSession(int64(session)) {
		context.header.Extra = notaData
		return
	}

	tx := txutils.MakeSignedTxWithData(
		bm.key,
		&bm.address,
		context.state.GetNonce(bm.address),
		big.NewInt(0), nil, notaData, big.NewInt(0),
	)

	k := uint32(bm.k.GetValueAtSession(int64(session)))

	// Use the reserved gas.
	context.gp = new(core.GasPool).AddGas(getMaxConsensusTxGas(k))
	if err := bm.applyTransaction(context, tx); err != nil {
		debug.Bug("Cannot apply the consensus transaction. err = %s, gas limit = %d, gp = %d", err, tx.Gas(), context.gp.Gas())
	}
}

func (bm *BlockMakerImpl) mustFinalizeAndSealBlock(context *blockContext) *types.Block {
	bm.applyConsensusTransaction(context)
	chainEngine := bm.bc.Engine()

	// Create new block and seal it
	block, err := chainEngine.FinalizeAndAssemble(bm.bc, context.header, context.state, context.transactions, nil, context.receipts)
	if err != nil {
		debug.Bug("txpool.blockmaker: failed to finalize block for sealing: %s", err)
		return nil
	}
	results := make(chan *types.Block, 1)
	err = chainEngine.Seal(bm.bc, block, results, nil)
	if err != nil {
		debug.Bug("txpool.blockmaker: block sealing failed: %s", err)
		return nil
	}
	return <-results
}

// Reference TxPoolBlockMaker.prepareHeader() in 224c59c30883
func (bm *BlockMakerImpl) prepareHeader(parent *types.Block, parentSn BlockSn, sn BlockSn) *types.Header {
	chainEngine := bm.bc.Engine()
	mixDigest := common.Hash{}

	num := new(big.Int).Add(parent.Number(), common.Big1)
	chainSeq := chain.Seq(num.Int64())
	if thundervm.IsRNGActive.GetValueAt(chainSeq) {
		// Generate a random seed every block, this is a non-blocking call.
		seed, err := bm.generateRandomSeed()
		if err != nil {
			logger.Debug("Random seed generation failed.")
		}
		mixDigest = common.BytesToHash(seed)
	}

	sessionOffset := uint64(1)
	if parentSn.Epoch.Session == sn.Epoch.Session {
		sessionOffset = parent.Nonce() + 1
	}
	blockTime := new(big.Int).SetInt64(clk.Now().Unix() + int64(bm.timePerBlock.Seconds()))
	parentTime := new(big.Int).SetUint64(parent.Time())
	if blockTime.Cmp(parentTime) <= 0 {
		// NOTE: We don't need to wait for now. See checkStopCondition().
		blockTime = blockTime.Add(parentTime, common.Big1)
	}

	header := &types.Header{
		Difficulty: EncodeBlockSnToNumber(parentSn, sn),
		Number:     num,
		ParentHash: parent.Hash(),
		GasLimit:   protocol.BlockGasLimit.GetValueAtU64(chain.Seq(num.Int64())),
		Time:       blockTime.Uint64(),
		Nonce:      types.EncodeNonce(uint64(sessionOffset)),
		MixDigest:  mixDigest,
	}

	if bm.bc.Config().Thunder.IsLondon(uint32(sn.Epoch.Session)) {
		header.BaseFee = bm.bc.Config().Thunder.BaseFee.GetValueAtSession(int64(sn.Epoch.Session))
	}

	if err := chainEngine.Prepare(bm.bc, header); err != nil {
		debug.Bug("blockmaker: Failed to prepare header: %s", err)
		return nil
	}
	return header
}

func (bm *BlockMakerImpl) getPendingTransactions(context *blockContext) (int, *types.TransactionsByPriceAndNonce) {
	if bm.makingEmptyBlock {
		return 0, nil
	}
	numPending := 0
	pending, err := bm.txpool.Pending(false)
	if err != nil {
		debug.Bug("failed to fetch pending transactions")
	}

	numDebug := 0

	pendingInContext := make(map[common.Address]types.Transactions)
	for a, txs := range pending {
		numDebug += txs.Len()
		if context != nil {
			if n, ok := context.nonceCache[a]; ok {
				// Find lowerbound of cached nonce
				k := sort.Search(txs.Len(), func(i int) bool { return txs[i].Nonce() > n })
				if k < txs.Len() && txs[k].Nonce() == n+1 {
					txs = txs[k:]
				} else {
					continue
				}
			}

			if txs.Len() != 0 && context.gp.Gas() < txs[0].Gas() {
				txs = txs[:0]
			}
		}

		if txs.Len() != 0 {
			pendingInContext[a] = txs
			numPending += txs.Len()
		}
	}

	if numPending != 0 {
		pendingTxs := types.NewTransactionsByPriceAndNonce(context.signer, pendingInContext, nil)
		return numPending, pendingTxs
	}

	return 0, nil
}

func txToString(tx *types.Transaction) string {
	data, err := tx.MarshalJSON()
	if err != nil {
		logger.Error("transaction.MarshalJSON() failed: %s", err)
	}

	return string(data)
}

func (bm *BlockMakerImpl) applyTransaction(context *blockContext, tx *types.Transaction) error {
	context.state.Prepare(tx.Hash(), context.tCount)
	from, _ := types.Sender(context.signer, tx)
	receipt, err := core.ApplyTransaction(bm.bc.Config(), bm.bc, nil, context.gp, context.state, context.header, tx, &context.header.GasUsed, *bm.bc.GetVMConfig())

	if err == nil {
		// THUNDER: The transaction will be removed from the txpool on the next
		//          reset
		//
		// Everything ok, collect the logs and shift in the next transaction from
		// the same account coalescedLogs = append(coalescedLogs, logs...)
		context.transactions = append(context.transactions, tx)
		context.receipts = append(context.receipts, receipt)
		context.logs = append(context.logs, receipt.Logs...)
		context.tCount++
		context.nonceCache[from] = tx.Nonce()
		if context.pendingTransactions != nil {
			context.pendingTransactions.Shift()
		}
		return nil
	}

	if strings.Contains(err.Error(), core.ErrGasLimitReached.Error()) {
		// THUNDER: These transactions will be processed in the next round
		//
		// Pop the current out-of-gas transaction without shifting in the next
		// from the account
		logger.Debug("Insufficient remaining block gas for tx(sender %q, block gas left %q, block gas limit: %d, tx:%s)",
			hex.EncodeToString(from[:]), context.gp, context.header.GasLimit, txToString(tx))
		if context.pendingTransactions != nil {
			context.pendingTransactions.Pop()
		}

	} else if strings.Contains(err.Error(), core.ErrNonceTooLow.Error()) {
		// THUNDER: The transaction will be removed from the txpool on the next
		//          reset
		//
		// New head notification data race between the transaction pool and miner,
		// shift
		logger.Debug("Skipping transaction with low nonce sender %q, nonce %d",
			from, tx.Nonce())
		if context.pendingTransactions != nil {
			context.pendingTransactions.Shift()
		}

	} else if strings.Contains(err.Error(), core.ErrNonceTooHigh.Error()) {
		// THUNDER :The transaction will be held in the txpool until the eviction
		// timer is hit or is replaced by a better transaction if the txpool is
		// full
		//
		// Reorg notification data race between the transaction pool and miner,
		// skip account =
		logger.Debug("Skipping account with hight nonce sender %q, nonce %d",
			from, tx.Nonce())
		if context.pendingTransactions != nil {
			context.pendingTransactions.Pop()
		}
	} else if strings.Contains(err.Error(), core.ErrInsufficientFunds.Error()) {
		// THUNDER: These transactions will be processed in the next round
		//
		// Pop the current insufficient-funds transaction without shifting in the next
		// from the account
		logger.Debug("insufficient funds with err: %q, tx %s", err, txToString(tx))
		if context.pendingTransactions != nil {
			context.pendingTransactions.Shift()
		}
	} else {
		// THUNDER: these transactions will likely stay in the txpool until the
		// remove timer is hit
		//
		// Strange error, discard the transaction and get the next in line (note,
		// the nonce-too-high clause will prevent us from executing in vain).
		logger.Warn("Transaction failed with err: %q, tx %s", err, txToString(tx))
		if context.pendingTransactions != nil {
			context.pendingTransactions.Shift()
		}
	}

	return err
}

func (bm *BlockMakerImpl) generateRandomSeed() ([]byte, error) {
	b := make([]byte, 32)

	// Get random bytes via /dev/urandom
	_, err := rand.Read(b)
	if err != nil {
		logger.Debug("failed to generate random bytes")
		return nil, err
	}

	return b, nil
}
