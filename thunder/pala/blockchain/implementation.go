package blockchain

import (
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/thundervm/reward"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/ethereum/go-ethereum/thunder/pala/metrics"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	"golang.org/x/xerrors"
)

// Storage stores BlockSn and notarizations related data, we can use geth with tiny modify for production
// Storage is goroutine safe because it should be only use in BlockChainImpl and protected by the lock of BlockChainImpl.
type Storage interface {
	GetBlock(sn BlockSn) Block
	GetHeader(sn BlockSn) Header
	GetNotarization(sn BlockSn) Notarization
	InsertBlock(block Block) error
	AddNotarization(nota Notarization) (freshestExtended BlockSn, finalExtended BlockSn, err error)
	GetFreshestNotarizedHeadSn() BlockSn
	GetFreshestNotarizedHeadInfo() BlockInfo
	GetGenesisBlock() Block
	GetLatestFinalizedStopBlock() Block
	GetBlockByNumber(number uint64) Block
	GetCommInfo(session Session) *committee.CommInfo
	GetClearingGasPrice(session Session) *big.Int
	GetProposerAddresses(session Session) map[ConsensusId]string
	IsStopBlock(block Block) bool
	IsAfterStopBlock(block Block, includingStopBlock bool) bool
	GetFinalizedHeadSn() BlockSn
	GetHeaderByNumber(number uint64) Header
	GetRawBlockBody(hash Hash) []byte
	GetRawNotarization(sn BlockSn) []byte
	GetReward(number uint64) (*reward.Results, error)
	GetThunderConfig() *params.ThunderConfig
}

// BlockMaker creates blocks and push into ch and stops after receiving a message from stopChan.
type BlockMaker interface {
	KeepCreatingNewBlocks(
		bc *BlockChainImpl, parent Block, epoch Epoch, cNota ClockMsgNota,
		ch chan BlockMadeEvent, stopChan chan struct{}, notaChan chan Notarization, stopEvent chan struct{})
}

// About goroutine-safety:
// * All public methods hold mutex by themselves.
// * Most private methods assume the caller holds the mutex.
type BlockChainImpl struct {
	// Protect all data. All public methods hold the lock.
	mutex utils.CheckedLock
	// The max number of unnotarized blocks. Also used as the finalized parameter.
	k               *config.Int64HardforkConfig
	eventChans      []chan interface{}
	finalizedEvent  chan *FinalizedChainExtendedEvent
	txpool          *core.TxPool
	metrics         metrics.PalaMetrics
	gasPriceSession Session

	// Worker goroutine
	isCreatingBlockCh chan struct{}
	stopChan          chan struct{}
	notaChan          chan Notarization
	blockMaker        BlockMaker
	blockDecoder      BlockDecoder
	storage           Storage
}

const WaitingPeriodForStopingNewBlocks = 2 * time.Second

func NewBlockChainImpl(
	k *config.Int64HardforkConfig, store Storage, bm BlockMaker, bd BlockDecoder, txpool *core.TxPool, m metrics.PalaMetrics,
) (BlockChain, error) {
	bc := &BlockChainImpl{
		k:                 k,
		stopChan:          make(chan struct{}),
		finalizedEvent:    make(chan *FinalizedChainExtendedEvent, 1),
		storage:           store,
		blockDecoder:      bd,
		blockMaker:        bm,
		txpool:            txpool,
		metrics:           m,
		isCreatingBlockCh: make(chan struct{}),
	}
	session := bc.GetFinalizedHeadSn().Epoch.Session
	bc.mutex.Lock()
	// Note that there is always a finalized head, but there is no stop block in session 0.
	if sb := bc.getLatestFinalizedStopBlock(); sb != nil {
		session = sb.GetBlockSn().Epoch.Session + 1
	}
	bc.gasPriceSession = session
	bc.updateTxPoolGasPrice()
	close(bc.isCreatingBlockCh)
	bc.mutex.Unlock()

	return bc, nil
}

type Config struct {
	ChainDb           ethdb.Database
	EthChain          *core.BlockChain
	Txpool            *core.TxPool
	UnnotarizedWindow *config.Int64HardforkConfig
	TimePerBlock      time.Duration
	CommInfo          *committee.CommInfo
	AlterCommInfo     map[string]*committee.CommInfo
	PalaFromGenesis   bool
	Metrics           metrics.PalaMetrics

	TracerCacheSize int64
}

func NewBlockChain(config Config) (BlockChain, error) {
	dm := &DataUnmarshallerImpl{Config: config.EthChain.Config().Thunder}
	storage := NewStorage(StorageConfig{
		Db:                config.ChainDb,
		Bc:                config.EthChain,
		Marshaller:        dm,
		Info:              config.CommInfo,
		AlterInfo:         config.AlterCommInfo,
		PalaFromGenesis:   config.PalaFromGenesis,
		UnnotarizedWindow: config.UnnotarizedWindow,
		TracerCacheSize:   config.TracerCacheSize,
	})

	return NewBlockChainImpl(
		config.UnnotarizedWindow,
		storage,
		NewBlockMaker(storage, config.UnnotarizedWindow, config.TimePerBlock, config.Txpool, config.Metrics),
		NewBlockImplDecoder(config.UnnotarizedWindow, dm, config.Txpool),
		config.Txpool,
		config.Metrics,
	)
}

func (bc *BlockChainImpl) SetHead(number uint64) {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	bc.stopCreatingNewBlocks(WaitingPeriodForStopingNewBlocks)
	bc.storage.(*StorageImpl).setHead(number)
}

func (bc *BlockChainImpl) DecodeBlock(b Block) ([]Notarization, ClockMsgNota) {
	config := bc.storage.GetThunderConfig()
	return bc.blockDecoder.GetNotarizations(b, config), bc.blockDecoder.GetClockMsgNota(b, config)
}

func (bc *BlockChainImpl) ToRawBlock(header []byte, blockBody []byte) ([]byte, error) {
	return bc.blockDecoder.ToRawBlock(header, blockBody)
}

func (bc *BlockChainImpl) ContainsBlock(s BlockSn) bool {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	return bc.doesBlockExist(s)
}

func (bc *BlockChainImpl) doesBlockExist(s BlockSn) bool {
	bc.mutex.CheckIsLocked("")

	// We should use a more efficient way to implement this in the real implementation.
	return bc.getBlock(s) != nil
}

func (bc *BlockChainImpl) GetBlock(s BlockSn) Block {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	return bc.getBlock(s)
}

func (bc *BlockChainImpl) getBlock(s BlockSn) Block {
	bc.mutex.CheckIsLocked("")

	return bc.storage.GetBlock(s)
}

func (bc *BlockChainImpl) GetHeader(s BlockSn) Header {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	return bc.storage.GetHeader(s)
}

func (bc *BlockChainImpl) GetGenesisBlock() Block {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	return bc.storage.GetGenesisBlock()
}

func (bc *BlockChainImpl) GetBlockByNumber(number uint64) Block {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	return bc.storage.GetBlockByNumber(number)
}

func (bc *BlockChainImpl) GetNotarization(s BlockSn) Notarization {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	return bc.getNotarization(s)
}

func (bc *BlockChainImpl) getNotarization(s BlockSn) Notarization {
	bc.mutex.CheckIsLocked("")

	return bc.storage.GetNotarization(s)
}

func (bc *BlockChainImpl) GetHeaderByNumber(number uint64) Header {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()
	return bc.storage.GetHeaderByNumber(number)
}

func (bc *BlockChainImpl) GetRawBlockBody(hash Hash) []byte {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()
	return bc.storage.GetRawBlockBody(hash)
}

func (bc *BlockChainImpl) GetRawNotarization(sn BlockSn) []byte {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()
	return bc.storage.GetRawNotarization(sn)
}

func (bc *BlockChainImpl) GetFreshestNotarizedHead() Block {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	return bc.getFreshestNotarizedChain()
}

func (bc *BlockChainImpl) GetFreshestNotarizedHeadSn() BlockSn {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	return bc.storage.GetFreshestNotarizedHeadSn()
}

func (bc *BlockChainImpl) GetFreshestNotarizedHeadInfo() BlockInfo {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	return bc.storage.GetFreshestNotarizedHeadInfo()
}

// Assume blocks and notarizations are inserted in order.
// The time complexity is O(1).
func (bc *BlockChainImpl) getFreshestNotarizedChain() Block {
	sn := bc.storage.GetFreshestNotarizedHeadSn()
	blk := bc.storage.GetBlock(sn)
	if blk == nil {
		logger.Critical("Cannot getBlock from %s", sn)
	}

	return blk
}

func (bc *BlockChainImpl) GetFinalizedHead() Block {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	return bc.getFinalizedChain()
}

func (bc *BlockChainImpl) GetFinalizedHeadSn() BlockSn {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	return bc.storage.GetFinalizedHeadSn()
}

func (bc *BlockChainImpl) GetLatestFinalizedStopBlock() Block {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	return bc.getLatestFinalizedStopBlock()
}

func (bc *BlockChainImpl) getLatestFinalizedStopBlock() Block {
	bc.mutex.CheckIsLocked("")
	return bc.storage.GetLatestFinalizedStopBlock()
}

func (bc *BlockChainImpl) getFinalizedChain() Block {
	bc.mutex.CheckIsLocked("")
	sn := bc.storage.GetFinalizedHeadSn()
	blk := bc.getBlock(sn)
	if blk == nil {
		logger.Critical("Cannot getBlock from %s", sn)
	}

	return blk
}

func (bc *BlockChainImpl) InsertBlock(b Block, replaceable bool) error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	return bc.insertBlock(b, replaceable)
}

func (bc *BlockChainImpl) insertBlock(b Block, replaceable bool) error {
	bc.mutex.CheckIsLocked("")

	if bc.getBlock(b.GetBlockSn()) != nil && !replaceable {
		logger.Info("%s already exists", b.GetBlockSn())
		return nil
	}

	if !b.GetBlockSn().IsGenesis() {
		p := getParentBlock(bc.storage, b)
		if p == nil {
			err := xerrors.Errorf("illegal block: parent %s of %s does not exist", b.GetParentBlockSn(), b.GetBlockSn())
			return utils.NewTemporaryError(err, true)
		}
		if p.GetHash() != b.GetParentHash() {
			return xerrors.Errorf("parent %s of %s has different hash; ours is %v != %v",
				b.GetParentBlockSn(), b.GetBlockSn(), p.GetHash(), b.GetParentHash())
		}
		if !bc.extendsFromFinalizedChainOrPreviousSB(b) {
			return xerrors.Errorf("block %s neither extends from finalized chain nor from previous stop block", b.GetBlockSn())
		}
	}
	sn := b.GetBlockSn()
	parentSn := b.GetParentBlockSn()
	if sn.Epoch != parentSn.Epoch {
		if sn.S != 1 || sn.Epoch.Compare(parentSn.Epoch) < 0 {
			return xerrors.Errorf("invalid block %s with parent %s", sn, parentSn)
		}
	} else if sn.S != parentSn.S+1 {
		return xerrors.Errorf("invalid block %s with parent %s", sn, parentSn)
	}

	k := uint32(bc.k.GetValueAtSession(int64(b.GetBlockSn().Epoch.Session)))

	bc.blockDecoder.PrehandleBlock(b)
	notas := bc.blockDecoder.GetNotarizations(b, bc.storage.GetThunderConfig())
	for _, n := range notas {
		// Ensure the notarization is added in order.
		if err := bc.addNotarization(n); err != nil {
			return xerrors.Errorf("invalid block %s with invalid notarization: %w", sn, err)
		}
	}

	// Ensure the block stores correct notarizations.
	// Recall the rule for (e,s):
	// * s=1       : contain the notarizations of the previous k blocks.
	// * s in [2,k]: contain no notarization.
	// * s>k       : contain the notarization of (e,s-k).
	if sn.S == 1 {
		if b.GetParentBlockSn().IsPala() && len(notas) == 0 {
			return xerrors.Errorf("invalid block %s without any notarization", sn)
		}
	} else if sn.S <= k {
		if len(notas) != 0 {
			return xerrors.Errorf("invalid block %s which contains %d notarization (k=%d)",
				sn, len(notas), k)
		}
	} else {
		if len(notas) != 1 {
			return xerrors.Errorf("invalid block %s which contains %d notarization (k=%d)",
				sn, len(notas), k)
		}
		notaSn := notas[0].GetBlockSn()
		if sn.Epoch != notaSn.Epoch || sn.S != notaSn.S+k {
			return xerrors.Errorf("invalid block %s which contains invalid notarization %s (k=%d)",
				sn, notaSn, k)
		}
	}

	return bc.storage.InsertBlock(b)
}

func (bc *BlockChainImpl) extendsFromFinalizedChainOrPreviousSB(b Block) bool {
	bc.mutex.CheckIsLocked("")

	// parent not exists
	p := getParentBlock(bc.storage, b)
	if p == nil {
		return false
	}

	fh := bc.getFinalizedChain()
	sb := bc.getLatestFinalizedStopBlock()
	if sb != nil && sb.GetBlockSn().Epoch.Session != fh.GetBlockSn().Epoch.Session {
		sb = nil
	}

	// stop block of this session is not finalized
	if sb == nil {
		return p.GetNumber() >= fh.GetNumber()
	}

	// TODO: linear search, DOS possible
	// stop block of this session is finalized, linear search
	for p.GetNumber() > sb.GetNumber() {
		if p.GetHash() == fh.GetHash() {
			return true
		}
		p = getParentBlock(bc.storage, p)
		if p == nil {
			return false
		}
	}
	return p.GetHash() == sb.GetHash()
}

func (bc *BlockChainImpl) updateTxPoolGasPrice() {
	bc.mutex.CheckIsLocked("")

	if bc.txpool == nil {
		return
	}

	price := bc.storage.GetClearingGasPrice(bc.gasPriceSession)
	logger.Info("update txpool gas price to %s at session %d", price.String(), bc.gasPriceSession)
	bc.txpool.SetGasPrice(price)
}

func (bc *BlockChainImpl) GetFinalizedEvent() *FinalizedChainExtendedEvent {
	select {
	case e := <-bc.finalizedEvent:
		return e
	default:
		return nil
	}
}

func (bc *BlockChainImpl) isCreatingBlock() bool {
	select {
	case <-bc.isCreatingBlockCh:
		// closed means not
		return false
	default:
		return true
	}
}

func (bc *BlockChainImpl) StartCreatingNewBlocks(
	epoch Epoch, cNota ClockMsgNota,
) (chan BlockMadeEvent, error) {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	if bc.isCreatingBlock() {
		return nil, xerrors.New("is still running")
	}

	parentSn := bc.storage.GetFreshestNotarizedHeadSn()
	pb := bc.getBlock(parentSn)
	if pb == nil {
		return nil, xerrors.Errorf("Parent %s does not exist", parentSn)
	}

	if parentSn.IsPala() {
		nota := bc.getNotarization(parentSn)
		if nota == nil {
			return nil, xerrors.Errorf("Parent %s is not notarized", parentSn)
		}
	}

	k := bc.k.GetValueAtSession(int64(epoch.Session))

	bc.stopChan = make(chan struct{})
	ch := make(chan BlockMadeEvent, k)
	bc.isCreatingBlockCh = make(chan struct{})
	bc.notaChan = make(chan Notarization, 1024)
	go bc.blockMaker.KeepCreatingNewBlocks(bc, pb, epoch, cNota, ch, bc.stopChan, bc.notaChan, bc.isCreatingBlockCh)
	logger.Info("start creating blocks")
	return ch, nil
}

func (bc *BlockChainImpl) GetNotarizations(b Block, k int) []Notarization {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	return bc.getNotarizations(b, k)
}

// getNotarizations returns up to k notarizations that share the same epoch as block b
// starting from and including block b going backwards.
// If one of the above k notarizations is not found, nil is returned.
// I.e. let b.seq = (e,s) then this will return notarizations for blocks (e,s')
// for all s' in [max(1, s-k), s-1] if they exist.
// Notarizations are returned in ascending order.
func (bc *BlockChainImpl) getNotarizations(b Block, k int) []Notarization {
	bc.mutex.CheckIsLocked("")

	var notas []Notarization
	epoch := b.GetBlockSn().Epoch
	for i := 0; i < k && epoch == b.GetBlockSn().Epoch; i++ {
		n := bc.getNotarization(b.GetBlockSn())
		if n != nil {
			notas = append(notas, n)
			b = getParentBlock(bc.storage, b)
		} else {
			return nil
		}
	}
	reverse(notas)
	return notas
}

func getParentBlock(s Storage, b Block) Block {
	return s.GetBlock(b.GetParentBlockSn())
}

// Stop the creation. However, there may be some blocks in the returned channel
// by StartCreatingNewBlocks().
func (bc *BlockChainImpl) StopCreatingNewBlocks(waitingPeriod time.Duration) error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	return bc.stopCreatingNewBlocks(waitingPeriod)
}

func (bc *BlockChainImpl) stopCreatingNewBlocks(waitingPeriod time.Duration) error {
	bc.mutex.CheckIsLocked("")

	if !bc.isCreatingBlock() {
		return xerrors.New("the worker goroutine is not running")
	}

	// Wait the worker goroutine to end.

	stoppedEvent := bc.isCreatingBlockCh
	bc.mutex.Unlock()
	// stoppedEvent is closed when BlockMaker's goroutine ends. There may be a race
	// condition that BlckMaker's goroutine ends now. In that case, nobody reads stopChan
	// and thus the write is blocked forever. Check stoppedEvent to avoid being blocked forever.
	select {
	case bc.stopChan <- struct{}{}:
		logger.Info("stop creating blocks (notified BlockMaker)")
	case <-stoppedEvent:
		logger.Info("stop creating blocks (BlockMaker already stopped")
	}

	select {
	case <-stoppedEvent:
		logger.Info("stopped creating blocks")
	case <-time.After(waitingPeriod):
		logger.Warn("Cannot wait for blockmaker stop")
	}
	bc.mutex.Lock()
	return nil
}

func (bc *BlockChainImpl) IsCreatingBlock() bool {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	return bc.isCreatingBlock()
}

func (bc *BlockChainImpl) AddNotarization(n Notarization) error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	return bc.addNotarization(n)
}

func (bc *BlockChainImpl) addNotarization(n Notarization) error {
	bc.mutex.CheckIsLocked("")

	if oldNota := bc.getNotarization(n.GetBlockSn()); oldNota != nil {
		// Collect the late votes.
		if oldNota.GetNVote() < n.GetNVote() {
			bc.storage.AddNotarization(n)
		}
		return nil
	}

	// Allow adding the notarization only if the parent block and notarization exist.
	// This constraint simplifies the implementation of maintaining the freshest notarized chain.
	sn := n.GetBlockSn()
	fnc := bc.getBlock(sn)
	if fnc == nil {
		return xerrors.Errorf("add notarization %s but the corresponding block does not exist", sn)
	}
	parentSn := fnc.GetParentBlockSn()
	if parentSn.IsPala() && bc.getNotarization(parentSn) == nil {
		return xerrors.Errorf("%s's parent notarization %s does not exist", sn, parentSn)
	}
	notaExt, finalExt, err := bc.storage.AddNotarization(n)
	if err != nil {
		return err
	}

	if notaExt != (BlockSn{}) {
		bc.notifyEvent(FreshestNotarizedChainExtendedEvent{notaExt})
	}

	if finalExt != (BlockSn{}) {
		sb := bc.getLatestFinalizedStopBlock()
		if sb != nil && sb.GetBlockSn().Epoch.Session == finalExt.Epoch.Session {
			bc.stopCreatingNewBlocks(WaitingPeriodForStopingNewBlocks)
			bc.gasPriceSession = finalExt.Epoch.Session + 1
			bc.updateTxPoolGasPrice()
		}
		bc.notifyEvent(FinalizedChainExtendedEvent{finalExt})
	}

	if bc.isCreatingBlock() {
		// The work goroutine is running. Notify it there is a new notarization.
		select {
		case bc.notaChan <- n:
		default:
			debug.Bug("Nota chan is not expected full")
		}
	}

	return nil
}

func (bc *BlockChainImpl) notifyEvent(e interface{}) {
	for _, ch := range bc.eventChans {
		select {
		case ch <- e:
		default:
			debug.Bug("Too busy to process event")
		}
	}
}

func (bc *BlockChainImpl) NewNotificationChannel() <-chan interface{} {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()
	ch := make(chan interface{}, 1024)
	bc.eventChans = append(bc.eventChans, ch)
	return ch
}

func (bc *BlockChainImpl) RemoveNotificationChannel(target <-chan interface{}) {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()
	for i, ch := range bc.eventChans {
		if ch == target {
			bc.eventChans = append(bc.eventChans[:i], bc.eventChans[i+1:]...)
			break
		}
	}
}

func (bc *BlockChainImpl) AllowBadBehaviorForTest() {
	utils.EnsureRunningInTestCode()

	bc.mutex.Lock()
	defer bc.mutex.Unlock()
	bc.blockMaker.(*BlockMakerFake).AllowBadBehavior()
}

// Reset wipes out all data.
func (bc *BlockChainImpl) ResetForTest() error {
	utils.EnsureRunningInTestCode()

	if bc.isCreatingBlock() {
		return xerrors.New("cannot reset BlockChainImpl while it is running")
	}

	bc.mutex.Lock()
	defer bc.mutex.Unlock()
	stopBlockSessionOffset := bc.storage.(*StorageFake).stopBlockSessionOffset
	thunderConfig := bc.storage.GetThunderConfig()
	bc.storage = NewStorageFake(bc.k, stopBlockSessionOffset, thunderConfig)
	return nil
}

func (bc *BlockChainImpl) GetCommInfo(session Session) *committee.CommInfo {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	return bc.storage.GetCommInfo(session)
}

func (bc *BlockChainImpl) GetReward(number uint64) (*reward.Results, error) {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	return bc.storage.GetReward(number)
}

func (bc *BlockChainImpl) GetProposerAddresses(session Session) map[ConsensusId]string {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	return bc.storage.GetProposerAddresses(session)
}

func (bc *BlockChainImpl) GetTxPoolStatus() core.TxPoolStatus {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	return bc.txpool.GetStatus()
}

func (bc *BlockChainImpl) SetProposerAddressesForTest(
	session Session, addresses map[ConsensusId]string) {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	utils.EnsureRunningInTestCode()

	bc.storage.(*StorageFake).SetProposerAddresses(session, addresses)
}

func (bc *BlockChainImpl) GetBlockMakerForTest() BlockMaker {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	utils.EnsureRunningInTestCode()

	return bc.blockMaker
}

func (bc *BlockChainImpl) GetTtTransfersByBlockNumber(number uint64) ([]TtTransferWithHash, error) {
	return bc.storage.(*StorageImpl).GetTtTransfersByBlockNumber(number)
}

func (bc *BlockChainImpl) GetPalaMetaForSnapshot() (map[string][]byte, error) {
	return bc.storage.(*StorageImpl).GetPalaMetaForSnapshot()
}

func (bc *BlockChainImpl) GetTrieStateForSnapshot(keys []common.Hash) ([]trie.SyncResult, error) {
	return bc.storage.(*StorageImpl).GetTrieStateForSnapshot(keys)
}

func (bc *BlockChainImpl) GetTtBlockForSnapshot(number uint64) (*TtBlockForSnapshot, error) {
	return bc.storage.(*StorageImpl).GetTtBlockForSnapshot(number)
}

func (bc *BlockChainImpl) GetTotalInflation(bn rpc.BlockNumber) (*NumericRpcRespnse, error) {
	return bc.storage.(*StorageImpl).GetTotalInflation(bn)
}

func (bc *BlockChainImpl) GetTotalFeeBurned(bn rpc.BlockNumber) (*NumericRpcRespnse, error) {
	return bc.storage.(*StorageImpl).GetTotalFeeBurned(bn)
}

func (bc *BlockChainImpl) GetTotalSupply(bn rpc.BlockNumber) (*NumericRpcRespnse, error) {
	return bc.storage.(*StorageImpl).GetTotalSupply(bn)
}

// GetSessionParams contain StopBlockSessionOffset, K
func (bc *BlockChainImpl) GetSessionParams(session uint32) *SessionParams {
	return bc.storage.(*StorageImpl).GetSessionParams(session)
}

func (bc *BlockChainImpl) GetBidStatus(bn rpc.BlockNumber) ([]*BidStatus, error) {
	return bc.storage.(*StorageImpl).GetBidStatus(bn)
}

type HardforkCfg struct {
	PalaBlock               *big.Int
	VerifyBidSession        Session
	ElectionStopBlockOffset *config.Int64HardforkConfig
	ProposerListName        *config.StringHardforkConfig
	MaxCodeSize             *config.Int64HardforkConfig
	GasTable                *config.StringHardforkConfig
	RewardScheme            *config.StringHardforkConfig
	VaultGasUnlimited       *config.BoolHardforkConfig
	EVMHardforkVersion      *config.StringHardforkConfig
	IsConsensusInfoInHeader *config.BoolHardforkConfig
	RNGVersion              *config.StringHardforkConfig
	BaseFee                 *config.BigIntHardforkConfig
	TokenInflation          *config.BigIntHardforkConfig
	CommitteeRewardRatio    *config.Int64HardforkConfig
	K                       *config.Int64HardforkConfig
	TPCRevertDelegateCall   *config.BoolHardforkConfig
}

func NewThunderConfig(cfg *HardforkCfg) *params.ThunderConfig {
	return &params.ThunderConfig{
		PalaBlock:                      new(big.Int).Set(cfg.PalaBlock),
		VerifyBidSession:               uint32(cfg.VerifyBidSession),
		GetSessionFromDifficulty:       GetSessionFromDifficulty,
		GetBlockSnFromDifficulty:       GetBlockSnFromDifficultySeparately,
		IsInConsensusTx:                IsInConsensusTx,
		BidVerificationEnabled:         func() bool { return true },
		ElectionStopBlockSessionOffset: cfg.ElectionStopBlockOffset,
		ProposerListName:               cfg.ProposerListName,
		MaxCodeSize:                    cfg.MaxCodeSize,
		GasTable:                       cfg.GasTable,
		RewardScheme:                   cfg.RewardScheme,
		VaultGasUnlimited:              cfg.VaultGasUnlimited,
		EVMHardforkVersion:             cfg.EVMHardforkVersion,
		IsConsensusInfoInHeader:        cfg.IsConsensusInfoInHeader,
		RNGVersion:                     cfg.RNGVersion,
		BaseFee:                        cfg.BaseFee,
		TokenInflation:                 cfg.TokenInflation,
		CommitteeRewardRatio:           cfg.CommitteeRewardRatio,
		TPCRevertDelegateCall:          cfg.TPCRevertDelegateCall,
	}
}
