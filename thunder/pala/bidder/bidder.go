package bidder

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/consensus/startstopwaiter"

	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chain"
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chainconfig"
	"github.com/ethereum/go-ethereum/thunder/thunderella/election"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"
	"github.com/ethereum/go-ethereum/thunder/thunderella/thundervm"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/davecgh/go-spew/spew"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
	"golang.org/x/xerrors"
)

const (
	// After some testing, we decided to set the gas limit to 1M
	// The test shows this transaction costs around 150k gas. So
	// 1M seems enough in this case.
	gasLimit = uint64(1000000)
)

var (
	logger  = lgr.NewLgr("/bidder")
	negOne  = big.NewInt(-1)
	oneGwei = big.NewInt(params.GWei)
)

func init() {
	// lgr.SetLogLevel("/bidder", lgr.LvlDebug)
}

type BiddedEvent struct {
	S       blockchain.Session
	Receipt *types.Receipt
}

type ClientReadyEvent struct{}

type Client interface {
	Close()
	TransactionReceipt(context.Context, common.Hash) (*types.Receipt, error)
	HeaderByNumber(context.Context, *big.Int) (*types.Header, error)
	SendTransaction(context.Context, *types.Transaction) error
	NonceAt(context.Context, common.Address, *big.Int) (uint64, error)
	SuggestGasPrice(context.Context) (*big.Int, error)
	CallContract(context.Context, ethereum.CallMsg, *big.Int) ([]byte, error)
}

type bidStatus struct {
	Tx *types.Transaction
	S  blockchain.Session
	N  uint16
}

func (s bidStatus) String() string {
	return fmt.Sprintf("S: %s, N: %d, Tx: %s", s.S, s.N, s.Tx.Hash().Hex())
}

type BidderCfg struct {
	LoggingId         string
	Url               string
	PrepareClientFunc func(string, string) (Client, error)
	ThunderConfig     *params.ThunderConfig

	// stake info
	VoteKeySigner bls.BlsSigner
	StakeinKey    *ecdsa.PrivateKey
	Stake         *big.Int
	RewardAddress common.Address
	GasBidPrice   *big.Int

	// bidding tx
	BidTxGasPrice  *big.Int
	BidTxPriceBump int64
	BidTxPriceMax  *big.Int
	BidAddress     common.Address

	RetryInterval time.Duration
	BlockInterval time.Duration
	StopSession   blockchain.Session

	EnableDynamicBidAmount bool
	EnableBiddingByDefault bool
}

type Bidder struct {
	startstopwaiter.StartStopWaiterImpl
	loggingId         string
	client            Client
	url               string
	prepareClientFunc func(string, string) (Client, error)
	thunderConfig     *params.ThunderConfig

	// stake info
	voteKeySigner bls.BlsSigner
	stakeinKey    *ecdsa.PrivateKey
	stake         atomic.Value // *big.Int
	rewardAddress common.Address
	gasBidPrice   *big.Int

	// bidding tx
	bidTxGasPrice  *big.Int
	bidTxPriceBump int64
	bidTxPriceMax  *big.Int
	bidAddress     common.Address
	bidderAddress  common.Address

	retryInterval          time.Duration
	blockInterval          time.Duration
	retryChan              chan bidStatus
	bidAmountCh            chan *big.Int
	biddingSession         atomic.Value // blockchain.Session
	stopSession            atomic.Value // blockchain.Session
	enableDynamicBidAmount bool

	// eMutex protected members
	eMutex     sync.Mutex
	eventChans []chan interface{}

	isBidding bool
}

func NewBidder(cfg *BidderCfg) (*Bidder, error) {
	logger.Debug("[%s] New Bidder", cfg.LoggingId)
	if cfg.BidTxGasPrice == nil {
		cfg.BidTxGasPrice = big.NewInt(0)
	}
	if cfg.BidTxPriceBump <= 0 {
		// When the txpool is full, just using the suggested price would not be processed.
		// Use a higher price to reduce the chance to fail.
		cfg.BidTxPriceBump = 2
	}

	gasBidPrice := cfg.GasBidPrice
	if gasBidPrice.Cmp(oneGwei) < 0 {
		gasBidPrice = oneGwei
	}

	b := &Bidder{
		loggingId:              cfg.LoggingId,
		url:                    cfg.Url,
		prepareClientFunc:      cfg.PrepareClientFunc,
		thunderConfig:          cfg.ThunderConfig,
		voteKeySigner:          cfg.VoteKeySigner,
		stakeinKey:             cfg.StakeinKey,
		rewardAddress:          cfg.RewardAddress,
		gasBidPrice:            gasBidPrice,
		bidTxGasPrice:          cfg.BidTxGasPrice,
		bidTxPriceBump:         cfg.BidTxPriceBump,
		bidTxPriceMax:          cfg.BidTxPriceMax,
		bidAddress:             cfg.BidAddress,
		bidderAddress:          crypto.PubkeyToAddress(cfg.StakeinKey.PublicKey),
		retryInterval:          cfg.RetryInterval,
		blockInterval:          cfg.BlockInterval,
		enableDynamicBidAmount: cfg.EnableDynamicBidAmount,
		isBidding:              cfg.EnableBiddingByDefault,
	}
	b.stake.Store(cfg.Stake)
	b.stopSession.Store(cfg.StopSession)
	b.biddingSession.Store(blockchain.Session(0))
	return b, nil
}

func PrepareClientFunc(loggingId, url string) (Client, error) {
	return ethclient.Dial(url)
}

func (b *Bidder) Start() error {
	logger.Info("[%s] Starting bidder", b.loggingId)
	stoppedChan := make(chan interface{})
	action := func(stopChan chan interface{}) error {
		go b.bidLoop(stopChan, stoppedChan)
		return nil
	}

	return b.StartStopWaiterImpl.Start(action, stoppedChan)
}

func (b *Bidder) StopBid() {
	b.isBidding = false
}

func (b *Bidder) StartBid() {
	b.isBidding = true
}

func (b *Bidder) IsBidding() bool {
	return b.isBidding
}

func (b *Bidder) setupClient(stopChan <-chan interface{}) bool {
setupForEnd:
	for {
		select {
		case <-stopChan:
			return false
		default:
			if b.client == nil {
				if c, err := b.prepareClientFunc(b.loggingId, b.url); err == nil {
					b.client = c
				} else {
					logger.Warn("[%s] Failed to prepare client: %s, %s. Retry later", b.loggingId, b.url, err)
				}
			}

			if b.client != nil {
				break setupForEnd
			}

			time.Sleep(1 * time.Second)
		}
	}
	b.retryChan = make(chan bidStatus)
	b.bidAmountCh = make(chan *big.Int)
	if b.enableDynamicBidAmount {
		if b.bidAddress == chainconfig.VaultTPCAddress {
			b.dynamicLoadBidAmountFromVault(b.bidAmountCh, stopChan)
		} else {
			b.setupConfig(b.bidAmountCh)
		}
	}

	return true
}

func (b *Bidder) bidLoop(stopChan <-chan interface{}, stoppedChan chan interface{}) {
	defer close(stoppedChan)
	if !b.setupClient(stopChan) {
		logger.Info("[%s] Stopping bidder before entering bid loop", b.loggingId)
		return
	}
	b.notifyEvent(ClientReadyEvent{})
	logger.Info("[%s] Entering bid loop", b.loggingId)
	defer b.client.Close()
	ticker := time.After(b.blockInterval * 2)
ForEnd:
	for {
		select {
		case <-stopChan:
			logger.Info("[%s] Stopping bidder", b.loggingId)
			break ForEnd
		case <-ticker:
			h, err := b.client.HeaderByNumber(context.Background(), nil)
			if err != nil {
				logger.Warn("[%s] Cannot get latest header: %s", b.loggingId, err)
				ticker = time.After(b.blockInterval * 2)
				continue
			}

			if shouldBid, s := b.shouldBid(h); !shouldBid {
				logger.Debug("[%s] Skipping bid in session %s", b.loggingId, s)
				ticker = time.After(b.blockInterval * 2)
				continue
			}
			logger.Debug("[%s] Pulled new header (number=%d)", b.loggingId, h.Number.Int64())

			b.bid(h, stopChan)
			ticker = time.After(b.blockInterval * 2)
		case amount := <-b.bidAmountCh:
			stake := b.stake.Load().(*big.Int)
			// when new config is not the same as current, reset bid config
			// amount > 0: normal bid
			// amount = 0: bid 0 TT, make it lose election. Then, you can get all refund
			// amount = -1: bid with default minBidAmount in `createBiddingTx`
			// amount < -1: log an error and bid with 0 TT (make it lose election)
			if stake.Cmp(amount) != 0 {
				switch {
				// amount == 0
				case amount.Cmp(common.Big0) == 0:
					logger.Info("[%s] Received bid option [0] => make it lose the election and refund", b.loggingId)
				// amount == -1
				case amount.Cmp(negOne) == 0:
					logger.Info("[%s] Received bid option [-1] => bid with default min amount", b.loggingId)
				// amount < -1
				case amount.Cmp(negOne) < 0:
					logger.Warn("[%s] Received wrong bid option %v => bid with 0 to make it lose the election", b.loggingId, amount)
					amount = common.Big0
				// amount > 0
				default:
					logger.Info("[%s] Received a new bid amount %s", b.loggingId, amount.String())
				}
				b.stake.Store(amount)
				// biddingSession set 0, next round will send a new bid (2 second later)
				b.biddingSession.Store(blockchain.Session(0))
			}
		case status := <-b.retryChan:
			logger.Debug("[%s] Checking bid status: %s", b.loggingId, status)
			biddingSession := b.biddingSession.Load().(blockchain.Session)
			if r, err := b.getReceipt(status.Tx); err == nil {
				logger.Info("[%s] Received bidding receipt for session %s: %s", b.loggingId, status.S, r.TxHash.Hex())
				b.notifyEvent(BiddedEvent{S: status.S, Receipt: r})
			} else if status.S < biddingSession {
				logger.Warn("[%s] Drop expired bid: %s", b.loggingId, status)
			} else {
				logger.Warn("[%s] No receipt for %s, retrying", b.loggingId, status.Tx.Hash().Hex())
				tx, err := b.repackTransaction(status.Tx)
				if err != nil {
					logger.Warn("[%s] Failed to repack tx: %s", b.loggingId, err)
				} else if err := b.sendTx(tx, status.S); err != nil {
					if strings.HasPrefix(err.Error(), "known transaction: ") {
						logger.Note("[%s] Failed to send tx: %s", b.loggingId, err)
					} else {
						logger.Warn("[%s] Failed to send tx: %s", b.loggingId, err)
					}
				}
				// Either we've successful tried again or failed to try now,
				// check the status later.
				b.checkBidLater(bidStatus{tx, status.S, status.N + 1}, stopChan)
			}
		}
	}
}

func (b *Bidder) checkBidLater(status bidStatus, stopChan <-chan interface{}) {
	go func() {
		ticker := time.After(b.retryInterval)
		select {
		case <-ticker:
			select {
			case b.retryChan <- status:
			case <-stopChan:
			}
		case <-stopChan:
		}
	}()
}

func (b *Bidder) getAvailableElectionStake() (*big.Int, error) {
	method := "getAvailableStake"
	data, err := thundervm.ElectionABI.Pack(method,
		// since refundId is not used now
		[]byte{},
	)
	if err != nil {
		return nil, xerrors.Errorf("failed to pack ElectionABI getAvailableStake: %w", err)
	}
	msg := ethereum.CallMsg{
		From: b.bidderAddress,
		To:   &b.bidAddress,
		Data: data,
	}
	res, err := b.client.CallContract(context.Background(), msg, nil)
	if err != nil {
		return nil, xerrors.Errorf("failed to call contract method '%s': %w", method, err)
	}
	availableStake := big.NewInt(0)
	availableStake.SetBytes(res)
	return availableStake, nil
}

func (b *Bidder) getBiddingNonce() (*big.Int, error) {
	// only called after VerifyBid hardfork
	method := "getNonce"
	key := sha256.Sum256(b.voteKeySigner.GetPublicKey().ToBytes())
	var (
		data []byte
		err  error
	)
	if b.bidAddress == chainconfig.CommElectionTPCAddress {
		data, err = thundervm.ElectionR2ABI.Pack(method,
			key,
		)
	} else {
		data, err = thundervm.VaultR2ABI.Pack(method,
			key,
		)
	}
	if err != nil {
		return nil, xerrors.Errorf("faield to pack getNonce: %w", err)
	}
	msg := ethereum.CallMsg{
		From: b.bidderAddress,
		To:   &b.bidAddress,
		Data: data,
	}
	res, err := b.client.CallContract(context.Background(), msg, nil)
	if err != nil {
		return nil, xerrors.Errorf("failed to call contract method '%s': %w", method, err)
	}
	nonce := big.NewInt(0)
	nonce.SetBytes(res)
	return nonce, nil
}

func (b *Bidder) bid(header *types.Header, stopChan <-chan interface{}) {
	s := blockchain.Session(blockchain.GetSessionFromDifficulty(header.Difficulty, header.Number, b.thunderConfig))
	logger.Info("[%s] Should bid in session %s", b.loggingId, s)
	tx, err := b.createBiddingTx(chain.Seq(header.Number.Int64()), s)
	if err != nil {
		logger.Warn("[%s] Failed to create bidding tx: %s", b.loggingId, err)
		return
	}
	if err := b.sendTx(tx, s); err != nil {
		if strings.HasPrefix(err.Error(), "known transaction: ") {
			logger.Note("[%s] Failed to send tx: %s", b.loggingId, err)
		} else {
			logger.Warn("[%s] Failed to send tx: %s", b.loggingId, err)
		}
	}
	b.biddingSession.Store(s)
	b.checkBidLater(bidStatus{tx, s, 1}, stopChan)
}

func (b *Bidder) getReceipt(tx *types.Transaction) (*types.Receipt, error) {
	return b.client.TransactionReceipt(context.Background(), tx.Hash())
}

func (b *Bidder) shouldBid(header *types.Header) (bool, blockchain.Session) {
	s := blockchain.Session(blockchain.GetSessionFromDifficulty(header.Difficulty, header.Number, b.thunderConfig))
	biddingSession := b.biddingSession.Load().(blockchain.Session)
	shouldBid := !b.hitStopSession(s) && s > biddingSession && b.isBidding
	return shouldBid, s
}

func (b *Bidder) SetStopSessionForTest(s blockchain.Session) {
	utils.EnsureRunningInTestCode()
	b.stopSession.Store(s)
}

func (b *Bidder) SetStakeForTest(stake *big.Int) {
	utils.EnsureRunningInTestCode()
	b.stake.Store(stake)
}

func (b *Bidder) ResetBiddingSessionForTest() {
	utils.EnsureRunningInTestCode()
	b.biddingSession.Store(blockchain.Session(0))
}

func (b *Bidder) hitStopSession(s blockchain.Session) bool {
	stopSession := b.stopSession.Load().(blockchain.Session)
	if stopSession == 0 {
		return false
	}
	return s >= stopSession
}

func (b *Bidder) sendTx(tx *types.Transaction, session blockchain.Session) error {
	logger.Info("[%s] Sending stakein in session %s with nonce %d tx %s", b.loggingId, session, tx.Nonce(), spew.Sdump(tx))
	return b.client.SendTransaction(context.Background(), tx)
}

func (b *Bidder) repackTransaction(tx *types.Transaction) (*types.Transaction, error) {
	nonce, err := b.getNonce(b.bidderAddress)
	if err != nil {
		return tx, err
	}
	tx = types.NewTransaction(nonce, *tx.To(), tx.Value(), gasLimit, tx.GasPrice(), tx.Data())
	return b.signTx(tx)
}

func (b *Bidder) createBiddingTx(blk chain.Seq, s blockchain.Session) (*types.Transaction, error) {
	logger.Debug("[%s] createBiddingTx, blk: %d, session: %d", b.loggingId, blk, s)

	stake := b.stake.Load().(*big.Int)
	// the bid amount < -1 is invalid
	if stake.Cmp(negOne) < 0 {
		panic(fmt.Sprintf("[%s] Stake amount [%s] is invaild", b.loggingId, stake.String()))
	}
	stakeMsg := b.createStakeMsg(s)
	txData, err := b.prepareTxData(stakeMsg, s)
	if err != nil {
		logger.Warn("[%s] Failed to create txData: %s", b.loggingId, err)
		return nil, err
	}
	nonce, err := b.getNonce(b.bidderAddress)
	if err != nil {
		logger.Warn("[%s] Failed to get nonce: %s", b.loggingId, err)
		return nil, err
	}

	value := big.NewInt(0)
	if b.bidAddress == chainconfig.CommElectionTPCAddress {
		availableStake, err := b.getAvailableElectionStake()
		if err != nil {
			logger.Warn("[%s] Failed to get available stake: %s", b.loggingId, err)
			return nil, err
		}
		if availableStake.Cmp(stakeMsg.Stake) < 0 {
			value.Sub(stakeMsg.Stake, availableStake)
		}
	}
	price := new(big.Int).Set(b.bidTxGasPrice)
	if suggested, err := b.client.SuggestGasPrice(context.Background()); err == nil {
		multiple := big.NewInt(b.bidTxPriceBump)
		suggested = suggested.Mul(suggested, multiple)
		if price.Cmp(suggested) < 0 {
			logger.Info("[%s] update the bid gas price from %d to %d",
				b.loggingId, price.Int64(), suggested.Int64())
			price = suggested
		}
	} else {
		logger.Warn("[%s] failed to get suggested gas price: %s", b.loggingId, err)
	}

	// bidTxPriceMax > 0 and price > bidTxPriceMax
	if b.bidTxPriceMax.Cmp(big.NewInt(0)) > 0 && price.Cmp(b.bidTxPriceMax) > 0 {
		logger.Info("[%s] gas price (%d) exceed max gas limit (%d)", b.loggingId, price.Int64(), b.bidTxPriceMax.Int64())
		price = b.bidTxPriceMax
	}
	tx := types.NewTransaction(nonce, b.bidAddress, value, gasLimit, price, txData)
	return b.signTx(tx)
}

func (b *Bidder) signTx(tx *types.Transaction) (*types.Transaction, error) {
	chainId := params.ThunderChainConfig().ChainID
	signer := types.NewEIP155Signer(chainId)
	return types.SignTx(tx, signer, b.stakeinKey)
}

func (b *Bidder) getNonce(addr common.Address) (uint64, error) {
	return b.client.NonceAt(context.Background(), addr, nil)
}

func (b *Bidder) GetClientForTest() Client {
	utils.EnsureRunningInTestCode()
	return b.client
}

func (b *Bidder) notifyEvent(e interface{}) {
	b.eMutex.Lock()
	defer b.eMutex.Unlock()
	for _, ch := range b.eventChans {
		select {
		case ch <- e:
		default:
		}
	}
}

func (b *Bidder) NewNotificationChannel() <-chan interface{} {
	b.eMutex.Lock()
	defer b.eMutex.Unlock()
	ch := make(chan interface{}, 1024)
	b.eventChans = append(b.eventChans, ch)
	return ch
}

func (b *Bidder) RemoveNotificationChannel(target <-chan interface{}) {
	b.eMutex.Lock()
	defer b.eMutex.Unlock()
	for i, ch := range b.eventChans {
		if ch == target {
			b.eventChans = append(b.eventChans[:i], b.eventChans[i+1:]...)
			break
		}
	}
}

func (b *Bidder) createStakeMsg(s blockchain.Session) *election.StakeInfo {
	logger.Debug("[%s] createStakeMsg %d", b.loggingId, s)
	stake := b.stake.Load().(*big.Int)
	if stake.Cmp(negOne) == 0 {
		stake = election.MinBidderStake.GetValueAtSession(int64(s))
	}
	gasBidPrice := b.gasBidPrice
	if gasBidPrice.Cmp(negOne) == 0 {
		gasBidPrice = election.MinBidPrice.GetValueAtSession(int64(s))
	}
	stakeMsg := &election.StakeInfo{
		StakeMsg: election.StakeMsg{
			Stake:      stake,
			PubVoteKey: b.voteKeySigner.GetPublicKey(),
			Coinbase:   b.rewardAddress,
			GasPrice:   gasBidPrice,
		},
	}
	return stakeMsg
}

func (b *Bidder) prepareTxData(stakeMsg *election.StakeInfo, s blockchain.Session) ([]byte, error) {
	if b.bidAddress == chainconfig.CommElectionTPCAddress {
		if b.thunderConfig.ShouldVerifyBid(uint32(s)) {
			signed, err := b.signedStakeInfo(stakeMsg, s)
			if err != nil {
				return nil, err
			}
			return thundervm.StakeMsgToBidCallR2(signed)
		}
		return thundervm.StakeMsgToBidCall(stakeMsg)
	} else {
		if b.thunderConfig.ShouldVerifyBid(uint32(s)) {
			signed, err := b.signedStakeInfo(stakeMsg, s)
			if err != nil {
				return nil, err
			}
			return thundervm.StakeMsgToVaultBidCallR2(signed)
		}
		return thundervm.StakeMsgToVaultBidCall(stakeMsg)
	}
}

func (b *Bidder) signedStakeInfo(stakeInfo *election.StakeInfo, s blockchain.Session) (*election.SignedStakeInfo, error) {
	nonce, err := b.getBiddingNonce()
	if err != nil {
		return nil, err
	}
	// only called after VerifyBid hardfork
	signedStakeInfo := &election.SignedStakeInfo{
		StakeInfo: *stakeInfo,
		Session:   big.NewInt(int64(s)),
		Nonce:     nonce,
	}
	signedStakeInfo.Sign(b.voteKeySigner)
	return signedStakeInfo, nil
}

func (b *Bidder) getBiddingAmount() (*big.Int, error) {
	// only called after VaultR2P5 hardfork
	method := "getBidAmount"
	key := sha256.Sum256(b.voteKeySigner.GetPublicKey().ToBytes())
	var (
		data []byte
		err  error
	)
	if b.bidAddress != chainconfig.VaultTPCAddress {
		return nil, xerrors.Errorf("invalid bid address: [%x] should be [%v]", b.bidAddress, chainconfig.VaultTPCAddress)
	}

	data, err = thundervm.VaultR3ABI.Pack(method, key)
	if err != nil {
		return nil, xerrors.Errorf("faield to pack getBiddingAmount: %w", err)
	}
	msg := ethereum.CallMsg{
		From: b.bidderAddress,
		To:   &b.bidAddress,
		Data: data,
	}
	res, err := b.client.CallContract(context.Background(), msg, nil)
	if err != nil {
		return nil, xerrors.Errorf("failed to call contract method '%s': %w", method, err)
	}
	bidAmount := big.NewInt(0)
	bidAmount.SetBytes(res)
	return bidAmount, nil
}

func (b *Bidder) dynamicLoadBidAmountFromVault(bidAmountCh chan *big.Int, stopChan <-chan interface{}) {
	go func() {
		ticker := time.After(b.blockInterval * 3)
	ForEnd:
		for {
			select {
			case <-ticker:
				amount, err := b.getBiddingAmount()
				if err != nil {
					logger.Warn("[%s] Failed to get bid amount from vault contract: %w", b.loggingId, err)
				} else {
					bidAmountCh <- amount
				}
				ticker = time.After(b.blockInterval * 3)
			case <-stopChan:
				logger.Info("[%s] Stopping dynamic loading bid amount", b.loggingId)
				break ForEnd
			}
		}
	}()
}
