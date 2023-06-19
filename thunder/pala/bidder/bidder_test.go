package bidder

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/consensus/startstopwaiter"
	"github.com/ethereum/go-ethereum/thunder/pala/testutils/detector"

	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chainconfig"
	"github.com/ethereum/go-ethereum/thunder/thunderella/election"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/thundervm"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"
)

var (
	_             = startstopwaiter.StartStopWaiter(&Bidder{})
	bidInfo       *bidCfg
	bidTxGasPrice = big.NewInt(10000)
	bidTxGasMax   = big.NewInt(100000000000)
	voteKeySigner *bls.SigningKey
	stakeinKey    *ecdsa.PrivateKey
)

func init() {
	var err error
	voteKeySigner, err = bls.NewSigningKey()
	if err != nil {
		debug.Bug("Failed to create signing key: %s", err)
	}
	stakeinKey, err = ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		debug.Bug("Failed to create stake-in key: %s", err)
	}
	bidInfo = &bidCfg{
		voteKeySigner:  voteKeySigner,
		stakeinKey:     stakeinKey,
		stake:          big.NewInt(10),
		rewardAddress:  common.Address{},
		gasBidPrice:    big.NewInt(20),
		bidTxGasPrice:  bidTxGasPrice,
		bidTxPriceBump: 10,
		bidTxGasMax:    bidTxGasMax,
		// TODO: should test VaultTPCAddress and CommElectionTPCAddress behavior
		bidAddress:             common.BigToAddress(big.NewInt(40)),
		enableDynamicBidAmount: false,
	}

}

func createTmpDirAndFile(req *require.Assertions) (string, string) {
	tmpdir, err := ioutil.TempDir("", "test_bid")
	req.NoError(err)
	abspath := filepath.Join(tmpdir, "override.yml")

	err = ioutil.WriteFile(abspath, []byte("bidder.amount: 10"), 0666)
	req.NoError(err)

	fmt.Printf("TMPDIR: %s, FILENAME: %s, PATH: %s\n", tmpdir, "file", abspath)
	return tmpdir, abspath
}

type bidCfg struct {
	voteKeySigner          bls.BlsSigner
	stakeinKey             *ecdsa.PrivateKey
	stake                  *big.Int
	rewardAddress          common.Address
	gasBidPrice            *big.Int
	bidTxGasPrice          *big.Int
	bidTxPriceBump         int64
	bidTxGasMax            *big.Int
	bidAddress             common.Address
	enableDynamicBidAmount bool
}

func verifyBid(req *require.Assertions, stakeMsg *thundervm.StakeMsgR2ABI) {
	pubkey, err := bls.PublicKeyFromBytes(stakeMsg.VotePubKey)
	req.NoError(err)
	sig, err := bls.SignatureFromBytes(stakeMsg.Sig)
	req.NoError(err)
	var msg = &election.SignedStakeInfo{
		StakeInfo: election.StakeInfo{
			StakeMsg: election.StakeMsg{
				Stake:      stakeMsg.Stake,
				Coinbase:   stakeMsg.RewardAddress,
				GasPrice:   stakeMsg.GasPrice,
				PubVoteKey: pubkey,
			},
			RefundID: stakeMsg.RefundID,
		},
		Session: stakeMsg.Session,
		Nonce:   stakeMsg.Nonce,
		Sig:     sig,
	}
	req.True(msg.Verify())
}

func validateBid(req *require.Assertions, tx *types.Transaction, session uint32, thunderCfg *params.ThunderConfig) {
	data := tx.Data()
	if thunderCfg.ShouldVerifyBid(session) {
		method, err := thundervm.VaultR2ABI.MethodById(data[:4])
		req.NoError(err)
		req.Equal("bid", method.Name)

		var arg thundervm.StakeMsgR2ABI
		vs, err := method.Inputs.Unpack(data[4:])
		req.NoError(err)
		req.NoError(method.Inputs.Copy(&arg, vs))
		req.Equal(bidInfo.rewardAddress, arg.RewardAddress)
		req.Zero(bidInfo.stake.Cmp(arg.Stake))

		if bidInfo.gasBidPrice.Cmp(oneGwei) < 0 {
			req.Equal(arg.GasPrice, oneGwei)
		} else {
			req.Zero(bidInfo.gasBidPrice.Cmp(arg.GasPrice))
		}

		req.Equal(bidInfo.voteKeySigner.GetPublicKey().ToBytes(), arg.VotePubKey)
		verifyBid(req, &arg)
	} else {
		method, err := thundervm.VaultABI.MethodById(data[:4])
		req.NoError(err)
		req.Equal("bid", method.Name)

		var arg thundervm.StakeMsgABI_0p5
		vs, err := method.Inputs.Unpack(data[4:])
		req.NoError(err)
		req.NoError(method.Inputs.Copy(&arg, vs))
		req.Equal(bidInfo.rewardAddress, arg.RewardAddress)
		req.Zero(bidInfo.stake.Cmp(arg.Stake))

		if bidInfo.gasBidPrice.Cmp(oneGwei) < 0 {
			req.Equal(arg.GasPrice, oneGwei)
		} else {
			req.Zero(bidInfo.gasBidPrice.Cmp(arg.GasPrice))
		}

		req.Equal(bidInfo.voteKeySigner.GetPublicKey().ToBytes(), arg.VotePubKey)
	}
}

func prepareClient(loggingId, bidder string) (Client, error) {
	c := NewFakeClient()
	return c, nil
}

func prepareBidderAndThunderConfig(bidInfo *bidCfg, req *require.Assertions) (*Bidder, *params.ThunderConfig) {
	thunderCfg := blockchain.NewThunderConfig(&blockchain.HardforkCfg{
		PalaBlock:        common.Big0,
		VerifyBidSession: 2,
	})
	b, err := NewBidder(&BidderCfg{
		VoteKeySigner:          bidInfo.voteKeySigner,
		Url:                    "",
		StakeinKey:             bidInfo.stakeinKey,
		Stake:                  bidInfo.stake,
		RewardAddress:          bidInfo.rewardAddress,
		GasBidPrice:            bidInfo.gasBidPrice,
		BidTxGasPrice:          bidInfo.bidTxGasPrice,
		BidTxPriceBump:         bidInfo.bidTxPriceBump,
		BidTxPriceMax:          bidInfo.bidTxGasMax,
		BidAddress:             bidInfo.bidAddress,
		RetryInterval:          0,
		BlockInterval:          100 * time.Millisecond,
		PrepareClientFunc:      prepareClient,
		ThunderConfig:          thunderCfg,
		EnableDynamicBidAmount: bidInfo.enableDynamicBidAmount,
		EnableBiddingByDefault: true,
	})
	req.NoError(err)
	return b, thunderCfg
}

func checkEvent(ch <-chan interface{}, d time.Duration) (interface{}, error) {
	t := time.After(d)
	select {
	case e := <-ch:
		return e, nil
	case <-t:
		return nil, xerrors.New("No events")
	}
}

func TestBidder(t *testing.T) {
	detector := detector.NewBundleDetector()
	detector.SetTrace()
	defer detector.Verify(t)

	req := require.New(t)
	tmpdir, file := createTmpDirAndFile(req)
	defer os.RemoveAll(tmpdir)
	ConfigPath = tmpdir

	b, thunderCfg := prepareBidderAndThunderConfig(bidInfo, req)
	defer b.StopAndWait()
	eventCh := b.NewNotificationChannel()
	defer b.RemoveNotificationChannel(eventCh)
	req.NoError(b.Start())
	e, err := checkEvent(eventCh, 1*time.Second)
	req.NoError(err)
	_, ok := e.(ClientReadyEvent)
	req.True(ok)
	c := b.GetClientForTest().(*FakeClient)
	s := uint32(1)

	t.Run("normal case", func(t *testing.T) {
		req := require.New(t)

		// should bid after receiving new header
		c.AdvanceHead(blockchain.NewBlockSn(s, 0, 1))
		tx, err := c.CheckAndRespondTx(true, 1*time.Second)
		req.NoError(err)
		validateBid(req, tx, s, thunderCfg)
		e, err := checkEvent(eventCh, 1*time.Second)
		req.NoError(err)
		req.Equal(blockchain.Session(s), e.(BiddedEvent).S)

		// should not bid in same session
		for i := uint32(1); i < 11; i++ {
			c.AdvanceHead(blockchain.NewBlockSn(s, 0, i))
			_, err = c.CheckAndRespondTx(false, 0)
			req.Error(err)
		}

		// bid in next session
		s++
		c.AdvanceHead(blockchain.NewBlockSn(s, 0, 1))
		tx, err = c.CheckAndRespondTx(true, 1*time.Second)
		req.NoError(err)
		validateBid(req, tx, s, thunderCfg)
		e, err = checkEvent(eventCh, 1*time.Second)
		req.NoError(err)
		req.Equal(blockchain.Session(s), e.(BiddedEvent).S)

	})

	t.Run("reload bidamount config", func(t *testing.T) {
		req := require.New(t)
		testBidInfo := &bidCfg{
			voteKeySigner:          voteKeySigner,
			stakeinKey:             stakeinKey,
			stake:                  big.NewInt(10),
			rewardAddress:          common.Address{},
			gasBidPrice:            big.NewInt(20),
			bidTxGasPrice:          bidTxGasPrice,
			bidTxPriceBump:         10,
			bidTxGasMax:            bidTxGasMax,
			bidAddress:             common.BigToAddress(big.NewInt(40)),
			enableDynamicBidAmount: true,
		}

		b, thunderCfg := prepareBidderAndThunderConfig(testBidInfo, req)
		defer b.StopAndWait()
		eventCh := b.NewNotificationChannel()
		defer b.RemoveNotificationChannel(eventCh)
		req.NoError(b.Start())
		e, err := checkEvent(eventCh, 1*time.Second)
		req.NoError(err)
		_, ok := e.(ClientReadyEvent)
		req.True(ok)
		c := b.GetClientForTest().(*FakeClient)
		s++
		// should bid after receiving new header
		c.AdvanceHead(blockchain.NewBlockSn(s, 0, 1))
		tx, err := c.CheckAndRespondTx(true, 1*time.Second)
		req.NoError(err)
		validateBid(req, tx, s, thunderCfg)
		e, err = checkEvent(eventCh, 1*time.Second)
		req.NoError(err)
		req.Equal(blockchain.Session(s), e.(BiddedEvent).S)

		// modify conifg, set bidder amount 20
		err = ioutil.WriteFile(file, []byte("bidder.amount: 20"), 0666)
		req.NoError(err)
		bidInfo.stake = big.NewInt(20)

		// check receive a new bid tx
		tx, err = c.CheckAndRespondTx(true, 1*time.Second)
		req.NoError(err)
		validateBid(req, tx, s, thunderCfg)
		e, err = checkEvent(eventCh, 1*time.Second)
		req.NoError(err)
		req.Equal(blockchain.Session(s), e.(BiddedEvent).S)

		// modify conifg, set bidder amount 0
		err = ioutil.WriteFile(file, []byte("bidder.amount: 0"), 0666)
		req.NoError(err)
		bidInfo.stake = big.NewInt(0)

		// check receive a new bid tx
		tx, err = c.CheckAndRespondTx(true, 1*time.Second)
		req.NoError(err)
		validateBid(req, tx, s, thunderCfg)
		e, err = checkEvent(eventCh, 1*time.Second)
		req.NoError(err)
		req.Equal(blockchain.Session(s), e.(BiddedEvent).S)

		// modify conifg back
		err = ioutil.WriteFile(file, []byte("bidder.amount: 10"), 0666)
		req.NoError(err)
		bidInfo.stake = big.NewInt(10)

		// check receive a new bid tx again
		tx, err = c.CheckAndRespondTx(true, 1*time.Second)
		req.NoError(err)
		validateBid(req, tx, s, thunderCfg)
		e, err = checkEvent(eventCh, 1*time.Second)
		req.NoError(err)
		req.Equal(blockchain.Session(s), e.(BiddedEvent).S)
	})

	t.Run("reload bidamount config from pre-complied vault contract", func(t *testing.T) {
		req := require.New(t)

		testBidInfo := &bidCfg{
			voteKeySigner:          voteKeySigner,
			stakeinKey:             stakeinKey,
			stake:                  big.NewInt(10),
			rewardAddress:          common.Address{},
			gasBidPrice:            big.NewInt(20),
			bidTxGasPrice:          bidTxGasPrice,
			bidTxPriceBump:         10,
			bidTxGasMax:            bidTxGasMax,
			bidAddress:             chainconfig.VaultTPCAddress,
			enableDynamicBidAmount: true,
		}

		b, thunderCfg := prepareBidderAndThunderConfig(testBidInfo, req)
		defer b.StopAndWait()
		eventCh := b.NewNotificationChannel()
		defer b.RemoveNotificationChannel(eventCh)

		req.NoError(b.Start())
		e, err := checkEvent(eventCh, 1*time.Second)
		req.NoError(err)
		_, ok := e.(ClientReadyEvent)
		req.True(ok)
		c := b.GetClientForTest().(*FakeClient)

		voterAddress := crypto.PubkeyToAddress(b.stakeinKey.PublicKey)
		c.SetBidAmount(voterAddress, big.NewInt(10))

		// should bid after receiving new header
		c.AdvanceHead(blockchain.NewBlockSn(s, 0, 1))
		tx, err := c.CheckAndRespondTx(true, 1*time.Second)
		req.NoError(err)
		validateBid(req, tx, s, thunderCfg)
		e, err = checkEvent(eventCh, 1*time.Second)
		req.NoError(err)
		req.Equal(blockchain.Session(s), e.(BiddedEvent).S)

		// modify conifg, set bidder amount 20
		c.SetBidAmount(voterAddress, big.NewInt(20))
		bidInfo.stake = big.NewInt(20)

		// check receive a new bid tx
		tx, err = c.CheckAndRespondTx(true, 2*time.Second)
		req.NoError(err)
		validateBid(req, tx, s, thunderCfg)
		e, err = checkEvent(eventCh, 1*time.Second)
		req.NoError(err)
		req.Equal(blockchain.Session(s), e.(BiddedEvent).S)

		// modify conifg, set bidder amount 0
		c.SetBidAmount(voterAddress, big.NewInt(0))
		bidInfo.stake = big.NewInt(0)

		// check receive a new bid tx
		tx, err = c.CheckAndRespondTx(true, 1*time.Second)
		req.NoError(err)
		validateBid(req, tx, s, thunderCfg)
		e, err = checkEvent(eventCh, 1*time.Second)
		req.NoError(err)
		req.Equal(blockchain.Session(s), e.(BiddedEvent).S)

		// modify conifg back
		c.SetBidAmount(voterAddress, big.NewInt(10))
		req.NoError(err)
		bidInfo.stake = big.NewInt(10)

		// check receive a new bid tx again
		tx, err = c.CheckAndRespondTx(true, 1*time.Second)
		req.NoError(err)
		validateBid(req, tx, s, thunderCfg)
		e, err = checkEvent(eventCh, 1*time.Second)
		req.NoError(err)
		req.Equal(blockchain.Session(s), e.(BiddedEvent).S)
	})

	t.Run("retry", func(t *testing.T) {
		req := require.New(t)

		s++
		c.AdvanceHead(blockchain.NewBlockSn(s, 0, 1))
		tx, err := c.CheckAndRespondTx(false, 1*time.Second)
		req.NoError(err)
		validateBid(req, tx, s, thunderCfg)
		tx, err = c.CheckAndRespondTx(true, 1*time.Second)
		req.NoError(err)
		validateBid(req, tx, s, thunderCfg)
		e := <-eventCh
		req.NotNil(e)
		req.Equal(blockchain.Session(s), e.(BiddedEvent).S)
	})

	t.Run("restart", func(t *testing.T) {
		req := require.New(t)

		req.NoError(b.StopAndWait())
		req.NoError(b.Start())
		e, err := checkEvent(eventCh, 1*time.Second)
		req.NoError(err)
		_, ok := e.(ClientReadyEvent)
		req.True(ok)
		c = b.GetClientForTest().(*FakeClient)

		s++
		c.AdvanceHead(blockchain.NewBlockSn(s, 0, 1))
		tx, err := c.CheckAndRespondTx(true, 1*time.Second)
		req.NoError(err)
		validateBid(req, tx, s, thunderCfg)
		e, err = checkEvent(eventCh, 1*time.Second)
		req.NoError(err)
		req.Equal(blockchain.Session(s), e.(BiddedEvent).S)
	})

	t.Run("stop session", func(t *testing.T) {
		req := require.New(t)

		s++
		b.SetStopSessionForTest(blockchain.Session(s))
		defer b.SetStopSessionForTest(0)
		c.AdvanceHead(blockchain.NewBlockSn(s, 0, 1))
		_, err := c.CheckAndRespondTx(false, 0)
		req.Error(err)
	})

	t.Run("bidTxGasMax > suggested > bidTxGasPrice, bid gas price will be suggested", func(t *testing.T) {
		// 100000000000 > 9999 * 10 > 10000, gas price = 9999 * 1000
		req := require.New(t)

		// Skip the tx in the "stop session" test. Without this step,
		// we may receive the tx which uses gas price before we set to the higher value.
		_, err := c.CheckAndRespondTx(true, 1*time.Second)
		req.NoError(err)

		// Now we're sure there will be no new tx until we advance the head.
		s++
		gp := big.NewInt(9999)
		c.SetGasPrice(gp)
		c.AdvanceHead(blockchain.NewBlockSn(s, 0, 1))
		tx, err := c.CheckAndRespondTx(true, 1*time.Second)
		req.NoError(err)
		validateBid(req, tx, s, thunderCfg)
		expected := new(big.Int).Set(gp)
		multiple := big.NewInt(bidInfo.bidTxPriceBump)
		expected.Mul(expected, multiple)
		req.Zero(expected.Cmp(tx.GasPrice()))
	})

	t.Run("bidTxGasMax > bidTxGasPrice > suggested, bid gas price will be bidTxGasPrice", func(t *testing.T) {
		// 100000000000 > 10000 > 100 * 10, gas price = 10000
		req := require.New(t)

		// Now we're sure there will be no new tx until we advance the head.
		s++
		gp := big.NewInt(100)
		c.SetGasPrice(gp)
		c.AdvanceHead(blockchain.NewBlockSn(s, 0, 1))
		tx, err := c.CheckAndRespondTx(true, 1*time.Second)
		req.NoError(err)
		validateBid(req, tx, s, thunderCfg)
		suggested := new(big.Int).Set(gp)
		multiple := big.NewInt(bidInfo.bidTxPriceBump)
		suggested.Mul(suggested, multiple)
		// bidTxGasPrice > suggested gas price
		req.Greater(bidTxGasPrice.Cmp(suggested), 0)
		req.Zero(bidTxGasPrice.Cmp(tx.GasPrice()))
	})

	t.Run("suggested > bidTxGasMax > bidTxGasPrice, bid gas price will be bidTxGasMax", func(t *testing.T) {
		// 999999 * 10 > 50000 > 10000, gas price = 50000
		req := require.New(t)
		newMax := big.NewInt(50000)

		testBidInfo := &bidCfg{
			voteKeySigner:  voteKeySigner,
			stakeinKey:     stakeinKey,
			stake:          big.NewInt(10),
			rewardAddress:  common.Address{},
			gasBidPrice:    big.NewInt(20),
			bidTxGasPrice:  bidTxGasPrice,
			bidTxPriceBump: 10,
			bidTxGasMax:    newMax,
			bidAddress:     common.BigToAddress(big.NewInt(40)),
		}

		b, thunderCfg := prepareBidderAndThunderConfig(testBidInfo, req)
		defer b.StopAndWait()
		eventCh := b.NewNotificationChannel()
		defer b.RemoveNotificationChannel(eventCh)
		req.NoError(b.Start())
		e, err := checkEvent(eventCh, 1*time.Second)
		req.NoError(err)
		_, ok := e.(ClientReadyEvent)
		req.True(ok)
		c := b.GetClientForTest().(*FakeClient)

		// Now we're sure there will be no new tx until we advance the head.
		s++
		gp := big.NewInt(999999)
		c.SetGasPrice(gp)
		c.AdvanceHead(blockchain.NewBlockSn(s, 0, 1))
		tx, err := c.CheckAndRespondTx(true, 1*time.Second)
		req.NoError(err)
		validateBid(req, tx, s, thunderCfg)
		suggested := new(big.Int).Set(gp)
		multiple := big.NewInt(bidInfo.bidTxPriceBump)
		suggested.Mul(suggested, multiple)
		// suggested > bidTxGasPrice gas price
		req.Greater(suggested.Cmp(bidTxGasPrice), 0)
		// suggested > bidTxGasMax gas price
		req.Greater(suggested.Cmp(newMax), 0)
		// bidTxGasMax > bidTxGasPrice gas price
		req.Greater(suggested.Cmp(newMax), 0)
		req.Zero(newMax.Cmp(tx.GasPrice()))
	})

	t.Run("suggested > bidTxGasPrice > bidTxGasMax, bid gas price will be bidTxGasMax", func(t *testing.T) {
		// 999999 * 10 > 10000 > 500, gas price = 500
		req := require.New(t)
		newMax := big.NewInt(500)

		testBidInfo := &bidCfg{
			voteKeySigner:  voteKeySigner,
			stakeinKey:     stakeinKey,
			stake:          big.NewInt(10),
			rewardAddress:  common.Address{},
			gasBidPrice:    big.NewInt(20),
			bidTxGasPrice:  bidTxGasPrice,
			bidTxPriceBump: 10,
			bidTxGasMax:    newMax,
			bidAddress:     common.BigToAddress(big.NewInt(40)),
		}

		b, thunderCfg := prepareBidderAndThunderConfig(testBidInfo, req)
		defer b.StopAndWait()
		eventCh := b.NewNotificationChannel()
		defer b.RemoveNotificationChannel(eventCh)
		req.NoError(b.Start())
		e, err := checkEvent(eventCh, 1*time.Second)
		req.NoError(err)
		_, ok := e.(ClientReadyEvent)
		req.True(ok)
		c := b.GetClientForTest().(*FakeClient)

		// Now we're sure there will be no new tx until we advance the head.
		s++
		gp := big.NewInt(999999)
		c.SetGasPrice(gp)
		c.AdvanceHead(blockchain.NewBlockSn(s, 0, 1))
		tx, err := c.CheckAndRespondTx(true, 1*time.Second)
		req.NoError(err)
		validateBid(req, tx, s, thunderCfg)
		req.Zero(newMax.Cmp(tx.GasPrice()))
	})

	t.Run("should not bid after stopBid called", func(t *testing.T) {
		req := require.New(t)
		newMax := big.NewInt(500)

		testBidInfo := &bidCfg{
			voteKeySigner:  voteKeySigner,
			stakeinKey:     stakeinKey,
			stake:          big.NewInt(10),
			rewardAddress:  common.Address{},
			gasBidPrice:    big.NewInt(20),
			bidTxGasPrice:  bidTxGasPrice,
			bidTxPriceBump: 10,
			bidTxGasMax:    newMax,
			bidAddress:     common.BigToAddress(big.NewInt(40)),
		}

		b, thunderCfg := prepareBidderAndThunderConfig(testBidInfo, req)
		defer b.StopAndWait()
		eventCh := b.NewNotificationChannel()
		defer b.RemoveNotificationChannel(eventCh)
		b.StopBid()
		req.NoError(b.Start())
		e, err := checkEvent(eventCh, 1*time.Second)
		req.NoError(err)
		_, ok := e.(ClientReadyEvent)
		req.True(ok)
		c := b.GetClientForTest().(*FakeClient)

		// Now we're sure there will be no new tx until we advance the head.
		s++
		gp := big.NewInt(999999)
		c.SetGasPrice(gp)
		c.AdvanceHead(blockchain.NewBlockSn(s, 0, 1))
		_, err = c.CheckAndRespondTx(true, 1*time.Second)
		req.Error(err)

		b.StartBid()
		tx, err := c.CheckAndRespondTx(true, 2*time.Second)
		validateBid(req, tx, s, thunderCfg)
	})
}
