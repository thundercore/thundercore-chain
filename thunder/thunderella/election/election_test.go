package election

import (
	"bytes"
	"math/big"
	"math/rand"
	"sort"
	"testing"

	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func testResult(require *require.Assertions, expected *Result, actual *Result) {
	if expected == nil {
		require.Nil(actual, "actual is not nil")
		// parsing failed as expected
		return
	}
	require.NotNilf(actual, "actual is nil expected %v", *expected)

	require.Equal(expected.ClearingGasPrice, actual.ClearingGasPrice,
		"differerent ClearingGasPrice")

	// Sort the two member slices again by our own criteria before doing
	// element-wise comparison.
	e := expected.Members
	sort.SliceStable(e, func(i, j int) bool {
		return e[i].Stake.Cmp(e[j].Stake) > 0
	})
	a := actual.Members
	sort.SliceStable(a, func(i, j int) bool {
		return a[i].Stake.Cmp(a[j].Stake) > 0
	})
	require.Equal(len(e), len(a), "Wrong member size")
	for i, e0 := range e {
		a0 := a[i]
		require.Equal(e0.Stake, a0.Stake, "Result Stakes differ")
		require.Equal(e0.PubVoteKey, a0.PubVoteKey, "Result PubVoteKeys differ")
		require.Equal(e0.Coinbase, a0.Coinbase, "Result Coinbases differ")
	}
}

func dummyCheck(*StakeInfo) bool {
	return true
}

func filterCheck(stakes []*StakeInfo) func(*StakeInfo) bool {
	return func(c *StakeInfo) bool {
		for _, stake := range stakes {
			if bytes.Equal(c.ToBytes(), stake.ToBytes()) {
				return true
			}
		}
		return false
	}
}

func failToFreeze(b0 *StakeInfo) func(*StakeInfo) bool {
	return func(b *StakeInfo) bool {
		return !bytes.Equal(b0.ToBytes(), b.ToBytes())
	}
}

func TestElectWithSamePubVoteKeyAndStakingAddress(t *testing.T) {
	require := require.New(t)

	// Case 1: s2 is not enough min auction stake.
	s1 := newStake(require, common.HexToAddress("0x1"),
		AuctionStakeThreshold.GetValueAt(config.InitialBlockNum))
	s2 := newStake(require, common.HexToAddress("0x1"),
		MinBidderStake.GetValueAt(config.InitialBlockNum))
	s3 := newStake(require, common.HexToAddress("0x1"), big.NewInt(0))

	err := s2.PubVoteKey.FromBytes(s1.PubVoteKey.ToBytes())
	require.Nil(err, "FromBytes error: %v", err)

	err = s3.PubVoteKey.FromBytes(s1.PubVoteKey.ToBytes())
	require.Nil(err, "FromBytes error: %v", err)

	stakes := []*StakeInfo{s1, s2}

	actual := Elect(stakes, dummyCheck, int64(0))
	testResult(require, nil, actual)

	// Case 2: s3 is stake-out.
	stakes = []*StakeInfo{s1, s3}
	actual = Elect(stakes, dummyCheck, int64(0))
	testResult(require, nil, actual)

	// Case 3: s1 is enough min auction stake.
	stakes = []*StakeInfo{s2, s3, s1}
	actual = Elect(stakes, dummyCheck, int64(0))
	expected := &Result{
		Members:          []committee.MemberInfo{*s1.ToMemberInfo()},
		ClearingGasPrice: big.NewInt(20),
	}
	testResult(require, expected, actual)
}

func TestElectWithSamePubVoteKey(t *testing.T) {
	require := require.New(t)

	s := big.NewInt(0).Sub(AuctionStakeThreshold.GetValueAt(config.InitialBlockNum),
		MinBidderStake.GetValueAt(config.InitialBlockNum))
	s1 := newStake(require, common.HexToAddress("0x1"), s)
	s2 := newStake(require, common.HexToAddress("0x2"), s)
	s3 := newStake(require, common.HexToAddress("0x3"),
		MinBidderStake.GetValueAt(config.InitialBlockNum))

	err := s2.PubVoteKey.FromBytes(s1.PubVoteKey.ToBytes())
	require.Nil(err, "FromBytes error: %v", err)

	// Case 1: not enough min auction stake to form a committee because s2 has the same PubVoteKey as s1 so s2 is
	// filtered out.
	stakes := []*StakeInfo{s1, s2}

	actual := Elect(stakes, dummyCheck, int64(0))
	testResult(require, nil, actual)

	// Case 2: s1 & s3 are enough min auction stake to form a committee.
	stakes = []*StakeInfo{s1, s2, s3}
	actual = Elect(stakes, dummyCheck, int64(0))
	expected := &Result{
		Members:          []committee.MemberInfo{*s1.ToMemberInfo(), *s3.ToMemberInfo()},
		ClearingGasPrice: big.NewInt(20),
	}
	testResult(require, expected, actual)
}

func expectedElectionResult(elected []*StakeInfo, clearingGasPrice *big.Int) *Result {
	members := make([]committee.MemberInfo, 0, len(elected))
	for _, b := range elected {
		members = append(members, *b.ToMemberInfo())
	}
	return &Result{
		Members:          members,
		ClearingGasPrice: clearingGasPrice,
	}
}

func TestElection_TopK(t *testing.T) {
	req := require.New(t)

	keys := make([]*bls.SigningKey, 0)
	stake := new(big.Int).Add(MinBidderStake.GetValueAtSession(10), common.Big256)
	bids := make([]*StakeInfo, 0)
	for i := 0; i < 20; i++ {
		k, err := bls.NewSigningKey()
		req.NoError(err)
		keys = append(keys, k)
		b := newStakeWithKey(common.HexToAddress("0x1"), stake, k.GetPublicKey())
		bids = append(bids, b)
		stake = stake.Sub(stake, common.Big1)
	}

	actual := Elect(bids[:1], dummyCheck, int64(10))
	testResult(req, expectedElectionResult(bids[:1], bids[0].GasPrice), actual)

	actual = Elect(bids[:2], dummyCheck, int64(10))
	testResult(req, expectedElectionResult(bids[:2], bids[0].GasPrice), actual)

	actual = Elect(bids[:3], dummyCheck, int64(10))
	testResult(req, expectedElectionResult(bids[:3], bids[0].GasPrice), actual)

	actual = Elect(bids, dummyCheck, int64(10))
	testResult(req, expectedElectionResult(bids[:3], bids[0].GasPrice), actual)

	expectedBids := make([]*StakeInfo, 3)
	copy(expectedBids, bids[:3])
	expectedGPrice := new(big.Int).Set(bids[0].GasPrice)

	// random shuffle
	for i := int32(len(bids)) - 1; i > 0; i-- {
		j := rand.Int31n(i + 1)
		bids[i], bids[j] = bids[j], bids[i]
	}

	actual = Elect(bids, dummyCheck, int64(10))
	testResult(req, expectedElectionResult(expectedBids, expectedGPrice), actual)
}

func TestMaliciousBidWithSamePubVoteKey(t *testing.T) {
	// Thunder 0.5's election algorithm contains this vulnerability:
	// A malicious bid that specifies a stake larger than its account balance
	// i.e., a bid where `freeze(bid)` fails and return false, can stop other bids
	// with the same voting key from being considered if the malicious bid has a
	// higher `stake/gasPrice` value.
	req := require.New(t)

	k, err := bls.NewSigningKey()
	req.NoError(err)
	stake0 := new(big.Int).Set(AuctionStakeThreshold.GetValueAt(config.InitialBlockNum))
	stake1 := new(big.Int).Add(stake0, common.Big1)

	sessionNumbers := []int64{0, 100}
	// Same voting key, different staking addresses, with enough stake to form a committee with any single bid
	b0 := newStakeWithKey(common.HexToAddress("0x1"), stake0, k.GetPublicKey())
	b1 := newStakeWithKey(common.HexToAddress("0x2"), stake1, k.GetPublicKey())

	for _, sess := range sessionNumbers {
		t.Run(ElectionScheme.GetValueAtSession(sess), func(t *testing.T) {
			req := require.New(t)
			// `failToFreeze(b1)` makes `b1` simulate a bid with a stake larger than the balance in its `StakingAddr`
			// The fact that `b1` stops `b0` from being considered is the vulnerability.
			actual := Elect([]*StakeInfo{b0, b1}, failToFreeze(b1), sess)
			testResult(req, nil, actual)

			// `b2` has a stake equal to `b0` but a different voting key
			b2 := newStake(req, common.HexToAddress("0x2"), stake0)
			actual = Elect([]*StakeInfo{b0, b1, b2}, failToFreeze(b1), sess)
			testResult(req, expectedElectionResult([]*StakeInfo{b2}, b2.GasPrice), actual)

			// Using `dummyCheck()` allows all `freeze()` calls to succeed.
			// `b0` has enough stake to form a committee by itself.
			actual = Elect([]*StakeInfo{b0}, dummyCheck, sess)
			testResult(req, expectedElectionResult([]*StakeInfo{b0}, b0.GasPrice), actual)

			// `b0` and `b1` still have the same voting key, so `b1`, with its higher stake, wins.
			actual = Elect([]*StakeInfo{b0, b1}, dummyCheck, sess)
			testResult(req, expectedElectionResult([]*StakeInfo{b1}, b1.GasPrice), actual)

			// When `freeze()` is allowed to succeed for all bids,
			// since `b1` and `b3` has the same amount of stake, the one that comes first
			// in the stake table wins.
			b3 := newStake(req, common.HexToAddress("0x4"), stake1)
			actual = Elect([]*StakeInfo{b0, b1, b3}, dummyCheck, sess)
			var exp []*StakeInfo
			if ElectionScheme.GetValueAtSession(sess) == "TopKCandidates" {
				exp = []*StakeInfo{b1, b3}
			} else {
				exp = []*StakeInfo{b1}
			}
			testResult(req, expectedElectionResult(exp, b1.GasPrice), actual)

			actual = Elect([]*StakeInfo{b0, b3, b1}, dummyCheck, sess)
			if ElectionScheme.GetValueAtSession(sess) == "TopKCandidates" {
				exp = []*StakeInfo{b3, b1}
			} else {
				exp = []*StakeInfo{b3}
			}
			testResult(req, expectedElectionResult(exp, b3.GasPrice), actual)
		})
	}
}

func TestElectWithStakeOrder(t *testing.T) {
	require := require.New(t)

	// Case 1: same gas price
	s1 := newStake(require, common.HexToAddress("0x1"),
		AuctionStakeThreshold.GetValueAt(config.InitialBlockNum))
	s2 := newStake(require, common.HexToAddress("0x2"),
		AuctionStakeThreshold.GetValueAt(config.InitialBlockNum))

	stakes := []*StakeInfo{s1, s2}

	actual := Elect(stakes, dummyCheck, 0)
	expected := &Result{
		Members:          []committee.MemberInfo{*s1.ToMemberInfo()},
		ClearingGasPrice: big.NewInt(20),
	}
	testResult(require, expected, actual)

	// Case 2: lower gas price
	s2.GasPrice = big.NewInt(10)
	actual = Elect(stakes, dummyCheck, 0)
	expected = &Result{
		Members:          []committee.MemberInfo{*s2.ToMemberInfo()},
		ClearingGasPrice: big.NewInt(10),
	}
	testResult(require, expected, actual)
}

func TestElectWithAccountBalance(t *testing.T) {
	require := require.New(t)

	// Case 1: not enough account balance
	s1 := newStake(require, common.HexToAddress("0x1"), AuctionStakeThreshold.GetValueAt(config.InitialBlockNum))

	stakes := make([]*StakeInfo, 0)

	actual := Elect(stakes, filterCheck(stakes), 0)
	testResult(require, nil, actual)

	stakes = append(stakes, s1)
	actual = Elect(stakes, filterCheck(stakes), 0)
	expected := &Result{
		Members:          []committee.MemberInfo{*s1.ToMemberInfo()},
		ClearingGasPrice: big.NewInt(20),
	}
	testResult(require, expected, actual)
}

func TestElectWithAuctionStakeThreshold(t *testing.T) {
	require := require.New(t)

	// Case 1: not enough auction stake
	s1 := newStake(require, common.HexToAddress("0x1"), MinBidderStake.GetValueAt(config.InitialBlockNum))

	stakes := []*StakeInfo{s1}

	actual := Elect(stakes, dummyCheck, 0)
	testResult(require, nil, actual)

	// Case 2: enough auction stake
	s1.Stake = AuctionStakeThreshold.GetValueAt(config.InitialBlockNum)
	actual = Elect(stakes, dummyCheck, 0)
	expected := &Result{
		Members:          []committee.MemberInfo{*s1.ToMemberInfo()},
		ClearingGasPrice: big.NewInt(20),
	}
	testResult(require, expected, actual)
}

func TestCandidatesWithZeroGas(t *testing.T) {
	require := require.New(t)

	k, err := bls.NewSigningKey()
	require.Equal(nil, err, "Got an error creating signing key: %s", err)
	stakes := make([]*StakeInfo, 2)
	stakes[0] = &StakeInfo{
		StakeMsg: StakeMsg{
			Stake:      AuctionStakeThreshold.GetValueAtSession(0),
			PubVoteKey: k.GetPublicKey(),
			Coinbase:   common.HexToAddress("0x1"),
			GasPrice:   big.NewInt(0),
		},
		StakingAddr: common.HexToAddress("0x1"),
		RefundID:    []byte{},
	}
	stakes[1] = newStake(require, common.HexToAddress("0x1"), MinBidderStake.GetValueAtSession(0))

	candidates := getCandidates(stakes, 0)
	expected := []*StakeInfo{stakes[1]}
	require.Equal(expected, candidates, "bad candidates")
}

func TestCandidateValues(t *testing.T) {
	require := require.New(t)

	k, err := bls.NewSigningKey()
	require.Equal(nil, err, "Got an error creating signing key: %s", err)
	stakes := make([]*StakeInfo, 2)
	oldMinStake := MinBidderStake.GetValueAtSession(0)
	defer func() {
		MinBidderStake.SetTestValueAtSession(oldMinStake, 0)
	}()
	MinBidderStake.SetTestValueAtSession(big.NewInt(1), 0)
	stakes[0] = &StakeInfo{
		StakeMsg: StakeMsg{
			Stake:      big.NewInt(1000),
			PubVoteKey: k.GetPublicKey(),
			Coinbase:   common.HexToAddress("0x1"),
			GasPrice:   big.NewInt(1),
		},
		StakingAddr: common.HexToAddress("0x1"),
		RefundID:    []byte{},
	}
	k, err = bls.NewSigningKey()
	require.Equal(nil, err, "Got an error creating signing key: %s", err)
	stakes[1] = &StakeInfo{
		StakeMsg: StakeMsg{
			Stake:      big.NewInt(10001),
			PubVoteKey: k.GetPublicKey(),
			Coinbase:   common.HexToAddress("0x1"),
			GasPrice:   big.NewInt(999),
		},
		StakingAddr: common.HexToAddress("0x1"),
		RefundID:    []byte{},
	}

	candidates := getCandidates(stakes, 0)
	expected := []*StakeInfo{stakes[0], stakes[1]}
	require.Equal(expected, candidates, "bad candidates")
}

func TestElectWithNoGasPrice(t *testing.T) {
	require := require.New(t)

	k, err := bls.NewSigningKey()
	require.Equal(nil, err, "Got an error creating signing key: %s", err)

	s1 := &StakeInfo{
		StakeMsg: StakeMsg{
			Stake:      AuctionStakeThreshold.GetValueAtSession(0),
			PubVoteKey: k.GetPublicKey(),
			Coinbase:   common.HexToAddress("0x1"),
			GasPrice:   big.NewInt(0),
		},
		StakingAddr: common.HexToAddress("0x1"),
		RefundID:    []byte{},
	}

	stakes := make([]*StakeInfo, 0)

	stakes = append(stakes, s1)
	actual := Elect(stakes, filterCheck(stakes), 0)
	testResult(require, nil, actual)

	s2 := newStake(require, common.HexToAddress("0x1"), MinBidderStake.GetValueAtSession(0))
	stakes = append(stakes, s2)
	actual = Elect(stakes, filterCheck(stakes), 0)
	testResult(require, nil, actual) // auction stake threshold not met
	oldThresh := AuctionStakeThreshold.GetValueAtSession(0)

	defer func() {
		AuctionStakeThreshold.SetTestValueAtSession(oldThresh, 0)
	}()

	AuctionStakeThreshold.SetTestValueAtSession(big.NewInt(1), 0)
	actual = Elect(stakes, filterCheck(stakes), 0)
	expected := &Result{
		Members:          []committee.MemberInfo{*s2.ToMemberInfo()},
		ClearingGasPrice: big.NewInt(20),
	}
	testResult(require, expected, actual)
}

func TestElectMaxSizeCheck(t *testing.T) {
	require := require.New(t)

	config.SetManual("committee.MinBidderStake", "1")
	//For slices, the capacity defaults to the length
	stakes := make([]*StakeInfo, committee.MaxCommSize+1)
	for i := 0; i < committee.MaxCommSize; i++ {
		s := newStake(require, common.HexToAddress("0x1"), big.NewInt(1))
		stakes[i] = s
	}
	amount := big.NewInt(0).Sub(AuctionStakeThreshold.GetValueAt(config.InitialBlockNum), big.NewInt(512))
	stakes[committee.MaxCommSize] = newStake(require, common.HexToAddress("0x1"), amount)

	actual := Elect(stakes, dummyCheck, 0)
	testResult(require, nil, actual)
}

func TestElectR3WithDifferentGasPrice(t *testing.T) {
	require := require.New(t)

	k, err := bls.NewSigningKey()
	require.Equal(nil, err, "Got an error creating signing key: %s", err)

	k2, _ := bls.NewSigningKey()
	k3, _ := bls.NewSigningKey()

	ElectionScheme.SetTestValueAtSession("TopKCandidates", 0)

	s1 := &StakeInfo{
		StakeMsg: StakeMsg{
			Stake:      MinBidderStake.GetValueAtSession(0),
			PubVoteKey: k.GetPublicKey(),
			Coinbase:   common.HexToAddress("0x1"),
			GasPrice:   big.NewInt(1),
		},
		StakingAddr: common.HexToAddress("0x1"),
		RefundID:    []byte{},
	}

	s2 := &StakeInfo{
		StakeMsg: StakeMsg{
			Stake:      new(big.Int).Mul(MinBidderStake.GetValueAtSession(0), big.NewInt(3)),
			PubVoteKey: k2.GetPublicKey(),
			Coinbase:   common.HexToAddress("0x1"),
			GasPrice:   big.NewInt(1000000),
		},
		StakingAddr: common.HexToAddress("0x2"),
		RefundID:    []byte{},
	}

	s3 := &StakeInfo{
		StakeMsg: StakeMsg{
			Stake:      new(big.Int).Mul(MinBidderStake.GetValueAtSession(0), big.NewInt(2)),
			PubVoteKey: k3.GetPublicKey(),
			Coinbase:   common.HexToAddress("0x1"),
			GasPrice:   big.NewInt(1),
		},
		StakingAddr: common.HexToAddress("0x3"),
		RefundID:    []byte{},
	}

	stakes := make([]*StakeInfo, 0)
	stakes = append(stakes, s1)
	stakes = append(stakes, s2)
	stakes = append(stakes, s3)

	oldThresh := AuctionStakeThreshold.GetValueAtSession(0)
	defer func() {
		AuctionStakeThreshold.SetTestValueAtSession(oldThresh, 0)
	}()

	AuctionStakeThreshold.SetTestValueAtSession(big.NewInt(1), 0)
	actual := ElectR3(stakes, filterCheck(stakes), 0)

	// originally should be 3, 1, 2, but since gas price is ignored when get candiates, the order is 2, 3, 1
	expected := &Result{
		Members:          []committee.MemberInfo{*s2.ToMemberInfo(), *s3.ToMemberInfo(), *s1.ToMemberInfo()},
		ClearingGasPrice: big.NewInt(1000000),
	}
	testResult(require, expected, actual)
}

func TestElectR3GasPriceSchemaTop1CandidatesDecision(t *testing.T) {
	require := require.New(t)

	k, err := bls.NewSigningKey()
	require.Equal(nil, err, "Got an error creating signing key: %s", err)

	k2, _ := bls.NewSigningKey()
	k3, _ := bls.NewSigningKey()

	// 3 * MinBidderStake + gas price 100
	ClearingGasPriceScheme.SetTestValueAtSession("Top1CandidatesDecision", 0)
	s1 := &StakeInfo{
		StakeMsg: StakeMsg{
			Stake:      new(big.Int).Mul(MinBidderStake.GetValueAtSession(0), big.NewInt(3)),
			PubVoteKey: k.GetPublicKey(),
			Coinbase:   common.HexToAddress("0x1"),
			GasPrice:   big.NewInt(100),
		},
		StakingAddr: common.HexToAddress("0x1"),
		RefundID:    []byte{},
	}

	// 3 * MinBidderStake + gas price 200
	s2 := &StakeInfo{
		StakeMsg: StakeMsg{
			Stake:      new(big.Int).Mul(MinBidderStake.GetValueAtSession(0), big.NewInt(3)),
			PubVoteKey: k2.GetPublicKey(),
			Coinbase:   common.HexToAddress("0x1"),
			GasPrice:   big.NewInt(200),
		},
		StakingAddr: common.HexToAddress("0x2"),
		RefundID:    []byte{},
	}

	// 2 * MinBidderStake + gas price 300
	s3 := &StakeInfo{
		StakeMsg: StakeMsg{
			Stake:      new(big.Int).Mul(MinBidderStake.GetValueAtSession(0), big.NewInt(2)),
			PubVoteKey: k3.GetPublicKey(),
			Coinbase:   common.HexToAddress("0x1"),
			GasPrice:   big.NewInt(300),
		},
		StakingAddr: common.HexToAddress("0x3"),
		RefundID:    []byte{},
	}

	stakes := make([]*StakeInfo, 0)
	stakes = append(stakes, s1)
	stakes = append(stakes, s2)
	stakes = append(stakes, s3)

	oldThresh := AuctionStakeThreshold.GetValueAtSession(0)
	defer func() {
		AuctionStakeThreshold.SetTestValueAtSession(oldThresh, 0)
	}()

	AuctionStakeThreshold.SetTestValueAtSession(big.NewInt(1), 0)
	actual := ElectR3(stakes, filterCheck(stakes), 0)

	// the order is 1,2,3 and ClearingGasPrice get the top 1 candidates 200
	expected := &Result{
		Members:          []committee.MemberInfo{*s1.ToMemberInfo(), *s2.ToMemberInfo(), *s3.ToMemberInfo()},
		ClearingGasPrice: big.NewInt(200),
	}
	testResult(require, expected, actual)
}
