package reward

import (
	// Standard imports

	"math/big"
	"testing"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chainconfig"
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"

	// Vendor imports
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	accel1       = common.HexToAddress("0xc2940")
	accel2       = common.HexToAddress("0xc2941")
	comm1        = common.HexToAddress("0xc2931")
	comm2        = common.HexToAddress("0xc2932")
	comm3        = common.HexToAddress("0xc2933")
	totalFee     = big.NewInt(150)
	accelFee     = big.NewInt(20)
	committeeFee = big.NewInt(100)
)

func getStateDB() *state.StateDB {
	// Create an empty state database
	db := rawdb.NewMemoryDatabase()
	state, _ := state.New(common.Hash{}, state.NewDatabase(db), nil)

	setFee(state, feeHash.total, totalFee)
	setFee(state, feeHash.accel, accelFee)
	setFee(state, feeHash.committee, committeeFee)

	return state
}

func getCommInfo() *committee.CommInfo {
	k1, _ := bls.NewSigningKey()
	k2, _ := bls.NewSigningKey()

	commInfo := &committee.CommInfo{
		AccelId: 1,
		MemberInfo: []committee.MemberInfo{
			{
				Stake:    big.NewInt(20),
				Coinbase: comm1,
			},
			{
				Stake:    big.NewInt(30),
				Coinbase: comm2,
			},
			{
				Stake:    big.NewInt(50),
				Coinbase: comm3,
			},
		},
		AccelInfo: []committee.AccelInfo{
			{
				MemberInfo: committee.MemberInfo{
					PubVoteKey: k1.GetPublicKey(),
					Stake:      big.NewInt(30),
					Coinbase:   accel1,
				},
			},
			{
				MemberInfo: committee.MemberInfo{
					PubVoteKey: k2.GetPublicKey(),
					Stake:      big.NewInt(70),
					Coinbase:   accel2,
				},
			},
		},
	}
	return commInfo
}

func TestResultsToJSON(t *testing.T) {
	assert := assert.New(t)

	expected := &Results{
		Payments: []Payment{
			Payment{
				Coinbase: comm1,
				Fee:      big.NewInt(1 << 55),
			},
			Payment{
				Coinbase: comm2,
				Fee:      big.NewInt(0).Mul(big.NewInt(1<<60), big.NewInt(1<<60)),
			},
		},
	}

	actual := &Results{}
	actual.FromJSON(expected.ToJSON())
	assert.Equal(expected, actual, "Results different")
}

func TestGetCurrentDistributionBasic(t *testing.T) {
	req := require.New(t)

	expected := &Results{
		Payments: []Payment{
			Payment{
				Coinbase: comm1,
				Fee:      big.NewInt(20),
			},
			Payment{
				Coinbase: comm2,
				Fee:      big.NewInt(30),
			},
			Payment{
				Coinbase: comm3,
				Fee:      big.NewInt(50),
			},
			Payment{
				Coinbase: accel1,
				Fee:      big.NewInt(6),
			},
			Payment{
				Coinbase: accel2,
				Fee:      big.NewInt(14),
			},
			Payment{
				Coinbase: chainconfig.TestnetThunderFoundationAddr,
				Fee:      big.NewInt(30),
			},
		},
	}

	actual, err := getCurrentDistribution(getCommInfo(), getStateDB())

	req.NoError(err, "getDistributingResults got error: %v", err)
	req.Equal(totalFee, actual.TotalFees(), "mismatch on total fee")
	req.Equal(expected, actual, "Results different")
}

func TestGetCurrentDistributionSameCoinbase(t *testing.T) {
	req := require.New(t)

	coinbase := common.HexToAddress("0x3a220f351252089d385b29beca14e27f204c29cb")
	expected := &Results{
		Payments: []Payment{
			Payment{
				Coinbase: coinbase,
				Fee:      big.NewInt(20),
			},
			Payment{
				Coinbase: coinbase,
				Fee:      big.NewInt(30),
			},
			Payment{
				Coinbase: coinbase,
				Fee:      big.NewInt(50),
			},
			Payment{
				Coinbase: accel2,
				Fee:      big.NewInt(6),
			},
			Payment{
				Coinbase: accel2,
				Fee:      big.NewInt(14),
			},
			Payment{
				Coinbase: chainconfig.TestnetThunderFoundationAddr,
				Fee:      big.NewInt(30),
			},
		},
	}

	commInfo := getCommInfo()
	for x := range commInfo.MemberInfo {
		commInfo.MemberInfo[x].Coinbase = coinbase
	}

	for x := range commInfo.AccelInfo {
		commInfo.AccelInfo[x].Coinbase = accel2
	}
	actual, err := getCurrentDistribution(commInfo, getStateDB())

	req.NoError(err, "getCurrentDistribution got error: %v", err)
	req.Equal(totalFee, actual.TotalFees(), "mismatch on total fee")
	req.Equal(expected, actual, "Results different")
}

func TestCommitteeFeeIndivisableByTotalStake(t *testing.T) {
	assert := assert.New(t)

	// committeeFees is not divisible by totalStake
	// committeeFees = 66
	// totalStake = 13
	//
	// comm_1 fee = 30 = floor(66 * 6 / 13)
	// comm_2 fee = 35 = floor(66 * 7 / 13)
	//
	// committeeFees = 66 != 65 = comm_1 fee + comm_2 fee
	//
	// This test verifies that accelator fee is 67 instead of 66 so no transaction fee is lost.
	committeeFee = big.NewInt(66)
	commInfo := getCommInfo()

	commInfo.MemberInfo = []committee.MemberInfo{
		committee.MemberInfo{
			Stake:    big.NewInt(6),
			Coinbase: comm1,
		},
		committee.MemberInfo{
			Stake:    big.NewInt(7),
			Coinbase: comm2,
		},
	}

	expected := &Results{
		Payments: []Payment{
			Payment{
				Coinbase: comm1,
				Fee:      big.NewInt(30),
			},
			Payment{
				Coinbase: comm2,
				Fee:      big.NewInt(35),
			},
			Payment{
				Coinbase: accel1,
				Fee:      big.NewInt(6),
			},
			Payment{
				Coinbase: accel2,
				Fee:      big.NewInt(14),
			},
			Payment{
				Coinbase: chainconfig.TestnetThunderFoundationAddr,
				Fee:      big.NewInt(65),
			},
		},
	}

	actual, err := getCurrentDistribution(commInfo, getStateDB())

	assert.NoError(err, "getCurrentDistribution got error: %v", err)
	assert.Equal(totalFee, actual.TotalFees(), "mismatch on total fee")
	assert.Equal(expected, actual, "Results different")
	committeeFee = big.NewInt(100)
}

var rewardTest = []struct {
	coinbase common.Address
	balance  *big.Int
	fee      *big.Int
	expected *big.Int
}{
	{common.HexToAddress("0x3a220f351252089d385b29beca14e27f204c2941"),
		big.NewInt(1), big.NewInt(0), big.NewInt(1)},
	{common.HexToAddress("0x3a220f351252089d385b29beca14e27f204c2942"),
		big.NewInt(2), big.NewInt(7), big.NewInt(9)},
	{common.HexToAddress("0x3a220f351252089d385b29beca14e27f204c2943"),
		big.NewInt(3), big.NewInt(11), big.NewInt(14)},

	// Fee account balace should be reduce by total fees above.
	{chainconfig.TestnetTxnFeeAddr, big.NewInt(18), big.NewInt(0), big.NewInt(0)},
}

func TestReward(t *testing.T) {
	// Create an empty state database
	db := rawdb.NewMemoryDatabase()
	state, _ := state.New(common.Hash{}, state.NewDatabase(db), nil)
	results := &Results{
		Payments: make([]Payment, 0),
	}

	for _, payment := range rewardTest {
		state.SetBalance(payment.coinbase, payment.balance)
		results.AddValue(&payment.coinbase, payment.fee)
	}

	assert := assert.New(t)
	err := distribute(state, results)
	assert.NoError(err, "distribute error: %v", err)

	for _, payment := range rewardTest {
		// using assert.True with a Cmp instead of assert.Equal, because it's possible to
		// have 2 big.Ints with value 0, but one with cap field == 5, one with cap field
		// == 0, will be considered assert.Equal will assert false
		assert.True(payment.expected.Cmp(state.GetBalance(payment.coinbase)) == 0,
			"incorrect balance")
	}
}

var insufficientFeeBalanceTest = []struct {
	coinbase common.Address
	balance  *big.Int
	reward   *big.Int
	fee      *big.Int
}{
	{common.HexToAddress("0x3a220f351252089d385b29beca14e27f204c2940"),
		big.NewInt(1), big.NewInt(3), big.NewInt(3)},
	// Fee account balace is 0.
	{chainconfig.TestnetTxnFeeAddr, big.NewInt(0), big.NewInt(0), big.NewInt(0)},
}

func TestInsufficientFeeBalanceError(t *testing.T) {
	// Create an empty state database
	db := rawdb.NewMemoryDatabase()
	state, _ := state.New(common.Hash{}, state.NewDatabase(db), nil)
	results := &Results{
		Payments: make([]Payment, 0),
	}

	for _, payment := range insufficientFeeBalanceTest {
		state.SetBalance(payment.coinbase, payment.balance)
		results.AddValue(&payment.coinbase, payment.fee)
	}

	assert := assert.New(t)
	err := distribute(state, results)
	assert.Equal(errInsufficientFeeBalance, err, "insufficient fee balance")
}

var totalFeeTests = []struct {
	totalFee *big.Int
	expected *big.Int
}{
	{nil, big.NewInt(0)},
	{big.NewInt(10), big.NewInt(10)},
}

func TestTotalFee(t *testing.T) {
	assert := assert.New(t)
	// Create an empty state database
	db := rawdb.NewMemoryDatabase()
	state, _ := state.New(common.Hash{}, state.NewDatabase(db), nil)

	for _, test := range totalFeeTests {
		if test.totalFee != nil {
			setFee(state, feeHash.total, test.totalFee)
		}
		actual := getFee(state, feeHash.total)
		assert.True(test.expected.Cmp(actual) == 0, "incorrect totalFee")
	}
}

func TestNoCommittee(t *testing.T) {
	req := require.New(t)

	k1, _ := bls.NewSigningKey()

	commInfo := &committee.CommInfo{
		AccelId: 0,
		AccelInfo: []committee.AccelInfo{
			{
				MemberInfo: committee.MemberInfo{
					PubVoteKey: k1.GetPublicKey(),
					Stake:      big.NewInt(3310),
					Coinbase:   accel1,
				},
			},
		},
	}

	expected := &Results{
		Payments: []Payment{
			Payment{
				Coinbase: accel1,
				Fee:      accelFee,
			},
			Payment{
				Coinbase: chainconfig.TestnetThunderFoundationAddr,
				Fee:      big.NewInt(130),
			},
		},
	}

	state := getStateDB()
	state.SetBalance(chainconfig.TestnetTxnFeeAddr, big.NewInt(300))
	actual := Distribute(commInfo, state)

	req.NotNil(actual, "getDistributingResults got error")
	req.Equal(totalFee, actual.TotalFees(), "mismatch on total fee")
	req.Equal(expected, actual, "Results different")

	totalFee := getFee(state, feeHash.total)
	req.Equal(int64(0), totalFee.Int64(), "total fee wrong")
}

func Test_distributeR4(t *testing.T) {
	assert := assert.New(t)
	// Create an empty state database
	db := rawdb.NewMemoryDatabase()
	state, _ := state.New(common.Hash{}, state.NewDatabase(db), nil)

	state.AddBalance(chainconfig.TestnetTxnFeeAddr, big.NewInt(5566))

	payments := []Payment{
		{common.HexToAddress("0xa"), big.NewInt(5567)},
		{common.HexToAddress("0xb"), big.NewInt(1234)},
		{common.HexToAddress("0xc"), big.NewInt(4567)},
		{common.HexToAddress("0xd"), big.NewInt(9527)},
	}

	distributeR4(state, &Results{payments})

	for _, payment := range payments {
		assert.Equal(payment.Fee, state.GetBalance(payment.Coinbase))
	}

	// balance of TestnetTxnFeeAddr should not be changed
	assert.Equal(big.NewInt(5566), state.GetBalance(chainconfig.TestnetTxnFeeAddr))
}

func TestUpdateFeeR4(t *testing.T) {
	assert := assert.New(t)
	gwei := int64(1000000000)
	basefee := big.NewInt(gwei)
	inflation := new(big.Int).Mul(big.NewInt(15), big.NewInt(int64(params.Ether)))

	txdatas := []types.TxData{
		// gasprice <= basefee will be skipped
		&types.LegacyTx{
			GasPrice: big.NewInt(12345678),
		},
		&types.DynamicFeeTx{
			GasFeeCap: big.NewInt(1 * gwei),
			GasTipCap: big.NewInt(1 * gwei),
		},
		&types.DynamicFeeTx{
			GasFeeCap: big.NewInt(1 * gwei),
			GasTipCap: big.NewInt(0 * gwei),
		},

		// normal tx
		&types.LegacyTx{
			GasPrice: big.NewInt(5 * gwei),
		},
		&types.DynamicFeeTx{
			GasFeeCap: big.NewInt(10 * gwei),
			GasTipCap: big.NewInt(2 * gwei),
		},
		&types.DynamicFeeTx{
			GasFeeCap: big.NewInt(10 * gwei),
		},
	}

	txs := []*types.Transaction{}
	for _, txdata := range txdatas {
		txs = append(txs, types.NewTx(txdata))
	}

	receipts := []*types.Receipt{
		{GasUsed: uint64(11111)},
		{GasUsed: uint64(11111)},
		{GasUsed: uint64(11111)},
		{GasUsed: uint64(123456)},
		{GasUsed: uint64(234567)},
		{GasUsed: uint64(98765)},
	}

	t.Run("test update fee r4 with same share", func(t *testing.T) {
		// Create an empty state database
		db := rawdb.NewMemoryDatabase()
		defer db.Close()

		state, _ := state.New(common.Hash{}, state.NewDatabase(db), nil)

		UpdateFeesR4(state, txs, receipts, inflation, basefee, int64(50))

		totalFee := getFee(state, feeHash.total)
		accelFee := getFee(state, feeHash.accel)
		committeeFee := getFee(state, feeHash.committee)

		// tx1: 123456 * (5-1) gwei
		// tx2: 234567 * (10-1) gwei
		// tx3: 98765  * (10-1) gwei
		// inflation: 15 ether
		expectedTotal := new(big.Int).Add(inflation, big.NewInt(3493812*gwei))
		assert.Equal(expectedTotal, totalFee)

		halfFee := new(big.Int).Quo(totalFee, big.NewInt(2))
		remainingFee := new(big.Int).Sub(totalFee, halfFee)
		assert.Equal(halfFee, committeeFee)
		assert.Equal(remainingFee, accelFee)

		totalInflation := GetTotalInflation(state)
		totalFeeBurned := GetTotalFeeBurned(state)

		assert.Equal(inflation, totalInflation)
		// fee burned = (123456 + 234567 + 98765) * 1gwei
		assert.Equal(big.NewInt(456788*gwei), totalFeeBurned)
	})

	t.Run("test update fee r4 with different share", func(t *testing.T) {
		// Create an empty state database
		db := rawdb.NewMemoryDatabase()
		defer db.Close()

		state, _ := state.New(common.Hash{}, state.NewDatabase(db), nil)

		UpdateFeesR4(state, txs, receipts, inflation, basefee, int64(90))

		totalFee := getFee(state, feeHash.total)
		accelFee := getFee(state, feeHash.accel)
		committeeFee := getFee(state, feeHash.committee)

		// tx1: 123456 * (5-1) gwei
		// tx2: 234567 * (10-1) gwei
		// tx3: 98765  * (10-1) gwei
		// inflation: 15 ether
		expectedTotal := new(big.Int).Add(inflation, big.NewInt(3493812*gwei))
		assert.Equal(expectedTotal, totalFee)

		commShare := mulDiv(totalFee, big.NewInt(90), big.NewInt(100))
		remainingFee := new(big.Int).Sub(totalFee, commShare)
		assert.Equal(remainingFee, accelFee)
		assert.Equal(commShare, committeeFee)

		totalInflation := GetTotalInflation(state)
		totalFeeBurned := GetTotalFeeBurned(state)

		assert.Equal(inflation, totalInflation)
		// fee burned = (123456 + 234567 + 98765) * 1gwei
		assert.Equal(big.NewInt(456788*gwei), totalFeeBurned)
	})

	t.Run("test basefee increased", func(t *testing.T) {
		// Create an empty state database
		db := rawdb.NewMemoryDatabase()
		defer db.Close()

		state, _ := state.New(common.Hash{}, state.NewDatabase(db), nil)
		newBaseFee := new(big.Int).SetInt64(5 * gwei)

		UpdateFeesR4(state, txs, receipts, inflation, newBaseFee, int64(90))

		totalFee := getFee(state, feeHash.total)
		accelFee := getFee(state, feeHash.accel)
		committeeFee := getFee(state, feeHash.committee)

		// tx1: gasprice <= basefee will be skipped
		// tx2: 234567 * (10-5) gwei
		// tx3: 98765  * (10-5) gwei
		// inflation: 15 ether
		expectedTotal := new(big.Int).Add(inflation, big.NewInt(1666660*gwei))
		assert.Equal(expectedTotal, totalFee)

		commShare := mulDiv(totalFee, big.NewInt(90), big.NewInt(100))
		remainingFee := new(big.Int).Sub(totalFee, commShare)
		assert.Equal(remainingFee, accelFee)
		assert.Equal(commShare, committeeFee)

		totalInflation := GetTotalInflation(state)
		totalFeeBurned := GetTotalFeeBurned(state)

		assert.Equal(inflation, totalInflation)
		// fee burned = (234567 + 98765) * 5gwei
		assert.Equal(big.NewInt(1666660*gwei), totalFeeBurned)
	})

	t.Run("test inflation increased", func(t *testing.T) {
		// Create an empty state database
		db := rawdb.NewMemoryDatabase()
		defer db.Close()

		state, _ := state.New(common.Hash{}, state.NewDatabase(db), nil)
		newInflation := new(big.Int).Mul(big.NewInt(20), big.NewInt(params.Ether))

		UpdateFeesR4(state, txs, receipts, newInflation, basefee, int64(90))

		totalFee := getFee(state, feeHash.total)
		accelFee := getFee(state, feeHash.accel)
		committeeFee := getFee(state, feeHash.committee)

		// tx1: 123456 * (5-1) gwei
		// tx2: 234567 * (10-1) gwei
		// tx3: 98765  * (10-1) gwei
		// inflation: 20 ether
		expectedTotal := new(big.Int).Add(newInflation, big.NewInt(3493812*gwei))
		assert.Equal(expectedTotal, totalFee)

		commShare := mulDiv(totalFee, big.NewInt(90), big.NewInt(100))
		remainingFee := new(big.Int).Sub(totalFee, commShare)
		assert.Equal(remainingFee, accelFee)
		assert.Equal(commShare, committeeFee)

		totalInflation := GetTotalInflation(state)
		totalFeeBurned := GetTotalFeeBurned(state)

		assert.Equal(newInflation, totalInflation)
		// fee burned = (123456 + 234567 + 98765) * 1gwei
		assert.Equal(big.NewInt(456788*gwei), totalFeeBurned)
	})

	t.Run("test zero inflation", func(t *testing.T) {
		// Create an empty state database
		db := rawdb.NewMemoryDatabase()
		defer db.Close()

		state, _ := state.New(common.Hash{}, state.NewDatabase(db), nil)
		newInflation := common.Big0

		UpdateFeesR4(state, txs, receipts, newInflation, basefee, int64(90))

		totalFee := getFee(state, feeHash.total)
		accelFee := getFee(state, feeHash.accel)
		committeeFee := getFee(state, feeHash.committee)

		// tx1: 123456 * (5-1) gwei
		// tx2: 234567 * (10-1) gwei
		// tx3: 98765  * (10-1) gwei
		// inflation: 0 ether
		expectedTotal := new(big.Int).Add(newInflation, big.NewInt(3493812*gwei))
		assert.Equal(expectedTotal, totalFee)

		commShare := mulDiv(totalFee, big.NewInt(90), big.NewInt(100))
		remainingFee := new(big.Int).Sub(totalFee, commShare)
		assert.Equal(remainingFee, accelFee)
		assert.Equal(commShare, committeeFee)

		totalInflation := GetTotalInflation(state)
		totalFeeBurned := GetTotalFeeBurned(state)

		// https://github.com/golang/go/issues/27379
		// - abs: (big.nat) <nil>
		// + abs: (big.nat) {}
		assert.Equal(int64(0), totalInflation.Int64())
		// fee burned = (123456 + 234567 + 98765) * 1gwei
		assert.Equal(big.NewInt(456788*gwei), totalFeeBurned)
	})

	t.Run("test zero basefee", func(t *testing.T) {
		// Create an empty state database
		db := rawdb.NewMemoryDatabase()
		defer db.Close()

		state, _ := state.New(common.Hash{}, state.NewDatabase(db), nil)
		newBaseFee := common.Big0

		UpdateFeesR4(state, txs, receipts, inflation, newBaseFee, int64(90))

		totalFee := getFee(state, feeHash.total)
		accelFee := getFee(state, feeHash.accel)
		committeeFee := getFee(state, feeHash.committee)

		// 12345678 * 11111 + 1gwei * 11111 + 1gwei * 11111 + 5gwi * 123456 + 10gwei * 234567 + 10 gwei * 98765
		// inflation: 15 ether
		expectedTotal := new(big.Int).Add(inflation, big.NewInt(3972959172828258))
		assert.Equal(expectedTotal, totalFee)

		commShare := mulDiv(totalFee, big.NewInt(90), big.NewInt(100))
		remainingFee := new(big.Int).Sub(totalFee, commShare)
		assert.Equal(remainingFee, accelFee)
		assert.Equal(commShare, committeeFee)

		totalInflation := GetTotalInflation(state)
		totalFeeBurned := GetTotalFeeBurned(state)

		assert.Equal(inflation, totalInflation)
		assert.Equal(int64(0), totalFeeBurned.Int64())
	})
}
