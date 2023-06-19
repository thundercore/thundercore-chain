package testutils

import (
	// Standard imports
	"crypto/ecdsa"
	"math/big"
	"time"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/analytics/metrics"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/txutils"

	// Vendor imports
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

var (
	accelKey1, _    = bls.NewSigningKey()
	accelKey2, _    = bls.NewSigningKey()
	TestingCommInfo = committee.CommInfo{
		AccelId: 1,
		AccelInfo: []committee.AccelInfo{
			{
				MemberInfo: committee.MemberInfo{
					Stake:      big.NewInt(1),
					PubVoteKey: accelKey1.GetPublicKey(),
					Coinbase:   common.HexToAddress("0x2930"),
					GasPrice:   big.NewInt(1),
				},
			},
			{
				MemberInfo: committee.MemberInfo{
					Stake:      big.NewInt(1),
					PubVoteKey: accelKey2.GetPublicKey(),
					Coinbase:   common.HexToAddress("0x2931"),
					GasPrice:   big.NewInt(0),
				},
			},
		},
		MemberInfo: []committee.MemberInfo{
			{
				Stake:    big.NewInt(20),
				Coinbase: common.HexToAddress("0x2932"),
				GasPrice: big.NewInt(10000000),
			},
			{
				Stake:    big.NewInt(30),
				Coinbase: common.HexToAddress("0x2933"),
				GasPrice: big.NewInt(10000003),
			},
			{
				Stake:    big.NewInt(50),
				Coinbase: common.HexToAddress("0x2934"),
				GasPrice: big.NewInt(10000100),
			},
		},
	}
)

func MakeTxact(from *ecdsa.PrivateKey,
	to *common.Address,
	nonce uint64,
	amount *big.Int,
	chainId *big.Int,
	gasPrice *big.Int,
) *types.Transaction {
	var data = []byte(nil)
	return txutils.MakeSignedTxWithData(from, to, nonce, amount, chainId, data, gasPrice)
}

// helper function to build transactions
func MakeTxactSimple(
	from *ecdsa.PrivateKey,
	to *common.Address,
	nonce uint64,
) *types.Transaction {
	return MakeTxact(from, to, nonce, big.NewInt(0), nil, nil)
}

type PredResult struct {
	result int
}

const (
	// if someone creates a value via val := testutils.PredResult{} it won't be good for
	// anything, as the value 0 is not a legal value (and checked for below)
	predAbort = iota + 1
	predFail
	predOk
)

// returning functions instead of global instances so the instances can't be changed

// PredAbort returns an instance that tells WaitForPredicate to immediately return false
func PredAbort() PredResult { return PredResult{predAbort} }

// PredFail returns an instance that tells WaitForPredicate to keep retrying the predicate until
// timeout
func PredFail() PredResult { return PredResult{predFail} }

// PredOk returns an instance that tells WaitForPredicate to begin testing that the predicate
// remains true
func PredOk() PredResult { return PredResult{predOk} }

// WaitForPredicate waits until a callback returns Ok, returns Abort, or until a timeout.  A
// return value of true indicates that the required condition (specified by the predicate callback)
// returned PredOk.  After PredOk is returned it waits a specified period of time to make sure
// the predicate remains true
func WaitForPredicate(predicate func() PredResult, timeout time.Duration,
	after time.Duration,
) bool {
	start := time.Now()
	limit := start.Add(timeout)
	ok := false
	for !ok && time.Now().Before(limit) {
		switch predicate().result {
		case predOk:
			ok = true // break out of the loop
		case predAbort:
			return false
		case predFail:
			time.Sleep(10 * time.Millisecond)
		default:
			debug.Bug("can only use Pred... constants from testutils")
		}
	}
	if predicate().result == predOk {
		time.Sleep(after)
		// the value might have incremented further
		return predicate().result == predOk
	}
	return false
}

// WaitForCounter waits until a counter reaches a value, and then maintains that value for a
// specified period of time
func WaitForCounter(metric metrics.Counter, value int64, timeout time.Duration,
	after time.Duration,
) bool {
	return WaitForPredicate(func() PredResult {
		if metric.Get() == value {
			return PredOk()
		} else if metric.Get() < value {
			return PredFail()
		} else {
			return PredAbort()
		}
	}, timeout, after)
}
