package blockchain

import (
	"math/big"
	"sync"

	"golang.org/x/xerrors"
)

type weightedVoteCountingScheme struct {
	mu        sync.Mutex
	weight    map[ConsensusId]*big.Int
	threshold *big.Int
}

// NOTE: PassThreshold just counts votes, it only accepts valid voter ids and doesn't check duplicates voter ids.
func (w *weightedVoteCountingScheme) PassThreshold(ids []ConsensusId) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	sum, err := weightedVoteCount(ids, w.weight)
	if err != nil {
		return false, err
	}
	return sum.Cmp(w.threshold) >= 0, nil
}

func weightedVoteCount(ids []ConsensusId, weight map[ConsensusId]*big.Int) (*big.Int, error) {
	sum := new(big.Int)
	for _, id := range ids {
		w, ok := weight[id]
		if !ok {
			return nil, xerrors.Errorf("invalid voter id=%s", id)
		}
		sum.Add(sum, w)
	}
	return sum, nil
}

func newCountVoteByStake(e *ElectionResultImpl) *weightedVoteCountingScheme {
	total := new(big.Int)
	weight := make(map[ConsensusId]*big.Int)
	for _, info := range e.CommInfo.MemberInfo {
		id := ConsensusIdFromPubKey(info.PubVoteKey)
		stake := new(big.Int).Set(info.Stake)
		weight[id] = stake
		total.Add(total, stake)
	}

	// threshold = ceil(total * 2 / 3)
	threshold := divCeil(new(big.Int).Mul(total, big.NewInt(2)), big.NewInt(3))

	return &weightedVoteCountingScheme{
		weight:    weight,
		threshold: threshold,
	}
}

// newCountVoteBySeat treats count by seat as special case of weighted vote counting scheme where
// all voters have the same wieght.
// NOTE: this implementation is slower than just using len to count the number of vote.
func newCountVoteBySeat(e *ElectionResultImpl) *weightedVoteCountingScheme {
	total := big.NewInt(int64(len(e.CommInfo.MemberInfo)))
	weight := make(map[ConsensusId]*big.Int)
	for _, info := range e.CommInfo.MemberInfo {
		id := ConsensusIdFromPubKey(info.PubVoteKey)
		// every voter has the same weight
		weight[id] = big.NewInt(1)
	}

	// threshold = ceil(total * 2 / 3)
	threshold := divCeil(new(big.Int).Mul(total, big.NewInt(2)), big.NewInt(3))

	return &weightedVoteCountingScheme{
		weight:    weight,
		threshold: threshold,
	}
}

func divCeil(x, y *big.Int) *big.Int {
	q := new(big.Int)
	r := new(big.Int)

	// x = q*y + r
	q.QuoRem(x, y, r)
	if r.Sign() == 0 {
		return q
	}
	return q.Add(q, big.NewInt(1))
}
