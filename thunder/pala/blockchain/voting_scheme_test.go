package blockchain

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
)

func TestNewCountVoteByStake(t *testing.T) {
	keys := make([]*bls.PublicKey, 3)
	for i := range keys {
		for {
			if key, err := bls.NewSigningKey(); err == nil {
				keys[i] = &key.PublicKey
				break
			}
		}
	}

	toId := ConsensusIdFromPubKey

	testcases := []struct {
		keys          []*bls.PublicKey
		stakes        []int64
		wantWeight    map[ConsensusId]*big.Int
		wantThreshold *big.Int
	}{
		{
			keys:          []*bls.PublicKey{keys[0]},
			stakes:        []int64{3},
			wantThreshold: big.NewInt(2),
			wantWeight: map[ConsensusId]*big.Int{
				toId(keys[0]): big.NewInt(3),
			},
		},
		{
			keys:          []*bls.PublicKey{keys[0], keys[1], keys[2]},
			stakes:        []int64{3, 3, 4},
			wantThreshold: big.NewInt(7),
			wantWeight: map[ConsensusId]*big.Int{
				toId(keys[0]): big.NewInt(3),
				toId(keys[1]): big.NewInt(3),
				toId(keys[2]): big.NewInt(4),
			},
		},
		{
			keys:          []*bls.PublicKey{keys[0], keys[1], keys[2]},
			stakes:        []int64{3, 4, 4},
			wantThreshold: big.NewInt(8),
			wantWeight: map[ConsensusId]*big.Int{
				toId(keys[0]): big.NewInt(3),
				toId(keys[1]): big.NewInt(4),
				toId(keys[2]): big.NewInt(4),
			},
		},
		{
			keys:          []*bls.PublicKey{keys[0], keys[1], keys[2]},
			stakes:        []int64{4, 4, 4},
			wantThreshold: big.NewInt(8),
			wantWeight: map[ConsensusId]*big.Int{
				toId(keys[0]): big.NewInt(4),
				toId(keys[1]): big.NewInt(4),
				toId(keys[2]): big.NewInt(4),
			},
		},
		{
			keys:          []*bls.PublicKey{keys[0], keys[1], keys[2]},
			stakes:        []int64{5, 2, 6},
			wantThreshold: big.NewInt(9),
			wantWeight: map[ConsensusId]*big.Int{
				toId(keys[0]): big.NewInt(5),
				toId(keys[1]): big.NewInt(2),
				toId(keys[2]): big.NewInt(6),
			},
		},
	}

	for i, tc := range testcases {

		t.Run(fmt.Sprintln(i), func(t *testing.T) {
			// Build election result.
			var e ElectionResultImpl
			for i, key := range tc.keys {
				m := committee.MemberInfo{
					Stake:      big.NewInt(tc.stakes[i]),
					PubVoteKey: key,
				}
				e.CommInfo.MemberInfo = append(e.CommInfo.MemberInfo, m)
			}

			scheme := newCountVoteByStake(&e)
			if scheme.threshold.Cmp(tc.wantThreshold) != 0 {
				t.Errorf("threshold not equal want=%s, got=%s", tc.wantThreshold, scheme.threshold)
			}
			requireWeightEqual(t, tc.wantWeight, scheme.weight)
		})
	}
}

func TestNewCountVoteBySeat(t *testing.T) {
	keys := make([]*bls.PublicKey, 4)
	for i := range keys {
		for {
			if key, err := bls.NewSigningKey(); err == nil {
				keys[i] = &key.PublicKey
				break
			}
		}
	}

	toId := ConsensusIdFromPubKey

	testcases := []struct {
		keys          []*bls.PublicKey
		stakes        []int64
		wantWeight    map[ConsensusId]*big.Int
		wantThreshold *big.Int
	}{
		{
			keys:          []*bls.PublicKey{keys[0]},
			stakes:        []int64{3},
			wantThreshold: big.NewInt(1),
			wantWeight: map[ConsensusId]*big.Int{
				toId(keys[0]): big.NewInt(1),
			},
		},
		{
			keys:          []*bls.PublicKey{keys[0], keys[1]},
			stakes:        []int64{3, 2},
			wantThreshold: big.NewInt(2),
			wantWeight: map[ConsensusId]*big.Int{
				toId(keys[0]): big.NewInt(1),
				toId(keys[1]): big.NewInt(1),
			},
		},
		{
			keys:          []*bls.PublicKey{keys[0], keys[1], keys[2]},
			stakes:        []int64{3, 2, 1},
			wantThreshold: big.NewInt(2),
			wantWeight: map[ConsensusId]*big.Int{
				toId(keys[0]): big.NewInt(1),
				toId(keys[1]): big.NewInt(1),
				toId(keys[2]): big.NewInt(1),
			},
		},
		{
			keys:          []*bls.PublicKey{keys[0], keys[1], keys[2], keys[3]},
			stakes:        []int64{4, 3, 2, 1},
			wantThreshold: big.NewInt(3),
			wantWeight: map[ConsensusId]*big.Int{
				toId(keys[0]): big.NewInt(1),
				toId(keys[1]): big.NewInt(1),
				toId(keys[2]): big.NewInt(1),
				toId(keys[3]): big.NewInt(1),
			},
		},
	}

	for i, tc := range testcases {
		t.Run(fmt.Sprintln(i), func(t *testing.T) {
			// Build election result.
			var e ElectionResultImpl
			for i, key := range tc.keys {
				m := committee.MemberInfo{
					Stake:      big.NewInt(tc.stakes[i]),
					PubVoteKey: key,
				}
				e.CommInfo.MemberInfo = append(e.CommInfo.MemberInfo, m)
			}

			scheme := newCountVoteBySeat(&e)
			if scheme.threshold.Cmp(tc.wantThreshold) != 0 {
				t.Errorf("threshold not equal want=%s, got=%s", tc.wantThreshold, scheme.threshold)
			}
			requireWeightEqual(t, tc.wantWeight, scheme.weight)
		})
	}
}

func requireWeightEqual(t *testing.T, want, got map[ConsensusId]*big.Int) {
	t.Helper()
	if len(want) != len(got) {
		t.Errorf("weight len not equal, want=%d got=%d", len(want), len(got))
	}

	for k, v := range want {
		if v2, ok := got[k]; ok {
			if v.Cmp(v2) != 0 {
				t.Errorf("weight not equal, id=%s, want=%d got=%d", k, len(want), len(got))
			}
		} else {
			t.Errorf("want id not exist, id=%s", k)
		}
	}
}

func TestWeightedVoteCount(t *testing.T) {

	ids := make([]ConsensusId, 5)
	for i := range ids {
		for {
			if key, err := bls.NewSigningKey(); err == nil {
				ids[i] = ConsensusIdFromPubKey(&key.PublicKey)
				break
			}
		}
	}

	weight := map[ConsensusId]*big.Int{
		ids[0]: big.NewInt(1),
		ids[1]: big.NewInt(2),
		ids[2]: big.NewInt(3),
		ids[3]: big.NewInt(4),
		ids[4]: big.NewInt(5),
	}

	testcases := []struct {
		ids  []ConsensusId
		want *big.Int
	}{
		{
			ids:  []ConsensusId{},
			want: big.NewInt(0),
		},
		{
			ids:  []ConsensusId{ids[0]},
			want: big.NewInt(1),
		},
		{
			ids:  []ConsensusId{ids[1], ids[2]},
			want: big.NewInt(5),
		},
		{
			ids:  []ConsensusId{ids[1], ids[3], ids[4]},
			want: big.NewInt(11),
		},
	}

	for i, tc := range testcases {
		t.Run(fmt.Sprintln(i), func(t *testing.T) {
			got, err := weightedVoteCount(tc.ids, weight)
			if err != nil {
				t.Errorf("err=%s", err.Error())
			} else {
				if got.Cmp(tc.want) != 0 {
					t.Errorf("want=%s, got=%s", tc.want, got)
				}
			}
		})
	}
}

func TestPassThreshold(t *testing.T) {
	ids := make([]ConsensusId, 5)
	for i := range ids {
		for {
			if key, err := bls.NewSigningKey(); err == nil {
				ids[i] = ConsensusIdFromPubKey(&key.PublicKey)
				break
			}
		}
	}
	scheme := &weightedVoteCountingScheme{
		weight: map[ConsensusId]*big.Int{
			ids[0]: big.NewInt(1),
			ids[1]: big.NewInt(1),
			ids[2]: big.NewInt(1),
			ids[3]: big.NewInt(1),
			ids[4]: big.NewInt(1),
		},
	}

	testcases := []struct {
		ids       []ConsensusId
		threshold *big.Int
		isPassed  bool
	}{
		{ids[:3], big.NewInt(0), true},
		{ids[:3], big.NewInt(1), true},
		{ids[:3], big.NewInt(2), true},
		{ids[:3], big.NewInt(3), true},
		{ids[:3], big.NewInt(4), false},
		{ids[:3], big.NewInt(5), false},
		{ids[:3], big.NewInt(6), false},
	}

	for i, tc := range testcases {
		t.Run(fmt.Sprintln(i), func(t *testing.T) {
			scheme.threshold = tc.threshold
			got, err := scheme.PassThreshold(tc.ids)
			if err != nil {
				t.Errorf("err=%+v", err)
			}
			if got != tc.isPassed {
				t.Errorf("want=%v got=%v", tc.isPassed, got)
			}
		})
	}
}
