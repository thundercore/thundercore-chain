package election

import (
	"encoding/hex"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/ethereum/go-ethereum/rlp"
)

var (
	logger           = lgr.NewLgr("/Election")
	minCommitteeSize = config.NewInt64HardforkConfig(
		"committee.minCommitteeSize",
		"min number of committee members to form a committee")

	// These are the original values
	// auctionStakeThresholdAmount, _ = big.NewInt(0).SetString("500000000000000000000000", 10) // 500000 thunder
	// minBidderStakeAmount, _        = big.NewInt(0).SetString("100000000000000000000000", 10) // 100000 thunder
	// minGasBidPrice, _              = big.NewInt(0).SetString("10000000", 10)                 // 0.01 gella

	// exposed for thundervm unit tests
	AuctionStakeThreshold = config.NewBigIntHardforkConfig(
		"committee.AuctionStakeThreshold",
		"min number of Thunder tokens required to form a committee")
	MinBidderStake = config.NewBigIntHardforkConfig(
		"committee.MinBidderStake",
		"min number of Thunder tokens required for a bidder")
	MinBidPrice = config.NewBigIntHardforkConfig(
		"committee.MinGasBidPrice",
		"minimum gas bid price")

	// hardfork flags
	BurnReward = config.NewBoolHardforkConfig(
		"vault.burnReward",
		"committee rewards are burned if sent to address 0")
	ElectionScheme = config.NewStringHardforkConfig(
		"committee.electionScheme",
		"the committee election scheme in use")
	ClearingGasPriceScheme = config.NewStringHardforkConfig(
		"committee.clearingGasPriceScheme",
		"the committee clearing gas price scheme in use")
	expectedCommSize = config.NewInt64HardforkConfig(
		"committee.expectedCommSize",
		"the expected commSize (the K value of the Top-K scheme), should be larger than minCommitteeSize")
)

// Result holds the outcome of a committee election.
type Result struct {
	Members          []committee.MemberInfo
	ClearingGasPrice *big.Int
}

// ToBytes serializes an election.Result to bytes (uses the RLP trans-coding interfaces)
func (r *Result) ToBytes() []byte {
	buf, err := rlp.EncodeToBytes(r)
	if err != nil {
		debug.Bug("ToBytes error: %s", err)
	}
	return buf
}

// From bytes decodes an RLP encoded buffer into a fully formed election.Result struct.
func (r *Result) FromBytes(buf []byte) error {
	return rlp.DecodeBytes(buf, r)
}

// Elect returns the result of a committee election given stake-in messages.
// The stakes are ordered from old to new which is used as a tiebreaker in the election.
// It is important to the election result to be determinitic so all nodes have the consistent
// election result.
func Elect(stakes []*StakeInfo, freeze func(*StakeInfo) bool, sessionNum int64) *Result {
	logger.Info("elect %d stakes", len(stakes))

	candidates := getCandidates(stakes, sessionNum)
	return elect(candidates, freeze, sessionNum)
}

func ElectR3(stakes []*StakeInfo, freeze func(*StakeInfo) bool, sessionNum int64) *Result {
	logger.Info("elect %d stakes", len(stakes))

	candidates := getCandidates2P5(stakes, sessionNum)
	return elect(candidates, freeze, sessionNum)
}

// getCandidates filters out invalid stakes and returns a list of candidates ordered by
// Stake / GasPrice. The original order of stakes is used as a tiebreaker.
func getCandidates(stakes []*StakeInfo, sessionNum int64) []*StakeInfo {
	candidates := []*StakeInfo{}
	// Since new stake message overwrites old ones, process in reverse order. For each
	// PubVoteKey & StakingAddr, only the last stake message is valid.
	seen := make(map[string]bool)
	for i := len(stakes) - 1; i >= 0; i-- {
		s := stakes[i]
		if s.GasPrice.Sign() <= 0 {
			logger.Warn("gas price <= 0: %v", s.StakingAddr)
			// we don't allow negative or 0 gasprice
			continue
		}
		in := append(s.PubVoteKey.ToBytes(), s.StakingAddr.Bytes()...)
		in = append(in, s.RefundID...)
		k := string(in)
		_, found := seen[k]
		if found {
			// Filter out old StakeInfo with same PubVoteKey & StakingAddr
			logger.Warn("dup candidate: vote key %s staking addr %v refundId %v",
				hex.EncodeToString(s.PubVoteKey.ToBytes()), s.StakingAddr.Hex(),
				hex.EncodeToString(s.RefundID))
			continue
		}
		seen[k] = true
		if s.Stake.Cmp(MinBidderStake.GetValueAtSession(sessionNum)) == -1 {
			// Filter out StakeInfo with less than min bidder stake
			logger.Warn("stake %v too small: %v; min stake=%v", s.Stake, s.StakingAddr,
				MinBidderStake.GetValueAtSession(sessionNum))
			continue
		}
		candidates = append(candidates, s)
	}

	// Sort candidates by Stake / GasPrice in decreasing order.
	// Since candidates are appended above in reversed order, reverse back to original order
	// to use as a tiebreaker. It is important that all nodes generate the same election.result.
	for i, j := 0, len(candidates)-1; i < j; i, j = i+1, j-1 {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	}

	// To avoid division by zero, use equivalent condition:
	// stake[i] / price[i] < stake[j] / price[j] <=> stake[i] * price[j] < stake[j] * price[i]
	sort.SliceStable(candidates, func(i int, j int) bool {
		return big.NewInt(0).Mul(candidates[j].Stake, candidates[i].GasPrice).Cmp(
			big.NewInt(0).Mul(candidates[i].Stake, candidates[j].GasPrice)) == -1

	})

	return candidates
}

// getCandidates filters out invalid stakes and returns a list of candidates ordered by
// Stake. The original order of stakes is used as a tiebreaker.
func getCandidates2P5(stakes []*StakeInfo, sessionNum int64) []*StakeInfo {
	candidates := []*StakeInfo{}
	// Since new stake message overwrites old ones, process in reverse order. For each
	// PubVoteKey & StakingAddr, only the last stake message is valid.
	seen := make(map[string]bool)
	for i := len(stakes) - 1; i >= 0; i-- {
		s := stakes[i]
		if s.GasPrice.Sign() <= 0 {
			logger.Warn("gas price <= 0: %v", s.StakingAddr)
			// we don't allow negative or 0 gasprice
			continue
		}
		in := append(s.PubVoteKey.ToBytes(), s.StakingAddr.Bytes()...)
		in = append(in, s.RefundID...)
		k := string(in)
		_, found := seen[k]
		if found {
			// Filter out old StakeInfo with same PubVoteKey & StakingAddr
			logger.Warn("dup candidate: vote key %s staking addr %v refundId %v",
				hex.EncodeToString(s.PubVoteKey.ToBytes()), s.StakingAddr.Hex(),
				hex.EncodeToString(s.RefundID))
			continue
		}
		seen[k] = true
		if s.Stake.Cmp(MinBidderStake.GetValueAtSession(sessionNum)) == -1 {
			// Filter out StakeInfo with less than min bidder stake
			logger.Warn("stake %v too small: %v; min stake=%v", s.Stake, s.StakingAddr,
				MinBidderStake.GetValueAtSession(sessionNum))
			continue
		}
		candidates = append(candidates, s)
	}

	// Sort candidates by Stake in decreasing order.
	// Since candidates are appended above in reversed order, reverse back to original order
	// to use as a tiebreaker. It is important that all nodes generate the same election.result.
	for i, j := 0, len(candidates)-1; i < j; i, j = i+1, j-1 {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	}

	// sort candidates by staked amount
	sort.SliceStable(candidates, func(i int, j int) bool {
		return candidates[i].Stake.Cmp(candidates[j].Stake) == 1
	})

	return candidates
}

func logStakeInfos(logger *lgr.Lgr, candidates []*StakeInfo) {
	for i, c := range candidates {
		logger.Info("    [%d]: votekey:%s... reward:%s... stake:%s eth, gas:%s", i,
			hex.EncodeToString(c.PubVoteKey.ToBytes())[:16],
			c.Coinbase.Hex()[:16], utils.WeiToEther(c.Stake).String(), c.GasPrice.String())
	}
}

func logMemberInfos(logger *lgr.Lgr, members []committee.MemberInfo) {
	for i, m := range members {
		logger.Info("    [%d]: votekey:%s... reward:%s... stake:%s eth, gas:%s", i,
			hex.EncodeToString(m.PubVoteKey.ToBytes())[:16],
			m.Coinbase.Hex()[:16], utils.WeiToEther(m.Stake).String(), m.GasPrice.String())
	}
}

// elect returns the election result given a valid and sorted list of candidates. If the list of
// candidates is not able to form a committee, elect returns nil.
func elect(candidates []*StakeInfo, freeze func(*StakeInfo) bool, sessionNum int64) *Result {
	result := &Result{
		Members:          []committee.MemberInfo{},
		ClearingGasPrice: big.NewInt(0),
	}
	logger.Info("elect: having %d candidates, in %d", len(candidates), sessionNum)
	logStakeInfos(logger, candidates)
	// for tracking clearing gas
	currentMaxStake := big.NewInt(0)
	// Keep track of stake in the current auction
	auctionStake := big.NewInt(0)
	// Since PubVoteKey should be unique in a committee, we track seen PubVoteKeys to filter out
	// candidates with the same PubVoteKey as a previous committee member. Candidates are already
	// sorted by stake so taking the first occurrence of the PubVoteKey is akin to taking the
	// largest one with the greatest bid.
	seen := make(map[string]bool)
	for _, c := range candidates {
		k := string(c.PubVoteKey.ToBytes())
		_, found := seen[k]
		if found {
			// consider changing criterion for picking candidates with dup PubVoteKeys, see THUNDER-519
			logger.Warn("dup vote key: %s", k)
			continue
		}
		seen[k] = true

		if !freeze(c) {
			logger.Warn("freeze failure: %v", c.StakingAddr)
			continue
		}

		// Add the current candidate to election.result
		result.Members = append(result.Members, *c.ToMemberInfo())
		switch ClearingGasPriceScheme.GetValueAtSession(sessionNum) {
		case "CandidatesMax":
			// Set the ClearingGasPrice to the maximum bid
			if result.ClearingGasPrice.Cmp(c.GasPrice) == -1 {
				result.ClearingGasPrice.Set(c.GasPrice)
			}
		case "Top1CandidatesDecision":
			// Set the ClearingGasPrice to the top 1 candidates bid
			if currentMaxStake.Cmp(c.Stake) == 0 && result.ClearingGasPrice.Cmp(c.GasPrice) == -1 {
				result.ClearingGasPrice.Set(c.GasPrice)
			} else if currentMaxStake.Cmp(c.Stake) == -1 {
				result.ClearingGasPrice.Set(c.GasPrice)
				currentMaxStake = c.Stake
			}
		}

		switch ElectionScheme.GetValueAtSession(sessionNum) {
		case "TotalStakeThreshold":
			// Return election result when min auction stake is reached.
			auctionStake = auctionStake.Add(auctionStake, c.Stake)
			if auctionStake.Cmp(AuctionStakeThreshold.GetValueAtSession(sessionNum)) >= 0 &&
				int64(len(result.Members)) >= minCommitteeSize.GetValueAtSession(sessionNum) {

				logger.Info("TotalStakeThreshold returns %v committees ClearingGasPrice:%v",
					len(result.Members), result.ClearingGasPrice.Int64())
				logMemberInfos(logger, result.Members)

				return result
			}
		case "TopKCandidates":
			if int64(len(result.Members)) == expectedCommSize.GetValueAtSession(sessionNum) {
				logger.Info("TopKCandidates returns %v committees ClearingGasPrice:%v",
					len(result.Members), result.ClearingGasPrice.Int64())
				logMemberInfos(logger, result.Members)

				return result
			}
		}

		if int64(len(result.Members)) >= committee.MaxCommSize {
			// The committee size should not be more than max commitee size.
			logger.Warn("committee of %d members is too large: limit %d",
				len(result.Members), committee.MaxCommSize)
			break
		}
	}

	if ElectionScheme.GetValueAtSession(sessionNum) == "TopKCandidates" &&
		int64(len(result.Members)) >= minCommitteeSize.GetValueAtSession(sessionNum) {
		logger.Info("elect returns %v committees ClearingGasPrice:%v",
			len(result.Members), result.ClearingGasPrice.Int64())
		logMemberInfos(logger, result.Members)

		return result
	}

	logger.Warn("Elect failed: total stake = %d, members = %d", auctionStake, len(result.Members))
	return nil
}
