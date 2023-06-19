package metrics

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"golang.org/x/xerrors"
)

var logger = lgr.NewLgr("/metrics")

func AddCounter(c Counter, v int64) {
	if c != nil {
		c.Add(v)
	}
}

func IncCounter(c Counter) {
	if c != nil {
		c.Inc()
	}
}

func AddGauge(g Gauge, v int64) {
	if g != nil {
		g.Add(v)
	}
}

func SetGauge(g Gauge, v int64) {
	if g != nil {
		g.Set(v)
	}
}

func IncGauge(g Gauge) {
	if g != nil {
		g.Inc()
	}
}

func ObserveHistogram(h Histogram, v float64) {
	if h != nil {
		h.Observe(v)
	}
}

// PalaMetrics is a set of metrics used by Pala
// You can freely add new metrics to the struct with no additional changes
// All bulk operations are handled using reflection using helper methods below
type PalaMetrics struct {
	// The tag `role` specifies whether to show the metric according to the role, for example:
	// - "": always show the metric
	// - "voter": only show the metric if role is a voter
	// - "proposer|voter": show the metric if role is voter or proposer

	// Mediator
	NumFinalized        Counter   `level:"INFO" desc:"number of blocks finalized"`
	NumNotarized        Counter   `level:"INFO" desc:"number of blocks notarized"`
	FinalizationTime    Histogram `level:"INFO" desc:"histogram of time between finalized blocks"`
	NotarizationTime    Histogram `level:"INFO" desc:"histogram of time between notarized blocks"`
	Timeout             Counter   `level:"INFO" desc:"number of timeouts"`
	ForceRotateProposer Counter   `level:"INFO" desc:"number of requests to force rotate the primary proposer"`
	LocalEpoch          Gauge     `level:"INFO" desc:"local epoch"`
	LocalSession        Gauge     `level:"INFO" desc:"local session"`
	FastPathHeight      Gauge     `level:"INFO" desc:"Number of last notarized fast-path block"`
	BadMessageCode      Counter   `level:"INFO" desc:"Number of messages with bad code"`

	// Consensus
	NumVotesInNotarizationInLastFinalizedBlock Histogram `level:"INFO" desc:"number of votes in the last notarization"`

	// Network
	Disconnects                          Counter `level:"INFO" desc:"Number of disconnects across all conn"`
	HandshakesGood                       Counter `level:"INFO" desc:"Number of good handshakes across all conn"`
	HandshakesSent                       Counter `level:"INFO" desc:"Number of handshakes sent across all conn"`
	ProtocolNameMismatches               Counter `level:"INFO" desc:"Number of protocol name mismatches in handshakes"`
	ProtocolVersionMismatches            Counter `level:"INFO" desc:"Number of protocol version mismatches in handshakes"`
	TotalHandshakesBad                   Counter `level:"INFO" desc:"Number of handshakes failed"`
	Proposer_ChallengeResponseInvalid    Counter `level:"INFO" desc:"Number of wrong responses to challenges" role:"proposer"`
	Proposer_ChallengeResponsesBadDecode Counter `level:"INFO" desc:"Number of challenge responses which failed to deserialize" role:"proposer"`
	Proposer_ChallengeResponsesSent      Counter `level:"INFO" desc:"Number of challenges successfully responded" role:"proposer"`
	Proposer_ChallengeResponsesValid     Counter `level:"INFO" desc:"Number of successful responses to challenges" role:"proposer"`
	Voter_ChallengeResponseInvalid       Counter `level:"INFO" desc:"Number of wrong responses to challenges" role:"voter"`
	Voter_ChallengeResponsesBadDecode    Counter `level:"INFO" desc:"Number of challenge responses which failed to deserialize" role:"voter"`
	Voter_ChallengeResponsesSent         Counter `level:"INFO" desc:"Number of challenges successfully responded" role:"voter"`
	Voter_ChallengeResponsesValid        Counter `level:"INFO" desc:"Number of successful responses to challenges" role:"voter"`

	// Proposer
	Proposer_ProposalsCreated      Counter   `level:"INFO" desc:"Number of created proposals" role:"proposer"`
	Proposer_ProposalsSent         Counter   `level:"INFO" desc:"Number of proposals sent for notarization" role:"proposer"`
	Proposer_VoteDecodeBad         Counter   `level:"INFO" desc:"Number of deserialization errors in vote messages" role:"proposer"`
	Proposer_VoteSigBad            Counter   `level:"INFO" desc:"Number of votes with bad sign" role:"proposer"`
	Proposer_VotesBad              Counter   `level:"INFO" desc:"Number of bad votes received across all proposals and committee members" role:"proposer"`
	Proposer_VotesGood             Counter   `level:"INFO" desc:"Number of good votes received across all proposals and committee members" role:"proposer"`
	Proposer_ProposalResponseTime  Histogram `level:"INFO" desc:"Time between proposal send and response." role:"proposer"`
	Proposer_ProposalNotarizedTime Histogram `level:"INFO" desc:"Time between proposal send and being notarized." role:"proposer"`
	Proposer_ProposalFinalizedTime Histogram `level:"INFO" desc:"Time between proposal send and being finalized." role:"proposer"`
	Proposer_NotarizationsSent     Counter   `level:"INFO" desc:"Numbers of notarized proposals sent" role:"proposer"`
	Proposer_CommitteeRound        Counter   `level:"INFO" desc:"Successful rounds of committee switched" role:"proposer"`
	Proposer_CommitteeSize         Gauge     `level:"INFO" desc:"Size of committee" role:"proposer"`
	Proposer_CommitteeStake        Gauge     `level:"INFO" desc:"Stake(thunder) of committee" role:"proposer"`
	Proposer_ActiveCommittees      Gauge     `level:"INFO" desc:"Number of active committees" role:"proposer"`

	// Blockmaker
	Proposer_Blockmaker_E2EBlockMakingTimeMs Histogram `level:"INFO" desc:"Time taken to create one block" role:"proposer"`
	Proposer_Blockmaker_GasUsedPerBlock      Gauge     `level:"INFO" desc:"Gas used in current block" role:"proposer"`
	Proposer_Blockmaker_GetPendingTxnsTimeMs Histogram `level:"INFO" desc:"Time taken to get pending txs from pool" role:"proposer"`
	Proposer_Blockmaker_MaxGas               Gauge     `level:"INFO" desc:"Max gas limit per block" role:"proposer"`
	Proposer_Blockmaker_MinGasPricePerBlock  Gauge     `level:"INFO" desc:"Minimum gas price in current block" role:"proposer"`
	Proposer_Blockmaker_TimePerBlockInSec    Gauge     `level:"INFO" desc:"Time between two blocks" role:"proposer"`
	Proposer_Blockmaker_TxPerBlock           Gauge     `level:"INFO" desc:"Number of transactions in current block" role:"proposer"`

	// TxPool
	Proposer_TxPool_NumNonProcessableTxs Gauge `level:"INFO" desc:"Number of non-processable txs in pool" role:"proposer"`
	Proposer_TxPool_NumProcessableTxs    Gauge `level:"INFO" desc:"Number of processable txs in pool" role:"proposer"`
	Proposer_TxPool_NumTotalTxs          Gauge `level:"INFO" desc:"Number of all txs in pool" role:"proposer"`
	Proposer_TxPool_TotalAvailableSlots  Gauge `level:"INFO" desc:"Number of slots (executable or not) available" role:"proposer"`
	Proposer_TxPool_TxsBad               Gauge `level:"INFO" desc:"Number of txs failed to be added to pool" role:"proposer"`

	// Voter
	Voter_ProposalsGood     Counter `level:"INFO" desc:"Number of good proposal received" role:"voter"`
	Voter_ProposalsBad      Counter `level:"INFO" desc:"Number of proposal deserialization errors" role:"voter"`
	Voter_ProposalsDup      Counter `level:"INFO" desc:"Number of duplicate proposals received" role:"voter"`
	Voter_ProposalsVoted    Counter `level:"INFO" desc:"Number of proposals voted" role:"voter"`
	Voter_NotarizationsBad  Counter `level:"INFO" desc:"Number of notarization deserialization errors" role:"voter"`
	Voter_NotarizationsDup  Counter `level:"INFO" desc:"Number of duplicate notarization received" role:"voter"`
	Voter_NotarizationsGood Counter `level:"INFO" desc:"Number of good notarization received" role:"voter"`
	Voter_ActiveCommRounds  Counter `level:"INFO" desc:"Number of rounds being an active committee" role:"voter"`
}

func GetMetricRole(f reflect.StructField) string {
	return f.Tag.Get("role")
}

// GetMetricsFilter compares the given 'roles' with every metric's role tag
// It returns a set of metrics that the 'roles' has access
func (pm *PalaMetrics) GetMetricsFilter(roles []string) map[string]bool {
	structType := reflect.TypeOf(pm).Elem()
	structValue := reflect.ValueOf(pm).Elem()
	numFields := structType.NumField()
	filter := make(map[string]bool)
	for i := 0; i < numFields; i++ {
		name := structValue.Type().Field(i).Name
		tagRole := GetMetricRole(structValue.Type().Field(i))
		if len(tagRole) == 0 {
			filter[name] = true
			continue
		}
		validRoles := strings.Split(tagRole, "|")
		for _, r := range roles {
			if utils.SliceContains(validRoles, r) {
				filter[name] = true
				break
			}
		}
	}
	return filter
}

// GetInvMetricsFilter returns the inverted filter of GetMetricsFilter
func (pm *PalaMetrics) GetInvMetricsFilter(roles []string) map[string]bool {
	filter := pm.GetMetricsFilter(roles)
	structType := reflect.TypeOf(pm).Elem()
	structValue := reflect.ValueOf(pm).Elem()
	numFields := structType.NumField()
	invFilter := make(map[string]bool)
	for i := 0; i < numFields; i++ {
		name := structValue.Type().Field(i).Name
		if filter[name] {
			continue
		}
		invFilter[name] = true
	}
	return invFilter
}

func NewPalaMetricsWithWriter(logId string, enablePrometheus bool) (PalaMetrics, MetricsWriter) {
	w := NewFileMetricsWriter(logId)
	w.open()
	r := PalaMetrics{}
	populateMetricsUsingReflection(w, &r, "Thunder", enablePrometheus)
	return r, w
}

func NewPalaMetrics(logId string, enablePrometheus bool) PalaMetrics {
	r := PalaMetrics{}
	populateMetricsUsingReflection(nil, &r, "Thunder", enablePrometheus)
	return r
}

func PrintMetricsUsingReflection(id string, current *PalaMetrics, previous *PalaMetrics) (string, error) {
	structType := reflect.TypeOf(current).Elem()
	structValue := reflect.ValueOf(current).Elem()
	numFields := structType.NumField()

	var b strings.Builder

	for i := 0; i < numFields; i++ {
		v := structValue.Field(i).Interface()
		if v == nil {
			continue
		}

		f := structType.Field(i)
		metricName := f.Name

		b.WriteString(metricName)
		b.WriteString(":\t")
		switch m := v.(type) {
		case Counter:
			b.WriteString(fmt.Sprintf("%d\n", m.Get()))
		case Gauge:
			b.WriteString(fmt.Sprintf("%d\n", m.Get()))
		case Histogram:
			b.WriteString(fmt.Sprintf("count: %d mean: %f variance: %f\n",
				m.SampleCount(), m.SampleAvg(), m.SampleVariance()))
		default:
			logger.Warn("unrecognized metrics object")
		}
	}

	// early return if there is nothing to output
	if b.String() == "" {
		return "", xerrors.New("no metrics")
	}

	var b2 strings.Builder
	if previous != nil {
		prevValue := reflect.ValueOf(previous).Elem()

		for i := 0; i < numFields; i++ {
			v := structValue.Field(i).Interface()
			pv := prevValue.Field(i).Interface()
			if v == nil || pv == nil {
				continue
			}

			f := structType.Field(i)
			metricName := f.Name
			b2.WriteString(metricName)
			b2.WriteString(":\t")
			switch m := v.(type) {
			case Counter:
				diff := m.Difference(pv.(Counter))
				b2.WriteString(fmt.Sprintf("%d\n", diff.Get()))
			case Gauge:
				diff := m.Difference(pv.(Gauge))
				b2.WriteString(fmt.Sprintf("%d\n", diff.Get()))
			case Histogram:
				diff := m.Difference(pv.(Histogram))
				b2.WriteString(fmt.Sprintf("count: %d mean: %f variance: %f\n",
					diff.SampleCount(), diff.SampleAvg(), diff.SampleVariance()))
			default:
				logger.Warn("unrecognized metrics object")
			}
		}
	}

	return fmt.Sprintf("\n[%s] TOTAL METRICS OUTPUT:\n%s\nMETRICS OUTPUT FROM CURRENT EPOCH:\n%s",
		id, b.String(), b2.String()), nil

}

func copyMetricsUsingReflection(current *PalaMetrics) *PalaMetrics {
	r := &PalaMetrics{}

	structType := reflect.TypeOf(current).Elem()
	structValue := reflect.ValueOf(current).Elem()
	numFields := structType.NumField()
	rValue := reflect.ValueOf(r).Elem()

	for i := 0; i < numFields; i++ {
		f := structType.Field(i)
		metricName := f.Name
		var b strings.Builder
		b.WriteString(metricName)
		b.WriteString(":")
		switch m := structValue.Field(i).Interface().(type) {
		case Counter:
			rValue.Field(i).Set(reflect.ValueOf(m.Copy()))
		case Gauge:
			rValue.Field(i).Set(reflect.ValueOf(m.Copy()))
		case Histogram:
			rValue.Field(i).Set(reflect.ValueOf(m.Copy()))
		default:
			logger.Warn("unrecognized metrics object")
		}
	}
	return r
}

// AdvanceLocalEpoch advances the local epoch and returns a copy of the metrics at this time
func (pm *PalaMetrics) AdvanceLocalEpoch(session, epoch uint32) *PalaMetrics {
	if pm.LocalEpoch == nil {
		return nil
	}
	r := copyMetricsUsingReflection(pm)
	pm.LocalSession.Set(int64(session))
	pm.LocalEpoch.Set(int64(epoch))
	return r
}
