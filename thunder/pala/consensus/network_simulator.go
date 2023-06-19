package consensus

import (
	"sync"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/pala/msggroup"
	"github.com/ethereum/go-ethereum/thunder/pala/network"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
)

// NetworkSimulator can simulate delaying messages or breaking connections.
type NetworkSimulator struct {
	haveCalledConnect bool
	rules             []*NetworkSimulatorRule
	baseDelay         network.Delay
	stopChan          chan interface{}
	wg                sync.WaitGroup
}

// First matched.
type NetworkSimulatorRule struct {
	// nil means "match all"
	From []ConsensusId
	// nil means "match all"
	To []ConsensusId
	// TypeNil means "match all"
	Type MessageId
	// BlockSn{0,0} means "match all"
	Sn     blockchain.BlockSn
	Action *network.FilterAction
}

//--------------------------------------------------------------------

func NewNetworkSimulator() *NetworkSimulator {
	return &NetworkSimulator{
		stopChan: make(chan interface{}),
	}
}

func (n *NetworkSimulator) SetBaseDelay(delay network.Delay) error {
	n.baseDelay = delay
	return nil
}

// Connect creates a connection from `fromHost` to `toHost`. Note that it doesn't check whether
// there is already a connection between them. If there is a duplicated connection, networkManager
// should drop the old one.
func (n *NetworkSimulator) Connect(fromHost *network.Host, toHost *network.Host) error {
	return n.ConnectWithDelay(fromHost, toHost, network.Delay{})

}

// ConnectWithDelay is the same as Connect() except it provides an extra argument `delay`.
func (n *NetworkSimulator) ConnectWithDelay(
	fromHost *network.Host, toHost *network.Host, delay network.Delay) error {
	n.haveCalledConnect = true
	delay = n.baseDelay.Add(delay)
	network.FakeConnectWithFilter(fromHost, toHost, &n.wg, n.stopChan, delay,
		func(from ConsensusId, to ConsensusId, typ uint8, blob []byte) *network.FilterAction {
			unmarshaller := &blockchain.DataUnmarshallerFake{}
			// Apply the first matched rule.
			for _, r := range n.rules {
				if len(r.From) > 0 && !contains(r.From, from) {
					continue
				}
				if len(r.To) > 0 && !contains(r.To, to) {
					continue
				}
				typ := MessageId(typ)
				if r.Type != MessageNil && r.Type != typ {
					continue
				}
				if msggroup.IsConsensusMessage(uint8(typ)) {
					sn := getBlockSn(typ, unmarshaller, blob)
					if !r.Sn.IsNil() && r.Sn != sn {
						continue
					}
				}

				return r.Action
			}
			return nil
		})
	return nil
}

func getBlockSn(typ MessageId, unmarshaller blockchain.DataUnmarshaller, blob []byte,
) blockchain.BlockSn {
	switch typ {
	case MessageBlock:
		value, _, err := unmarshaller.UnmarshalBlock(blob)
		if err != nil {
			debug.Bug("unmarshal err=%s", err)
		}
		return value.GetBlockSn()
	case MessageProposal:
		value, _, err := unmarshaller.UnmarshalProposal(blob)
		if err != nil {
			debug.Bug("unmarshal err=%s", err)
		}
		return value.GetBlockSn()
	case MessageVote:
		value, _, err := unmarshaller.UnmarshalVote(blob)
		if err != nil {
			debug.Bug("unmarshal err=%s", err)
		}
		return value.GetBlockSn()
	case MessageNotarization:
		value, _, err := unmarshaller.UnmarshalNotarization(blob)
		if err != nil {
			debug.Bug("unmarshal err=%s", err)
		}
		return value.GetBlockSn()
	case MessageClockMsg:
		value, _, err := unmarshaller.UnmarshalClockMsg(blob)
		if err != nil {
			debug.Bug("unmarshal err=%s", err)
		}
		return value.GetBlockSn()
	case MessageClockMsgNota:
		value, _, err := unmarshaller.UnmarshalClockMsgNota(blob)
		if err != nil {
			debug.Bug("unmarshal err=%s", err)
		}
		return value.GetBlockSn()
	default:
		debug.Bug("unexpected type %s", typ)
	}
	return blockchain.BlockSn{}
}

func contains(set []ConsensusId, target ConsensusId) bool {
	if len(set) == 0 {
		return false
	}
	for _, s := range set {
		if s == target {
			return true
		}
	}
	return false
}

// AddRule must be called before Connect.
func (n *NetworkSimulator) AddRule(rule NetworkSimulatorRule) {
	if n.haveCalledConnect {
		debug.Bug("must call AddRule() before any call of Connect()")
	}
	n.rules = append(n.rules, &rule)
}

func (n *NetworkSimulator) Stop() {
	close(n.stopChan)
	n.wg.Wait()
}
