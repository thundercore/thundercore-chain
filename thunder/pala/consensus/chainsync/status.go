package chainsync

import (
	"fmt"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"
)

// Status represents the node's main states. Nodes will exchange their
// status and request verifiable data when they are behind.
type Status struct {
	// The last block's sequence number of the freshest notarized chain.
	FncBlockSn  blockchain.BlockSn
	Epoch       blockchain.Epoch
	NodeVersion string
	BlockHeight uint64
}

func MarshalStatus(s Status) []byte {
	var out [][]byte
	out = append(out, s.FncBlockSn.ToBytes())
	out = append(out, s.Epoch.ToBytes())
	out = append(out, utils.StringToBytes(s.NodeVersion))
	out = append(out, utils.Uint64ToBytes(s.BlockHeight))
	return utils.ConcatCopyPreAllocate(out)
}

func UnmarshalStatus(bytes []byte) (Status, error) {
	s := Status{}
	var err error
	s.FncBlockSn, bytes, err = blockchain.NewBlockSnFromBytes(bytes)
	if err != nil {
		return Status{}, err
	}
	if s.Epoch, bytes, err = blockchain.NewEpochFromBytes(bytes); err != nil {
		return Status{}, err
	}
	// forward compatibility
	if len(bytes) == 0 {
		return s, nil
	}
	if s.NodeVersion, bytes, err = utils.BytesToString(bytes); err != nil {
		return Status{}, err
	}
	if s.BlockHeight, _, err = utils.BytesToUint64(bytes); err != nil {
		return Status{}, err
	}
	return s, nil
}

func NewStatus(session uint32, epoch uint32, s uint32, nodeVersion string, height uint64) Status {
	sn := blockchain.NewBlockSn(session, epoch, s)
	return Status{sn, sn.Epoch, nodeVersion, height}
}

func (s Status) isBehind(other Status) bool {
	if s.Epoch.Compare(other.Epoch) < 0 {
		return true
	}
	return s.FncBlockSn.Compare(other.FncBlockSn) < 0
}

func (s Status) String() string {
	return fmt.Sprintf("[%s %s %s %d]", s.Epoch, s.FncBlockSn, s.NodeVersion, s.BlockHeight)
}
