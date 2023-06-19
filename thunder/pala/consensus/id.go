package consensus

import (
	"github.com/ethereum/go-ethereum/thunder/pala/types"
)

type ConsensusId = types.ConsensusId

var ConsensusIds = types.ConsensusIds

var MakeConsensusIds = types.MakeConsensusIds

var Id = types.ConsensusIdFromPubKey

var IdWithRandomPostfix = types.ConsensusIdWithRandomPostfix
