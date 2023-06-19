package consensus

import "github.com/ethereum/go-ethereum/thunder/pala/blockchain"

type RoleString string

type TxRoutingConfig struct {
	Ids []ConsensusId
}

// TxRouterImpl implement the txrouter interface required by TxDistributor
type TxRouterImpl struct {
	role   RoleAssigner
	config *TxRoutingConfig
}

func NewTxRouter(role RoleAssigner, config *TxRoutingConfig) *TxRouterImpl {
	return &TxRouterImpl{
		role:   role,
		config: config,
	}
}

// ShouldSend defines the route of transactions in txservice.TxDistributor.
// The default rule is very simple: fullnodes to bootnodes, bootnodes to proposers.
// It's rely on that a transaction only need to propagate
// via thunder wire protocol connected peers to get to the proposers.
func (t *TxRouterImpl) ShouldSend(verifiedId ConsensusId, session blockchain.Session) bool {
	if t.config != nil {
		for _, target := range t.config.Ids {
			if verifiedId == target {
				return true
			}
		}

		return false
	}

	// fullnode -> bootnode
	if !t.role.IsBootnode(UseMyId) && !IsConsensusNode(t.role, UseMyId, session) &&
		t.role.IsBootnode(verifiedId) {
		return true
	}

	// bootnode -> proposer
	if t.role.IsBootnode(UseMyId) && t.role.IsProposer(verifiedId, session) {
		return true
	}

	return false
}
