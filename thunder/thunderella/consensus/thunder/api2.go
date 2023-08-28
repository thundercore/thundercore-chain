package thunder

import (
	"fmt"

	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chain"
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	"github.com/ethereum/go-ethereum/thunder/thunderella/thundervm/reward"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
)

type PrivateApi struct {
	rpcDelegate RpcDelegate
}

func (a *PrivateApi) GetMetrics() (interface{}, error) {
	return a.rpcDelegate.GetMetrics()
}

func (a *PrivateApi) GetTxPoolStatus() (interface{}, error) {
	return a.rpcDelegate.GetTxPoolStatus()
}

func (a *PrivateApi) GetCommInfo(session uint32) (interface{}, error) {
	return a.rpcDelegate.GetCommInfo(session)
}

func (a *PrivateApi) SetHead(number uint64) error {
	return a.rpcDelegate.SetHead(number)
}

func (a *PrivateApi) IsReadyForService(minHeightDiff uint64) (interface{}, error) {
	return a.rpcDelegate.IsReadyForService(minHeightDiff)
}

func (a *PrivateApi) TraceTxRoute(waitingSeconds uint8) (interface{}, error) {
	return a.rpcDelegate.TraceTxRoute(waitingSeconds)
}

//------------------------------------------------------------------------------

type PublicApi struct {
	rpcDelegate RpcDelegate
}

// Viewblock uses this.
func (a *PublicApi) GetConsensusNodesInfo(seq chain.Seq) (*committee.CommInfo, error) {
	r, err := a.rpcDelegate.GetCommInfoByNumber(int64(seq))
	if err != nil {
		return nil, err
	}
	commInfo, ok := r.(*committee.CommInfo)
	if !ok {
		return nil, fmt.Errorf("Failed to get consensus nodes")
	}
	return commInfo, nil
}

// Viewblock uses this.
func (a *PublicApi) GetRewardInfo(seq chain.Seq) (*reward.Results, error) {
	r, err := a.rpcDelegate.GetReward(int64(seq))
	if err != nil {
		return nil, err
	}
	reward, ok := r.(*reward.Results)
	if !ok {
		return nil, fmt.Errorf("Failed to get reward")
	}
	return reward, nil
}

// Helpful API for developers.
func (a *PublicApi) GetBlockSnByNumber(n uint64) (interface{}, error) {
	return a.rpcDelegate.GetBlockSnByNumber(n)
}

// Helpful API for developers.
func (a *PublicApi) GetNumberByBlockSn(session, epoch, s uint32) (interface{}, error) {
	return a.rpcDelegate.GetNumberByBlockSn(session, epoch, s)
}

// GetBlockInfo contains blocksn, committee info, and notarazions.
func (a *PublicApi) GetBlockInfo(bn rpc.BlockNumber) (interface{}, error) {
	return a.rpcDelegate.GetBlockInfo(bn)
}

func (a *PublicApi) GetTtTransfersByBlockNumber(number hexutil.Uint64) (interface{}, error) {
	return a.rpcDelegate.GetTtTransfersByBlockNumber(uint64(number))
}

func (a *PublicApi) GetPalaMetaForSnapshot(bn rpc.BlockNumber) (interface{}, error) {
	return a.rpcDelegate.GetPalaMetaForSnapshot(bn)
}

func (a *PublicApi) GetTrieStateForSnapshot(keys []common.Hash) (interface{}, error) {
	return a.rpcDelegate.GetTrieStateForSnapshot(keys)
}

func (a *PublicApi) GetTtBlockForSnapshot(number uint64) (interface{}, error) {
	return a.rpcDelegate.GetTtBlockForSnapshot(number)
}

func (a *PublicApi) GetTotalSupply(bn rpc.BlockNumber) (interface{}, error) {
	return a.rpcDelegate.GetTotalSupply(bn)
}

func (a *PublicApi) GetTotalInflation(bn rpc.BlockNumber) (interface{}, error) {
	return a.rpcDelegate.GetTotalInflation(bn)
}

func (a *PublicApi) GetTotalFeeBurned(bn rpc.BlockNumber) (interface{}, error) {
	return a.rpcDelegate.GetTotalFeeBurned(bn)
}

// GetSessionStatus return the start block, stop block, end block and K value in the given session
func (a *PublicApi) GetSessionStatus(session uint32) (interface{}, error) {
	return a.rpcDelegate.GetSessionStatus(session)
}

func (a *PublicApi) GetBidStatus(bn rpc.BlockNumber) (interface{}, error) {
	return a.rpcDelegate.GetBidStatus(bn)
}

func (a *PublicApi) GetStatus() (interface{}, error) {
	return a.rpcDelegate.GetStatus()
}

func (a *PublicApi) TraceTransaction(txHash common.Hash) (interface{}, error) {
	return a.rpcDelegate.TraceTransaction(txHash)
}
