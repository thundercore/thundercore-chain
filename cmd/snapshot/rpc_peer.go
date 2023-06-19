package main

import (
	"context"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
)

func NewRpcPeer(rpc string, i int) (*RpcPeer, error) {
	client, err := ethclient.Dial(rpc)
	if err != nil {
		return nil, err
	}
	return &RpcPeer{
		id:        fmt.Sprintf("%s #%d", rpc, i),
		rpc:       rpc,
		client:    client,
		available: true,
	}, nil
}

type RpcPeer struct {
	id        string
	rpc       string
	client    *ethclient.Client
	available bool

	mu sync.RWMutex
}

func (peer *RpcPeer) Close() {
	peer.client.Close()
}

func (peer *RpcPeer) Id() string {
	return peer.id
}

func (peer *RpcPeer) Disable() {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	peer.available = false
}

func (peer *RpcPeer) Enable() {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	peer.available = true
}

func (peer *RpcPeer) Available() bool {
	peer.mu.RLock()
	defer peer.mu.RUnlock()
	return peer.available
}

func (peer *RpcPeer) GetPalaMeta() (map[string][]byte, error) {
	result := make(map[string][]byte)
	err := peer.client.CallContext(context.TODO(), &result, "thunder_getPalaMetaForSnapshot")
	return result, err
}

func (peer *RpcPeer) GetBlockByNumber(number *big.Int) (*types.Block, error) {
	return peer.client.BlockByNumber(context.TODO(), number)
}

func (peer *RpcPeer) GetTtBlock(blockNum *big.Int) (*blockchain.TtBlockForSnapshot, error) {
	ttBlock := blockchain.TtBlockForSnapshot{}
	err := peer.client.CallContext(context.TODO(), &ttBlock, "thunder_getTtBlockForSnapshot", blockNum.Uint64())
	return &ttBlock, err
}

func (peer *RpcPeer) BatchGetTtBlocks(blocks []*big.Int) (ret []*blockchain.TtBlockForSnapshot, err error) {
	reqs := make([]rpc.BatchElem, len(blocks))
	for i, block := range blocks {
		reqs[i] = rpc.BatchElem{
			Method: "thunder_getTtBlockForSnapshot",
			Args:   []interface{}{block.Uint64()},
			Result: &blockchain.TtBlockForSnapshot{},
		}
	}

	err = peer.client.BatchCallContext(context.TODO(), reqs)
	if err != nil {
		return
	}

	for i, req := range reqs {
		if req.Error != nil {
			return ret, req.Error
		}

		full, ok := req.Result.(*blockchain.TtBlockForSnapshot)
		if !ok {
			return ret, fmt.Errorf("failed to convert TtBlockForSnapshot")
		}
		num := blocks[i].Uint64()
		full.BlockNumber = &num
		ret = append(ret, full)
	}
	return
}

func (peer *RpcPeer) GetTrieState(keys []common.Hash) ([]trie.SyncResult, error) {
	result := make([]trie.SyncResult, len(keys))
	err := peer.client.CallContext(context.TODO(), &result, "thunder_getTrieStateForSnapshot", keys)
	if err != nil {
		return []trie.SyncResult{}, err
	}
	return result, err
}
