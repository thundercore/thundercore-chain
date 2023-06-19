package main

import (
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
)

func NewSyncGroupByConfig(config *SnapshotConfig) (*PeerGroup, error) {
	peers, err := newPeers(config)
	if err != nil {
		return nil, err
	}
	return NewSyncGroup(peers), nil
}

func NewSyncGroup(peers []SyncPeer) *PeerGroup {
	ch := make(chan SyncPeer, MAX_CONNECTION)

	for _, peer := range peers {
		select {
		case ch <- peer:
			fmt.Printf("Init peer: %s\n", peer.Id())
		default:
			panic("failed to init peer")
		}
	}

	return &PeerGroup{
		peers:  peers,
		ch:     ch,
		signal: make(chan os.Signal, 1),
	}
}

func newPeers(config *SnapshotConfig) ([]SyncPeer, error) {
	var err error
	peers := []SyncPeer{}
	for _, rpc := range config.RpcUrls {
		num := config.Concurrency

		if strings.Contains(rpc, "=") {
			items := strings.Split(rpc, "=")
			rpc = items[0]
			num, err = strconv.Atoi(items[1])
			if err != nil {
				return peers, err
			}
		}

		for i := 0; i < num; i++ {
			peer, err := NewRpcPeer(rpc, i)
			if err != nil {
				return peers, err
			}
			peers = append(peers, peer)
		}
	}

	return peers, nil
}

type PeerGroup struct {
	peers  []SyncPeer
	ch     chan SyncPeer
	signal chan os.Signal
	mu     sync.Mutex
}

func (pg *PeerGroup) reloadConfig(config *SnapshotConfig) error {
	newPeers, err := newPeers(config)
	if err != nil {
		return err
	}

	pg.mu.Lock()
	defer pg.mu.Unlock()

	for _, peer := range pg.peers {
		peer.Disable()
	}

	for _, peer := range newPeers {
		pg.ch <- peer
	}

	pg.peers = newPeers

	return nil
}

func (pg *PeerGroup) Close() {
	for _, peer := range pg.peers {
		peer.Close()
	}
	close(pg.ch)
}

func (pg *PeerGroup) acquirePeer() SyncPeer {
	var peer SyncPeer
	for peer = range pg.ch {
		if peer.Available() {
			break
		}
	}
	return peer
}

func (pg *PeerGroup) releasePeer(peer SyncPeer) {
	if !peer.Available() {
		fmt.Printf("Drop disabled peer %s\n", peer.Id())
		return
	}

	select {
	case pg.ch <- peer:
	default:
		panic("failed to release peer")
	}
}

func (pg *PeerGroup) timeoutPeer(peer SyncPeer) {
	if !peer.Available() {
		fmt.Printf("Drop disabled peer %s\n", peer.Id())
		return
	}

	f := func() {
		pg.releasePeer(peer)
	}

	fmt.Printf("Timeout peer %s for 30s\n", peer.Id())
	time.AfterFunc(30*time.Second, f)
}

type peerHead struct {
	peer  SyncPeer
	block *types.Block
}

func (pg *PeerGroup) GetSlowestPeer() (SyncPeer, error) {
	var ret *peerHead

	for _, peer := range pg.peers {
		block, err := peer.GetBlockByNumber(nil)
		if err != nil {
			continue
		}
		fmt.Printf("Peer: %s, head block: %v\n", peer.Id(), block.NumberU64())

		if ret == nil {
			ret = &peerHead{
				peer:  peer,
				block: block,
			}
		} else if ret.block.Number().Cmp(block.Number()) > 0 {
			// ret.number > block.number
			ret = &peerHead{
				peer:  peer,
				block: block,
			}
		}
	}

	if ret == nil {
		panic("failed to get slowest peer!")
	}

	fmt.Printf("Slowest peer: %s, block: %v\n", ret.peer.Id(), ret.block.NumberU64())
	return ret.peer, nil
}

func (pg *PeerGroup) GetPalaMeta() (ret map[string][]byte, err error) {
	for retry := 0; retry < RETRY_MAX; retry++ {
		peer := pg.acquirePeer()
		ret, err = peer.GetPalaMeta()
		if err == nil {
			pg.releasePeer(peer)
			return ret, nil
		}

		pg.timeoutPeer(peer)
		fmt.Printf("GetPalaMetaForSnapshot raised error: %s\n", err.Error())
	}
	return ret, err
}

func (pg *PeerGroup) GetBlockByNumber(number *big.Int) (ret *types.Block, err error) {
	for retry := 0; retry < RETRY_MAX; retry++ {
		peer := pg.acquirePeer()
		ret, err = peer.GetBlockByNumber(number)
		if err == nil {
			pg.releasePeer(peer)
			return ret, nil
		}
		pg.timeoutPeer(peer)
		fmt.Printf("GetBlockByNumber raised error: %s\n", err.Error())
	}
	return ret, err
}

func (pg *PeerGroup) GetTtBlock(targetBlk *big.Int) (ret *blockchain.TtBlockForSnapshot, err error) {
	for retry := 0; retry < RETRY_MAX; retry++ {
		peer := pg.acquirePeer()
		ret, err = peer.GetTtBlock(targetBlk)
		if err == nil {
			pg.releasePeer(peer)
			return ret, nil
		}
		pg.timeoutPeer(peer)
		fmt.Printf("GetTtBlockraised error: %s\n", err.Error())
	}
	return ret, err
}

func (pg *PeerGroup) BatchGetTtBlocks(blockNums []*big.Int) (ret []*blockchain.TtBlockForSnapshot, err error) {
	for retry := 0; retry < RETRY_MAX; retry++ {
		peer := pg.acquirePeer()
		ret, err = peer.BatchGetTtBlocks(blockNums)
		if err == nil {
			pg.releasePeer(peer)
			return
		}
		pg.timeoutPeer(peer)
		fmt.Printf("GetFullBlocks raised error: %s\n", err.Error())
	}
	return
}

func (pg *PeerGroup) GetTrieState(keys []common.Hash) (ret []trie.SyncResult, err error) {
	for retry := 0; retry < RETRY_MAX; retry++ {
		peer := pg.acquirePeer()
		ret, err = peer.GetTrieState(keys)
		if err == nil {
			pg.releasePeer(peer)
			return ret, nil
		}
		pg.timeoutPeer(peer)
		fmt.Printf("GetTrieStateraised error: %s\n", err.Error())
	}
	return ret, err
}
