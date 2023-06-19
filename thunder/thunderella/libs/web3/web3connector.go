package web3

import (
	// Standard imports
	"context"
	"fmt"
	"math/big"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chain"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"

	// Vendor imports
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// a connector represents a connection to a fullnode (thunder, simulated auxnet, or ethereum).
type Web3Connector struct {
	ctx        context.Context
	rpc        *rpc.Client
	eth        *ethclient.Client
	lgr        *lgr.Lgr
	name       string
	nonceTable map[common.Address]uint64
}

func NewWeb3Connector(url string, name string, parentLogger *lgr.Lgr) (*Web3Connector, error) {
	newLgr := parentLogger.NewChildLgrT("Connector", name)
	rpcClient, err := rpc.Dial(url)
	if err != nil {
		newLgr.Error("Unable to connect to %s: %s", url, err)
		return nil, err
	}
	eth := ethclient.NewClient(rpcClient)
	conn := &Web3Connector{
		ctx:        context.Background(),
		rpc:        rpcClient,
		eth:        eth,
		lgr:        newLgr,
		name:       name,
		nonceTable: make(map[common.Address]uint64),
	}

	// Supplemental info.  If we get errors getting these values it doesn't cause us to not
	// return the connection.
	chainID, err := conn.GetChainID()
	if err != nil {
		// GetChainID() should always work
		rpcClient.Close()
		return nil, err
	}
	chainIDstr := fmt.Sprintf("Chain id %v", chainID)

	suggestedGas, err := eth.SuggestGasPrice(conn.ctx)
	if err != nil {
		// SuggestGasPrice() should always work
		rpcClient.Close()
		return nil, err
	}
	suggestedGasStr := fmt.Sprintf("Suggested gas price %v", suggestedGas)

	var protocolVersion string
	err = rpcClient.Call(&protocolVersion, "eth_protocolVersion")
	if err != nil {
		// Call() for protocolVersion should always work
		rpcClient.Close()
		return nil, err
	}
	protocolVersionStr := fmt.Sprintf("Protocol version %s", protocolVersion)

	conn.lgr.Info("Connected to %s, %s, %s, %s", url, protocolVersionStr, suggestedGasStr,
		chainIDstr)
	return conn, nil
}

func (conn *Web3Connector) GetName() string {
	return conn.name
}

func (conn *Web3Connector) NewChildLgr(name string) *lgr.Lgr {
	return conn.lgr.NewChildLgr(name)
}

func (conn *Web3Connector) GetNonce(addr *common.Address) (uint64, error) {
	var err error
	nonce, err := conn.eth.PendingNonceAt(conn.ctx, *addr)
	if err != nil {
		conn.lgr.Error("error getting nonce for account %s: %s", addr.String(), err)
		return 0, err
	}
	return nonce, nil
}

func (conn *Web3Connector) GetNonceAndIncrement(addr *common.Address) (uint64, error) {
	nonce, found := conn.nonceTable[*addr]
	if !found {
		var err error
		nonce, err = conn.GetNonce(addr)
		if err != nil {
			return 0, err
		}
		conn.nonceTable[*addr] = nonce
	}
	conn.lgr.Debug("nonce for %s is %d", addr.String(), nonce)
	conn.nonceTable[*addr] = nonce + 1
	return nonce, nil
}

func (conn *Web3Connector) SuggestedGasPrice() (*big.Int, error) {
	gasPrice, err := conn.eth.SuggestGasPrice(conn.ctx)
	if err != nil {
		conn.lgr.Error("error getting suggested gas price: %s", err)
		return nil, err
	}
	return gasPrice, nil
}

func (conn *Web3Connector) GetChainID() (*big.Int, error) {
	chainID, err := conn.eth.NetworkID(conn.ctx)
	if err != nil {
		conn.lgr.Error("error getting chain id: %s", err)
		return nil, err
	}
	return chainID, nil
}

func (conn *Web3Connector) GetLatestBlocknum() (*big.Int, error) {
	hdr, err := conn.GetLatestBlockHeader()
	if err != nil {
		return nil, err
	}
	return hdr.Number, nil
}

func (conn *Web3Connector) GetLatestBlockHeader() (*types.Header, error) {
	hdr, err := conn.GetBlockHeader(-1)
	if err != nil {
		return nil, err
	}
	return hdr, nil
}

func (conn *Web3Connector) GetBlockHeader(blockNum int64) (*types.Header, error) {
	var bnum *big.Int
	if blockNum == -1 {
		bnum = nil
	} else {
		bnum = big.NewInt(int64(blockNum))
	}
	hdr, err := conn.eth.HeaderByNumber(conn.ctx, bnum)
	if err != nil {
		conn.lgr.Error("error getting latest blocknum %v: %s", blockNum, err)
		return nil, err
	}
	return hdr, nil
}

func (conn *Web3Connector) SubscribeToHeaders(hdrChan chan<- *types.Header,
) (ethereum.Subscription, error) {
	sub, err := conn.eth.SubscribeNewHead(conn.ctx, hdrChan)
	if err != nil {
		conn.lgr.Error("error from SubscribeNewHead: %s", err)
		return nil, err
	}
	return sub, nil
}

func (conn *Web3Connector) GetBlock(blockNum int64) (*types.Block, error) {
	block, err := conn.eth.BlockByNumber(conn.ctx, big.NewInt(int64(blockNum)))
	if err != nil {
		return nil, err
	}
	return block, nil
}

func (conn *Web3Connector) GetBalance(addr *common.Address) (*big.Int, error) {
	balance, err := conn.eth.BalanceAt(conn.ctx, *addr, nil)
	if err != nil {
		conn.lgr.Error("error getting balance for address %s: %s", addr.Hex(), err)
		return nil, err
	}
	return balance, nil
}

func (conn *Web3Connector) SendTx(signedTx *types.Transaction) error {
	err := conn.eth.SendTransaction(conn.ctx, signedTx)
	if err != nil {
		conn.lgr.Error("error sending tx with nonce %d hash %s: %s", signedTx.Nonce(),
			signedTx.Hash().Hex(), err)
		return err
	}
	return nil
}

func (conn *Web3Connector) FindTx(tx *types.Transaction) (chain.Height, error) {
	_, blockNum, err := conn.eth.TransactionAndBlockByHash(conn.ctx, tx.Hash())
	if err != nil {
		conn.lgr.Error("error getting tx and hash: %s", err)
		return 0, err
	}
	return chain.Height(blockNum), nil
}

func (conn *Web3Connector) Close() {
	conn.rpc.Close()
}
