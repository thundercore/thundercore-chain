package test

import (
	"context"
	"math/big"
	"strconv"
	"sync"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
	"golang.org/x/xerrors"
)

type Client struct {
	c *rpc.Client

	mu     sync.Mutex
	record map[string]struct{}
}

type Block struct {
	Number          hexutil.Big    `json:"number"`
	Hash            common.Hash    `json:"hash"`
	ParentHash      common.Hash    `json:"parentHash"`
	Nonce           hexutil.Bytes  `json:"nonce"`
	SHA3Uncles      common.Hash    `json:"sha3Uncles"`
	LogsBloom       hexutil.Bytes  `json:"logsBloom"`
	TransactionRoot common.Hash    `json:"transactionRoot"`
	StateRoot       common.Hash    `json:"stateRoot"`
	Miner           common.Address `json:"miner"`
	Difficulty      hexutil.Big    `json:"difficulty"`
	TotalDifficulty hexutil.Big    `json:"totalDifficulty"`
	ExtraData       hexutil.Bytes  `json:"extraData"`
	Size            hexutil.Big    `json:"size"`
	GasLimit        hexutil.Big    `json:"gasLimit"`
	GasUsed         hexutil.Big    `json:"gasUsed"`
	Timestamp       hexutil.Uint64 `json:"timestamp"`
	Transactions    []Transaction  `json:"transactions"`
	Uncles          []common.Hash  `json:"uncles"`
}

type Transaction struct {
	Hash             common.Hash     `json:"hash"`
	BlockHash        *common.Hash    `json:"blockHash,omitempty"`
	BlockNumber      *hexutil.Big    `json:"blockNumber,omitempty"`
	From             common.Address  `json:"from"`
	To               *common.Address `json:"to,omitempty"`
	Gas              hexutil.Uint64  `json:"gas"`
	GasPrice         hexutil.Big     `json:"gasPrice"`
	Input            hexutil.Bytes   `json:"input"`
	Nonce            hexutil.Uint64  `json:"nonce"`
	TransactionIndex string          `json:"transactionIndex"`
	Value            hexutil.Big     `json:"value"`
	V                *hexutil.Big    `json:"v,omitempty"`
	R                *hexutil.Big    `json:"r,omitempty"`
	S                *hexutil.Big    `json:"s,omitempty"`
}

type SendTxArgs struct {
	From     common.Address  `json:"from"`
	To       *common.Address `json:"to"`
	Gas      *hexutil.Uint64 `json:"gas"`
	GasPrice *hexutil.Big    `json:"gasPrice"`
	Value    *hexutil.Big    `json:"value"`
	Nonce    *hexutil.Uint64 `json:"nonce"`
	Input    *hexutil.Bytes  `json:"input"`
}

func Dial(rawurl string) (*Client, error) {
	return DialContext(context.Background(), rawurl)
}

func DialContext(ctx context.Context, rawurl string) (*Client, error) {
	c, err := rpc.DialContext(ctx, rawurl)
	if err != nil {
		return nil, err
	}
	return NewClient(c), nil
}

func NewClient(c *rpc.Client) *Client {
	return &Client{
		c:      c,
		record: make(map[string]struct{}),
	}
}

func (c *Client) Close() {
	c.c.Close()
}

func (c *Client) CallContext(ctx context.Context, result interface{}, method string, args ...interface{}) error {
	c.mu.Lock()
	c.record[method] = struct{}{}
	c.mu.Unlock()
	return c.c.CallContext(ctx, result, method, args...)
}

func (c *Client) NewAccount(ctx context.Context, password string) (common.Address, error) {
	var address common.Address
	if err := c.CallContext(ctx, &address, "personal_newAccount", password); err != nil {
		return common.Address{}, err
	}
	return address, nil
}

func (c *Client) ListAccounts(ctx context.Context) ([]common.Address, error) {
	var addresses []common.Address
	if err := c.CallContext(ctx, &addresses, "personal_listAccounts"); err != nil {
		return nil, err
	}
	return addresses, nil
}

func (c *Client) SendTransaction(ctx context.Context, txArgs SendTxArgs, password string) (common.Hash, error) {
	var hash common.Hash
	err := c.CallContext(ctx, &hash, "personal_sendTransaction", txArgs, password)
	return hash, err
}

func (c *Client) NetworkID(ctx context.Context) (*big.Int, error) {
	var version big.Int
	var ver string
	if err := c.CallContext(ctx, &ver, "net_version"); err != nil {
		return nil, err
	}
	if _, ok := version.SetString(ver, 10); !ok {
		return nil, xerrors.Errorf("invalid net_version result %q", ver)
	}
	return &version, nil
}

func (c *Client) NetworkPeerCount(ctx context.Context) (int, error) {
	var s string
	if err := c.CallContext(ctx, &s, "net_peerCount"); err != nil {
		return 0, err
	}
	count, err := strconv.ParseInt(s, 0, 32)
	if err != nil {
		return 0, xerrors.Errorf("invalid net_peerCount result %q", s)
	}
	return int(count), nil
}

func (c *Client) NetworkListening(ctx context.Context) (bool, error) {
	var listening bool
	if err := c.CallContext(ctx, &listening, "net_listening"); err != nil {
		return false, err
	}
	return listening, nil
}

func (c *Client) Web3ClientVersion(ctx context.Context) (string, error) {
	var s string
	if err := c.CallContext(ctx, &s, "web3_clientVersion"); err != nil {
		return "", err
	}
	return s, nil
}

func (c *Client) Web3Sha3(ctx context.Context, input []byte) ([]byte, error) {
	var s string
	err := c.CallContext(ctx, &s, "web3_sha3", hexutil.Bytes(input))
	result, err := hexutil.Decode(s)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (c *Client) BlockNumber(ctx context.Context) (*big.Int, error) {
	var result hexutil.Big
	err := c.CallContext(ctx, &result, "eth_blockNumber")
	return result.ToInt(), err
}

func (c *Client) GetBalance(ctx context.Context, address common.Address, blockNumber *big.Int) (*big.Int, error) {
	var result hexutil.Big
	err := c.CallContext(ctx, &result, "eth_getBalance", address, toBlockNumArg(blockNumber))
	return result.ToInt(), err
}

func (c *Client) GetStorageAt(ctx context.Context, address common.Address, key common.Hash, blockNumber *big.Int) ([]byte, error) {
	var result hexutil.Bytes
	err := c.CallContext(ctx, &result, "eth_getStorageAt", address, key, toBlockNumArg(blockNumber))
	return result, err
}

func (c *Client) GetCode(ctx context.Context, address common.Address, blockNumber *big.Int) ([]byte, error) {
	var result hexutil.Bytes
	err := c.CallContext(ctx, &result, "eth_getCode", address, toBlockNumArg(blockNumber))
	return result, err
}

func (c *Client) GetNonce(ctx context.Context, address common.Address, blockNumber *big.Int) (uint64, error) {
	var result hexutil.Uint64
	err := c.CallContext(ctx, &result, "eth_getTransactionCount", address, toBlockNumArg(blockNumber))
	return uint64(result), err
}

func (c *Client) GetBlockByHash(ctx context.Context, hash common.Hash) (*Block, error) {
	return c.getBlock(ctx, "eth_getBlockByHash", hash, true)
}

func (c *Client) GetBlockByNumber(ctx context.Context, number *big.Int) (*Block, error) {
	return c.getBlock(ctx, "eth_getBlockByNumber", toBlockNumArg(number), true)
}

func (c *Client) GetBlockTransactionCountByHash(ctx context.Context, hash common.Hash) (uint, error) {
	var num hexutil.Uint
	err := c.CallContext(ctx, &num, "eth_getBlockTransactionCountByHash", hash)
	return uint(num), err
}

func (c *Client) GetBlockTransactionCountByNumber(ctx context.Context, number uint64) (uint, error) {
	var num hexutil.Uint
	err := c.CallContext(ctx, &num, "eth_getBlockTransactionCountByNumber", hexutil.Uint64(number))
	return uint(num), err
}

func (c *Client) GetTransactionByHash(ctx context.Context, hash common.Hash) (*Transaction, error) {
	var tx *Transaction
	err := c.CallContext(ctx, &tx, "eth_getTransactionByHash", hash)
	if err != nil {
		return nil, err
	} else if tx == nil {
		return nil, ethereum.NotFound
	} else if tx.R == nil {
		return nil, xerrors.New("server returned transaction without signature")
	}
	return tx, nil
}

func (c *Client) GetTransactionByBlockHashAndIndex(
	ctx context.Context, blockHash common.Hash, index uint) (*Transaction, error) {
	var tx *Transaction
	err := c.CallContext(ctx, &tx, "eth_getTransactionByBlockHashAndIndex", blockHash, hexutil.Uint64(index))
	if err == nil {
		if tx == nil {
			return nil, ethereum.NotFound
		} else if tx.R == nil {
			return nil, xerrors.New("server returned transaction without signature")
		}
	}
	return tx, err
}

func (c *Client) GetTransactionByBlockNumberAndIndex(ctx context.Context, blockNumber uint64, index uint) (*Transaction,
	error) {
	var tx *Transaction
	err := c.CallContext(ctx, &tx, "eth_getTransactionByBlockNumberAndIndex",
		hexutil.Uint64(blockNumber), hexutil.Uint64(index))
	if err == nil {
		if tx == nil {
			return nil, ethereum.NotFound
		} else if tx.R == nil {
			return nil, xerrors.New("server returned transaction without signature")
		}
	}
	return tx, err
}

func (c *Client) GetTransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	var r *types.Receipt
	err := c.CallContext(ctx, &r, "eth_getTransactionReceipt", txHash)
	if err == nil {
		if r == nil {
			return nil, ethereum.NotFound
		}
	}
	return r, err
}

func toBlockNumArg(number *big.Int) string {
	if number == nil {
		return "latest"
	}
	return hexutil.EncodeBig(number)
}

func (c *Client) getBlock(ctx context.Context, method string, args ...interface{}) (*Block, error) {
	var block *Block
	err := c.CallContext(ctx, &block, method, args...)
	if err != nil {
		return nil, err
	} else if block == nil {
		return nil, ethereum.NotFound
	}

	if block.TransactionRoot == types.EmptyRootHash && len(block.Transactions) > 0 {
		return nil, xerrors.New("server returned empty transaction list but block indicates no transactions")
	}

	/*
		if block.SHA3Uncles != types.EmptyRootHash && len(block.Uncles) == 0 {
			fmt.Println(block.SHA3Uncles)
			fmt.Println(types.EmptyRootHash)
			return nil, xerrors.New("server returned empty uncles list but block indicates transactions")
		}
	*/

	return block, nil
}

func (c *Client) SendRawTransaction(ctx context.Context, tx *types.Transaction) error {
	data, err := tx.MarshalBinary()
	if err != nil {
		return err
	}
	return c.CallContext(ctx, nil, "eth_sendRawTransaction", hexutil.Encode(data))
}

func (c *Client) CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	var hex hexutil.Bytes
	err := c.CallContext(ctx, &hex, "eth_call", toCallArg(msg), toBlockNumArg(blockNumber))
	if err != nil {
		return nil, err
	}
	return hex, nil
}

func (c *Client) EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error) {
	var hex hexutil.Uint64
	err := c.CallContext(ctx, &hex, "eth_estimateGas", toCallArg(msg))
	if err != nil {
		return 0, err
	}
	return uint64(hex), nil
}

func (c *Client) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	var hex hexutil.Big
	if err := c.CallContext(ctx, &hex, "eth_gasPrice"); err != nil {
		return nil, err
	}
	return hex.ToInt(), nil
}

func toCallArg(msg ethereum.CallMsg) interface{} {
	arg := map[string]interface{}{
		"from": msg.From,
		"to":   msg.To,
	}
	if len(msg.Data) > 0 {
		arg["data"] = hexutil.Bytes(msg.Data)
	}
	if msg.Value != nil {
		arg["value"] = (*hexutil.Big)(msg.Value)
	}
	if msg.Gas != 0 {
		arg["gas"] = hexutil.Uint64(msg.Gas)
	}
	if msg.GasPrice != nil {
		arg["gasPrice"] = (*hexutil.Big)(msg.GasPrice)
	}
	return arg
}

func (c *Client) NewFilter(ctx context.Context, q ethereum.FilterQuery) (string, error) {
	var id string
	arg, err := toFilterArg(q)
	if err != nil {
		return "", err
	}
	if err := c.CallContext(ctx, &id, "eth_newFilter", arg); err != nil {
		return "", err
	}
	return id, nil
}

func (c *Client) UninstallFilter(ctx context.Context, id string) (bool, error) {
	var result bool
	if err := c.CallContext(ctx, &result, "eth_uninstallFilter", id); err != nil {
		return false, err
	}
	return result, nil
}

func (c *Client) NewBlockFilter(ctx context.Context) (string, error) {
	var id string
	if err := c.CallContext(ctx, &id, "eth_newBlockFilter"); err != nil {
		return "", err
	}
	return id, nil
}

func (c *Client) NewPendingTransactionFilter(ctx context.Context) (string, error) {
	var id string
	if err := c.CallContext(ctx, &id, "eth_newPendingTransactionFilter"); err != nil {
		return "", err
	}
	return id, nil
}

func (c *Client) GetFilterLogs(ctx context.Context, id string) ([]*types.Log, error) {
	var logs []*types.Log
	if err := c.CallContext(ctx, &logs, "eth_getFilterLogs", id); err != nil {
		return nil, err
	}
	return logs, nil
}

func (c *Client) GetLogs(ctx context.Context, q ethereum.FilterQuery) ([]*types.Log, error) {
	var logs []*types.Log
	arg, err := toFilterArg(q)
	if err != nil {
		return nil, err
	}
	err = c.CallContext(ctx, &logs, "eth_getLogs", arg)
	return logs, err
}

func (c *Client) GetFilterChanges(ctx context.Context, id string) ([]common.Hash, error) {
	var hashes []common.Hash
	if err := c.CallContext(ctx, &hashes, "eth_getFilterChanges", id); err != nil {
		return nil, err
	}
	return hashes, nil
}

func (c *Client) GetLogFilterChanges(ctx context.Context, id string) ([]*types.Log, error) {
	var logs []*types.Log
	if err := c.CallContext(ctx, &logs, "eth_getFilterChanges", id); err != nil {
		return nil, err
	}
	return logs, nil
}

func (c *Client) SubscribeFilterLogs(ctx context.Context, q ethereum.FilterQuery, ch chan<- types.Log) (ethereum.Subscription, error) {
	arg, err := toFilterArg(q)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.record["eth_subscribe_logs"] = struct{}{}
	c.mu.Unlock()
	return c.c.EthSubscribe(ctx, ch, "logs", arg)
}

func (c *Client) Subscribe(ctx context.Context, method string, ch interface{}) (ethereum.Subscription, error) {
	c.mu.Lock()
	c.record["eth_subscribe_"+method] = struct{}{}
	c.mu.Unlock()
	return c.c.EthSubscribe(ctx, ch, method)
}

func toFilterArg(q ethereum.FilterQuery) (interface{}, error) {
	arg := map[string]interface{}{
		"address": q.Addresses,
		"topics":  q.Topics,
	}
	if q.BlockHash != nil {
		arg["blockHash"] = *q.BlockHash
		if q.FromBlock != nil || q.ToBlock != nil {
			return nil, xerrors.New("cannot specify both BlockHash and FromBlock/ToBlock")
		}
	} else {
		if q.FromBlock == nil {
			arg["fromBlock"] = "0x0"
		} else {
			arg["fromBlock"] = toBlockNumArg(q.FromBlock)
		}
		arg["toBlock"] = toBlockNumArg(q.ToBlock)
	}
	return arg, nil
}

func (c *Client) Record() map[string]struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.record
}
