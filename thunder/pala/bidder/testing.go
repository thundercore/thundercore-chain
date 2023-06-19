package bidder

import (
	"context"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/thunder/pala/blockchain"

	"github.com/ethereum/go-ethereum/thunder/thunderella/thundervm"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"golang.org/x/xerrors"
)

var discardTx = xerrors.New("discard tx")

type FakeSubscription struct {
	errChan chan error
}

func (s *FakeSubscription) Err() <-chan error {
	return s.errChan
}

func (s *FakeSubscription) Unsubscribe() {
	close(s.errChan)
}

type FakeClient struct {
	mutex      utils.CheckedLock
	receipts   map[common.Hash]*types.Receipt
	nonces     map[common.Address]uint64
	bidAmount  map[common.Address]*big.Int
	txChan     chan *types.Transaction
	txRespChan chan error
	head       blockchain.BlockSn
	gasPrice   *big.Int
}

func NewFakeClient() Client {
	utils.EnsureRunningInTestCode()
	return &FakeClient{
		txChan:     make(chan *types.Transaction),
		txRespChan: make(chan error),
		receipts:   make(map[common.Hash]*types.Receipt),
		nonces:     make(map[common.Address]uint64),
		bidAmount:  make(map[common.Address]*big.Int),
		gasPrice:   big.NewInt(100),
	}
}

func (c *FakeClient) Close() {
}

func (c *FakeClient) TransactionReceipt(ctx context.Context, h common.Hash) (*types.Receipt, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	r, ok := c.receipts[h]
	if ok {
		return r, nil
	}
	return nil, ethereum.NotFound
}

func (c *FakeClient) HeaderByNumber(ctx context.Context, n *big.Int) (*types.Header, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return newHeader(c.head), nil
}

func (c *FakeClient) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	timeout := 300 * time.Millisecond
	t := time.After(timeout)
	select {
	case c.txChan <- tx:
	case <-t:
		return xerrors.Errorf("blocked after %s", timeout)
	}
	err := <-c.txRespChan
	if err == nil {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		chainId := params.ThunderChainConfig().ChainID
		signer := types.NewEIP155Signer(chainId)
		addr, _ := types.Sender(signer, tx)
		c.incNonce(addr)
		c.receipts[tx.Hash()] = &types.Receipt{TxHash: tx.Hash()}
	}
	return nil
}

func (c *FakeClient) SetGasPrice(gasPrice *big.Int) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.gasPrice.Set(gasPrice)
}

func (c *FakeClient) CheckAndRespondTx(allow bool, d time.Duration) (*types.Transaction, error) {
	t := time.After(d)
	select {
	case tx := <-c.txChan:
		if allow {
			c.txRespChan <- nil
		} else {
			c.txRespChan <- discardTx
		}
		return tx, nil
	case <-t:
		return nil, xerrors.Errorf("No tx after %s", d)
	}
}

func (c *FakeClient) NonceAt(ctx context.Context, addr common.Address, b *big.Int) (uint64, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	nonce, ok := c.nonces[addr]
	if ok {
		return nonce, nil
	}
	return 0, nil
}

func (c *FakeClient) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return new(big.Int).Set(c.gasPrice), nil
}

func (c *FakeClient) AdvanceHead(sn blockchain.BlockSn) {
	c.mutex.Lock()
	c.head = sn
	c.mutex.Unlock()
}

func (c *FakeClient) CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	method, err := thundervm.VaultR3ABI.MethodById(msg.Data[:4])
	if err != nil {
		return nil, err
	}
	if method.Name == "getNonce" {
		return []byte{1}, nil
	}
	if method.Name == "getBidAmount" {
		return c.bidAmount[msg.From].Bytes(), nil
	}

	return nil, xerrors.New("not implemented")
}

func (c *FakeClient) SetBidAmount(addr common.Address, amount *big.Int) {
	c.bidAmount[addr] = amount
}

func (c *FakeClient) incNonce(addr common.Address) {
	c.mutex.CheckIsLocked("")
	if _, ok := c.nonces[addr]; ok {
		c.nonces[addr]++
	} else {
		c.nonces[addr] = 1
	}
}

func newHeader(sn blockchain.BlockSn) *types.Header {
	parentSn := blockchain.NewBlockSn(uint32(sn.Epoch.Session-1), sn.Epoch.E, 1)
	return &types.Header{Difficulty: blockchain.EncodeBlockSnToNumber(parentSn, sn), Number: big.NewInt(0)}
}
