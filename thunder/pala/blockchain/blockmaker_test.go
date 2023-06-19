package blockchain

import (
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/consensus/thunder"
	"github.com/ethereum/go-ethereum/thunder/thunderella/protocol"
	"github.com/ethereum/go-ethereum/thunder/thunderella/testutils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"
)

func BuildTxPool(chain *core.BlockChain) *core.TxPool {

	cfg := core.TxPoolConfig{
		NoLocals:         true,
		PriceLimit:       1,
		PriceBump:        10,
		AccountSlots:     1000,
		GlobalSlots:      10000,
		AccountQueue:     100,
		GlobalQueue:      1000,
		Lifetime:         time.Hour * 3,
		EvictionInterval: time.Second * 12,
	}
	txpool := core.NewTxPool(cfg, chain.Config(), chain)
	// set txpool.GasPrice using TestingCommInfo.ClearingGasPrice
	clearingGasPrice := testutils.TestingCommInfo.ClearingGasPrice()
	txpool.SetGasPrice(clearingGasPrice)
	return txpool
}

func setupBlockChainForTest(t *testing.T, unnotarizedWindow *config.Int64HardforkConfig, blockTime time.Duration) (BlockChain, ethdb.Database, *core.TxPool, *params.ThunderConfig) {
	req := require.New(t)
	memdb, chain, err := NewThunderSinceGenesisWithMemDb()
	req.NoError(err)

	txpool := BuildTxPool(chain)
	bc, err := NewBlockChainWithFakeNota(unnotarizedWindow, memdb, chain, txpool, nil, blockTime)
	req.NoError(err)

	return bc, memdb, txpool, chain.Config().Thunder
}

func setup(t *testing.T, numTx uint64, unnotarizedWindow *config.Int64HardforkConfig,
) (BlockChain, ethdb.Database, *params.ThunderConfig) {
	req := require.New(t)
	bc, memdb, txpool, thunderCfg := setupBlockChainForTest(t, unnotarizedWindow, blockTime)

	// really add transaction to test correctness
	for nonce := uint64(0); nonce < numTx; nonce++ {
		toAddr := common.HexToAddress("0x0000000000000000000000000000000000000000")
		tx := testutils.MakeTxactSimple(testutils.TestingKey, &toAddr, nonce)
		if err := txpool.AddRemote(tx); err != nil {
			req.NoError(err)
		}
	}

	return bc, memdb, thunderCfg
}

func NewContextForTest(t *testing.T, bc BlockChain, blkmaker *BlockMakerImpl) *blockContext {
	req := require.New(t)
	parent := bc.GetFreshestNotarizedHead()
	ethParent := parent.(*blockImpl).B
	sn := parent.GetBlockSn().NextS()
	header := blkmaker.prepareHeader(ethParent, parent.GetBlockSn(), sn)

	k := uint32(blkmaker.k.GetValueAtSession(int64(sn.Epoch.Session)))

	gp := new(core.GasPool).AddGas(header.GasLimit - getMaxConsensusTxGas(k))
	chainConfig := blkmaker.bc.Config()

	state, err := blkmaker.bc.StateAt(ethParent.Root())
	req.NoError(err)
	return &blockContext{
		header:     header,
		gp:         gp,
		state:      state,
		nonceCache: make(map[common.Address]uint64),
		signer:     types.MakeSigner(chainConfig, header.Number, uint32(sn.Epoch.Session)),
	}
}

func Test_applyTransactions(t *testing.T) {
	t.Run("test insufficient remaining block gas for tx", func(t *testing.T) {
		req := require.New(t)
		k := uint32(1)
		hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
		hardforkK.SetTestValueAtSession(int64(k), 0)

		bc, _, txpool, _ := setupBlockChainForTest(t, hardforkK, blockTime)
		blkmaker := bc.(*BlockChainImpl).GetBlockMakerForTest().(*BlockMakerImpl)
		context := NewContextForTest(t, bc, blkmaker)
		context.gp = new(core.GasPool).AddGas(uint64(21000))

		txs := []*types.Transaction{}
		for nonce := uint64(0); nonce < 5; nonce++ {
			toAddr := common.HexToAddress("0x0000000000000000000000000000000000001234")
			tx := testutils.MakeTxact(testutils.TestingKey, &toAddr, nonce, big.NewInt(600*params.GWei), nil, nil)
			txs = append(txs, tx)
		}

		errs := txpool.AddRemotesSync(txs)
		for _, err := range errs {
			req.NoError(err)
		}

		numTx, pendingTxs := blkmaker.getPendingTransactions(context)
		req.Equal(5, numTx)
		context.pendingTransactions = pendingTxs
		for i := 0; i < 10; i++ {
			tx := pendingTxs.Peek()
			if tx == nil {
				break
			}
			err := blkmaker.applyTransaction(context, tx)
			if i == 0 {
				req.NoError(err)
			} else {
				req.EqualError(err, core.ErrGasLimitReached.Error())
			}
		}
	})

	t.Run("test insufficient balance and denylist [THUNDER-1145]", func(t *testing.T) {
		req := require.New(t)
		k := uint32(1)
		hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
		hardforkK.SetTestValueAtSession(int64(k), 0)

		bc, _, txpool, _ := setupBlockChainForTest(t, hardforkK, blockTime)
		blkmaker := bc.(*BlockChainImpl).GetBlockMakerForTest().(*BlockMakerImpl)
		context := NewContextForTest(t, bc, blkmaker)
		nonce := context.state.GetNonce(testutils.TestingLowValueAddr)

		txs := []*types.Transaction{}
		for nonce := uint64(0); nonce < 5; nonce++ {
			toAddr := common.HexToAddress("0x0000000000000000000000000000000000001234")
			tx := testutils.MakeTxact(testutils.TestingLowValueKey, &toAddr, nonce, big.NewInt(400*params.GWei), nil, nil)
			txs = append(txs, tx)
		}
		errs := txpool.AddRemotesSync(txs)
		for _, err := range errs {
			req.NoError(err)
		}

		numTx, pendingTxs := blkmaker.getPendingTransactions(context)
		req.Equal(5, numTx)
		context.pendingTransactions = pendingTxs
		for i := 0; i < numTx; i++ {
			tx := pendingTxs.Peek()
			switch i {
			case 0:
				err := blkmaker.applyTransaction(context, tx)
				req.NoError(err)
			case 1:
				err := blkmaker.applyTransaction(context, tx)
				req.Contains(err.Error(), core.ErrInsufficientFunds.Error())
			case 2:
				err := blkmaker.applyTransaction(context, tx)
				req.Contains(err.Error(), core.ErrNonceTooHigh.Error())
			}
		}

		req.Equal(context.state.GetNonce(testutils.TestingLowValueAddr), nonce+1, "only first tx was accepted")

		numTx, _ = blkmaker.getPendingTransactions(context)
		req.Equal(4, numTx)
	})

	t.Run("test cache nonce", func(t *testing.T) {
		req := require.New(t)
		k := uint32(1)
		hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
		hardforkK.SetTestValueAtSession(int64(k), 0)

		bc, _, txpool, _ := setupBlockChainForTest(t, hardforkK, blockTime)
		blkmaker := bc.(*BlockChainImpl).GetBlockMakerForTest().(*BlockMakerImpl)
		context := NewContextForTest(t, bc, blkmaker)

		txs := []*types.Transaction{}
		for nonce := uint64(0); nonce < 5; nonce++ {
			toAddr := common.HexToAddress("0x0000000000000000000000000000000000001234")
			tx := testutils.MakeTxact(testutils.TestingKey, &toAddr, nonce, big.NewInt(500*params.GWei), nil, nil)
			txs = append(txs, tx)
		}
		errs := txpool.AddRemotesSync(txs)
		for _, err := range errs {
			req.NoError(err)
		}

		numTx, pendingTxs := blkmaker.getPendingTransactions(context)
		req.Equal(5, numTx)
		context.pendingTransactions = pendingTxs
		for {
			tx := pendingTxs.Peek()
			if tx == nil {
				break
			}
			req.NoError(blkmaker.applyTransaction(context, tx))
		}

		req.Equal(context.nonceCache[testutils.TestingAddr], uint64(4))

		txs = txs[:0]
		for nonce := uint64(5); nonce < 15; nonce++ {
			toAddr := common.HexToAddress("0x0000000000000000000000000000000000001234")
			tx := testutils.MakeTxact(testutils.TestingKey, &toAddr, nonce, big.NewInt(500*params.GWei), nil, nil)
			txs = append(txs, tx)
		}
		errs = txpool.AddRemotesSync(txs)
		for _, err := range errs {
			req.NoError(err)
		}
		numTx, _ = blkmaker.getPendingTransactions(context)
		req.Equal(10, numTx)
	})

	t.Run("test tx with basefee", func(t *testing.T) {
		req := require.New(t)

		memdb, chain, err := NewThunderSinceGenesisWithMemDb()
		req.NoError(err)

		k := uint32(1)
		hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
		hardforkK.SetTestValueAtSession(int64(k), 0)

		// setup
		// basefee = 10 gwei
		var gwei *big.Int = big.NewInt(1000000000)
		baseFee := new(big.Int).Mul(big.NewInt(10), gwei)
		chain.Config().Thunder.BaseFee.SetTestValueAtSession(baseFee, 0)

		txpool := BuildTxPool(chain)
		bc, err := NewBlockChainWithFakeNota(hardforkK, memdb, chain, txpool, nil, blockTime)
		req.NoError(err)

		blkmaker := bc.(*BlockChainImpl).GetBlockMakerForTest().(*BlockMakerImpl)
		context := NewContextForTest(t, bc, blkmaker)
		context.gp = new(core.GasPool).AddGas(uint64(21000 * 5))

		txs := []*types.Transaction{}
		for nonce := uint64(0); nonce < 5; nonce++ {
			toAddr := common.HexToAddress("0x0000000000000000000000000000000000001234")
			tx := testutils.MakeTxact(testutils.TestingKey, &toAddr, nonce, big.NewInt(600*params.GWei), nil, nil)
			txs = append(txs, tx)
		}

		txs = []*types.Transaction{}
		// gasPrice = 11gwei
		gasPrice := baseFee.Add(baseFee, gwei)
		for nonce := uint64(0); nonce < 5; nonce++ {
			toAddr := common.HexToAddress("0x0000000000000000000000000000000000001234")
			tx := testutils.MakeTxact(testutils.TestingKey, &toAddr, nonce, big.NewInt(600*params.GWei), nil, gasPrice)
			txs = append(txs, tx)
		}

		errs := txpool.AddRemotesSync(txs)
		for _, err := range errs {
			req.NoError(err)
		}

		numTx, pendingTxs := blkmaker.getPendingTransactions(context)
		req.Equal(numTx, 5)
		context.pendingTransactions = pendingTxs
		for i := 0; i < 10; i++ {
			tx := pendingTxs.Peek()
			if tx == nil {
				break
			}
			err := blkmaker.applyTransaction(context, tx)
			req.NoError(err)
		}
	})
}

func TestBlockMakerImp(t *testing.T) {
	req := require.New(t)
	numTx := uint64(6000)
	if testutils.RaceEnabled {
		numTx = 600
	}
	if testing.Short() {
		numTx = numTx / 20
	}
	unnotarizedWindow := uint32(3)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(unnotarizedWindow), 0)

	epoch := NewEpoch(1, 1)
	bc, memdb, _ := setup(t, numTx, hardforkK)

	// Create the blocks.
	var b Block
	ch, err := bc.StartCreatingNewBlocks(epoch, nil)
	req.NoError(err)
	defer func() {
		if bc.IsCreatingBlock() {
			err = bc.StopCreatingNewBlocks(WaitingPeriodForStopingNewBlocks)
			req.NoError(err)
		}
	}()
	for i := uint32(0); i < unnotarizedWindow; i++ {
		b = (<-ch).Block
		req.Equal(BlockSn{epoch, i + 1}, b.GetBlockSn())
	}
	// Expect the blockchain blocks because there is no notarization.
	select {
	case <-ch:
		t.FailNow()
	case <-time.After(100 * time.Millisecond):
	}

	// Add notarization, so BlockChain can create new blocks.
	voterIds := []ConsensusId{"v1"}
	notaEnd := uint32(256)

	if testing.Short() {
		notaEnd = uint32(16)
	}

	for i := uint32(1); i <= notaEnd; i++ {
		err = bc.AddNotarization(&NotarizationFake{BlockSn{epoch, i}, voterIds})
		req.NoError(err)
		b = (<-ch).Block
	}

	req.Equal(BlockSn{epoch, notaEnd + unnotarizedWindow}, b.GetBlockSn())
	decoder := NewBlockImplDecoder(hardforkK, &DataUnmarshallerFake{}, nil)
	notas := decoder.GetNotarizations(b, bc.(*BlockChainImpl).storage.GetThunderConfig())
	req.Equal(1, len(notas), "Fail to get nota from %s", b.GetBlockSn())
	// Expect storing the "parent-k"'s notarization.
	req.Equal(BlockSn{epoch, notaEnd}, notas[0].GetBlockSn())

	err = bc.StopCreatingNewBlocks(WaitingPeriodForStopingNewBlocks)
	req.NoError(err)
	// Expect created blocks are already inserted.
	for i := uint32(1); i <= uint32(notaEnd+unnotarizedWindow); i++ {
		b = bc.GetBlock(BlockSn{epoch, i})
		req.NotNil(b)
		req.Equal(BlockSn{epoch, i}, b.GetBlockSn())
	}

	// Create the blocks at the next epoch.
	err = bc.AddNotarization(&NotarizationFake{BlockSn{epoch, notaEnd + 1}, voterIds})
	req.NoError(err)

	epoch = epoch.NextEpoch()
	fnc := bc.GetFreshestNotarizedHead()
	ch, err = bc.StartCreatingNewBlocks(epoch, NewClockMsgNotaFake(epoch, voterIds))
	req.NoError(err)
	defer func() {
		err = bc.StopCreatingNewBlocks(WaitingPeriodForStopingNewBlocks)
		req.NoError(err)
	}()
	b = (<-ch).Block
	req.NotNil(b)
	req.Equal(BlockSn{epoch, 1}, b.GetBlockSn())
	req.Equal(fnc.GetBlockSn(), b.GetParentBlockSn())

	// Expect the first block contains previous blocks' notarizations.
	notas = decoder.GetNotarizations(b, bc.(*BlockChainImpl).storage.GetThunderConfig())
	req.Equal(unnotarizedWindow, uint32(len(notas)))
	pe, _ := epoch.PreviousEpoch()

	for i := uint32(0); i < unnotarizedWindow; i++ {
		req.Equal(BlockSn{pe, notaEnd + 1 - i}, notas[unnotarizedWindow-i-1].GetBlockSn())
	}

	for i := uint32(2); i <= unnotarizedWindow; i++ {
		b := (<-ch).Block
		req.NotNil(b)
		req.Equal(BlockSn{epoch, i}, b.GetBlockSn())

		hashn := rawdb.ReadCanonicalHash(memdb, uint64(notaEnd+1+i))
		req.Equal((common.Hash{}), hashn)
	}
}

func TestBlockBaseFee(t *testing.T) {
	req := require.New(t)

	unnotarizedWindow := uint32(3)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(unnotarizedWindow), 0)

	epoch := NewEpoch(1, 1)
	bc, _, _, thunderConfig := setupBlockChainForTest(t, hardforkK, blockTime)

	thunderConfig.EVMHardforkVersion.SetTestValueAtSession("london", 0)
	thunderConfig.IsConsensusInfoInHeader.SetTestValueAtSession(true, 0)

	testcases := []struct {
		epoch   Epoch
		baseFee *big.Int
	}{
		{epoch: NewEpoch(1, 1), baseFee: big.NewInt(10000000000)},
		{epoch: NewEpoch(2, 1), baseFee: big.NewInt(20000000000)},
		{epoch: NewEpoch(3, 1), baseFee: big.NewInt(30000000000)},
		{epoch: NewEpoch(4, 1), baseFee: big.NewInt(30000000000)},
		{epoch: NewEpoch(5, 1), baseFee: big.NewInt(20000000000)},
		{epoch: NewEpoch(6, 1), baseFee: big.NewInt(10000000000)},
	}

	// setup
	for _, c := range testcases {
		thunderConfig.BaseFee.SetTestValueAtSession(c.baseFee, int64(c.epoch.Session))
	}
	defer func() {
		thunderConfig.BaseFee.SetTestValueAt(common.Big0, 0)
	}()

	var cn ClockMsgNota
	for _, c := range testcases {
		// Create the blocks.
		var b Block
		ch, err := bc.StartCreatingNewBlocks(c.epoch, cn)
		req.NoError(err)
		for i := uint32(0); i < unnotarizedWindow; i++ {
			b = (<-ch).Block
			req.Equal(c.baseFee, b.(*blockImpl).B.BaseFee())
		}
		if bc.IsCreatingBlock() {
			err = bc.StopCreatingNewBlocks(WaitingPeriodForStopingNewBlocks)
			req.NoError(err)
		}

		voterIds := MakeConsensusIds(strings.Repeat("v", 60))
		cn = NewClockMsgNotaFake(epoch, voterIds)
	}
}

func TestBlockMakerAfterStopBlockEpectNotTx(t *testing.T) {
	req := require.New(t)

	numTx := uint64(2000)
	k := uint32(3)

	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(k), 0)

	epoch := NewEpoch(1, 1)
	bc, _, _ := setup(t, numTx, hardforkK)

	// assume each session should stop at block 13
	sessionStopBlock := int64(13)
	bc.(*BlockChainImpl).storage.GetThunderConfig().ElectionStopBlockSessionOffset.SetTestValueAt(sessionStopBlock, 0)
	bc.(*BlockChainImpl).storage.GetThunderConfig().IsConsensusInfoInHeader.SetTestValueAtSession(true, 0)

	var b Block
	ch, err := bc.StartCreatingNewBlocks(epoch, nil)
	req.NoError(err)
	defer func() {
		if bc.IsCreatingBlock() {
			err = bc.StopCreatingNewBlocks(WaitingPeriodForStopingNewBlocks)
			req.NoError(err)
		}
	}()

	// first k block should not have to have notarize to make
	for i := uint32(1); i <= k; i++ {
		b = (<-ch).Block
		req.Equal(BlockSn{epoch, i}, b.GetBlockSn())
	}

	// Expect the blockchain blocks because there is no notarization.
	select {
	case <-ch:
		t.FailNow()
	case <-time.After(100 * time.Millisecond):
	}

	voterIds := []ConsensusId{"v1"}
	notaEnd := uint32(13)

	// make block and add notarize from (1, 1, 1) to (1, 1, 13), and finalized head should be (1, 1, 13)
	for i := uint32(1); i <= notaEnd; i++ {
		err = bc.AddNotarization(&NotarizationFake{BlockSn{epoch, i}, voterIds})
		req.NoError(err)

		b = (<-ch).Block

		if i > uint32(sessionStopBlock) {
			// after sessionStopBlock, there should be not transaction in block.
			req.Equal(0, len(b.(*blockImpl).B.Transactions()), fmt.Sprintf("block %d should not contain any transactions (%d)", b.GetNumber(), len(b.(*blockImpl).B.Transactions())))
		}
	}

	err = bc.StopCreatingNewBlocks(WaitingPeriodForStopingNewBlocks)
	req.NoError(err)
}

func TestBlockMakerHardforkK(t *testing.T) {
	req := require.New(t)

	numTx := uint64(300)
	kAtSession1 := uint32(1)
	kAtSession2 := uint32(3)
	kAtSession3 := uint32(1)

	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(kAtSession1), 0)
	hardforkK.SetTestValueAtSession(int64(kAtSession2), 2)
	hardforkK.SetTestValueAtSession(int64(kAtSession3), 3)

	decoder := NewBlockImplDecoder(hardforkK, &DataUnmarshallerFake{}, nil)

	epoch := NewEpoch(1, 1)
	bc, _, _ := setup(t, numTx, hardforkK)

	// Create the blocks.
	var b Block
	ch, err := bc.StartCreatingNewBlocks(epoch, nil)
	req.NoError(err)
	defer func() {
		if bc.IsCreatingBlock() {
			err = bc.StopCreatingNewBlocks(WaitingPeriodForStopingNewBlocks)
			req.NoError(err)
		}
	}()

	checkBlockBeforeK := func(chBlock <-chan BlockMadeEvent, epoch Epoch, k uint32) {
		for i := uint32(1); i <= k; i++ {
			b = (<-chBlock).Block
			req.Equal(BlockSn{epoch, i}, b.GetBlockSn())
		}
	}
	checkBlockBeforeK(ch, epoch, kAtSession1)

	// Expect the blockchain blocks because there is no notarization.
	select {
	case <-ch:
		t.FailNow()
	case <-time.After(100 * time.Millisecond):
	}

	// Add notarization, so BlockChain can create new blocks.
	voterIds := []ConsensusId{"v1"}
	notaEnd := uint32(16)

	for i := uint32(1); i <= notaEnd; i++ {
		err = bc.AddNotarization(&NotarizationFake{BlockSn{epoch, i}, voterIds})
		req.NoError(err)
		b = (<-ch).Block
	}

	// notarized latest block in session 1
	bc.AddNotarization(&NotarizationFake{BlockSn{epoch, notaEnd + kAtSession1}, voterIds})

	err = bc.StopCreatingNewBlocks(WaitingPeriodForStopingNewBlocks)
	req.NoError(err)

	// Create the blocks at the next session where session = 2, k = 3
	epoch = epoch.NextSession()
	ch, err = bc.StartCreatingNewBlocks(epoch, nil)
	req.NoError(err)

	checkBlockBeforeK(ch, epoch, kAtSession2)

	// notarize (2, 1, 1) to (2, 1, 16), newest block should be (2, 1, 19)
	for i := uint32(1); i <= notaEnd; i++ {
		err = bc.AddNotarization(&NotarizationFake{BlockSn{epoch, i}, voterIds})
		req.NoError(err)
		b = (<-ch).Block
	}

	err = bc.StopCreatingNewBlocks(WaitingPeriodForStopingNewBlocks)
	req.NoError(err)

	// verify if newest block is (2, 1, 19)
	req.Equal(BlockSn{epoch, notaEnd + kAtSession2}, b.GetBlockSn())

	// freshest notarized head should be (2, 1, 16)
	fns := bc.GetFreshestNotarizedHeadSn()
	req.Equal(BlockSn{epoch, notaEnd}, fns)

	// finalized head should be (2, 1, 16 - k) = (2, 1, 13)
	fns = bc.GetFinalizedHeadSn()
	req.Equal(BlockSn{epoch, notaEnd - kAtSession2}, fns)

	// block (2, 1, 19) should contains notarization of (2, 1, 19 - k) = (2, 1, 16)
	notas := decoder.GetNotarizations(b, bc.(*BlockChainImpl).storage.GetThunderConfig())
	req.Equal(1, len(notas))
	req.Equal(BlockSn{epoch, notaEnd}, notas[0].GetBlockSn())

	// notarize latest k block in session 2
	for i := uint32(notaEnd + 1); i <= notaEnd+kAtSession2; i++ {
		err = bc.AddNotarization(&NotarizationFake{BlockSn{epoch, i}, voterIds})
	}

	// session 3, k = 1
	epoch = epoch.NextSession()
	ch, err = bc.StartCreatingNewBlocks(epoch, nil)
	req.NoError(err)

	checkBlockBeforeK(ch, epoch, kAtSession3)

	// since blockchain is not notarized in session 3 yet, the fresh head should be (2, 1, 19), and finalized head is (2, 1, 16)
	fns = bc.GetFreshestNotarizedHeadSn()
	req.Equal(BlockSn{Epoch{2, 1}, 19}, fns)

	fns = bc.GetFinalizedHeadSn()
	req.Equal(BlockSn{Epoch{2, 1}, 16}, fns)

	// notarize first 2 blocks, check notarization head and finalized head
	err = bc.AddNotarization(&NotarizationFake{BlockSn{epoch, 1}, voterIds})
	req.NoError(err)
	b = (<-ch).Block

	err = bc.AddNotarization(&NotarizationFake{BlockSn{epoch, 2}, voterIds})
	req.NoError(err)
	b = (<-ch).Block

	fns = bc.GetFreshestNotarizedHeadSn()
	req.Equal(BlockSn{Epoch{3, 1}, 2}, fns)

	fns = bc.GetFinalizedHeadSn()
	req.Equal(BlockSn{Epoch{3, 1}, 1}, fns)

	// add notarization for (3, 1, 1) to (3, 1, 16), newest block should be (3, 1, 17)
	for i := uint32(3); i <= notaEnd; i++ {
		err = bc.AddNotarization(&NotarizationFake{BlockSn{epoch, i}, voterIds})
		req.NoError(err)
		b = (<-ch).Block
	}

	err = bc.StopCreatingNewBlocks(WaitingPeriodForStopingNewBlocks)
	req.NoError(err)

	// verify newest block is (3, 1, 17)
	req.Equal(BlockSn{epoch, notaEnd + kAtSession3}, b.GetBlockSn())
}

func TestBlockMakerImpWithConsensusInfoInHeader(t *testing.T) {
	req := require.New(t)
	numTx := uint64(6000)
	if testutils.RaceEnabled {
		numTx = 600
	}
	if testing.Short() {
		numTx = numTx / 20
	}
	unnotarizedWindow := uint32(3)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(unnotarizedWindow), 0)

	epoch := NewEpoch(1, 1)
	bc, memdb, thunderCfg := setup(t, numTx, hardforkK)

	thunderCfg.IsConsensusInfoInHeader.SetTestValueAtSession(true, 0)

	// Create the blocks.
	var b Block
	ch, err := bc.StartCreatingNewBlocks(epoch, nil)
	req.NoError(err)
	defer func() {
		if bc.IsCreatingBlock() {
			err = bc.StopCreatingNewBlocks(WaitingPeriodForStopingNewBlocks)
			req.NoError(err)
		}
	}()
	for i := uint32(0); i < unnotarizedWindow; i++ {
		b = (<-ch).Block
		fmt.Printf("get block: %d\n", b.GetNumber())
		req.Equal(BlockSn{epoch, i + 1}, b.GetBlockSn())
	}
	// Expect the blockchain blocks because there is no notarization.
	select {
	case <-ch:
		t.FailNow()
	case <-time.After(100 * time.Millisecond):
	}

	// Add notarization, so BlockChain can create new blocks.
	voterIds := []ConsensusId{"v1"}
	notaEnd := uint32(256)

	if testing.Short() {
		notaEnd = uint32(16)
	}

	for i := uint32(1); i <= notaEnd; i++ {
		err = bc.AddNotarization(&NotarizationFake{BlockSn{epoch, i}, voterIds})
		req.NoError(err)
		b = (<-ch).Block
	}

	req.Equal(BlockSn{epoch, notaEnd + unnotarizedWindow}, b.GetBlockSn())
	decoder := NewBlockImplDecoder(hardforkK, &DataUnmarshallerFake{}, nil)
	// Expect transaction data in extra field of header
	req.True(len(b.(*blockImpl).B.Header().Extra) > 0, "Extra is empty %v", b.GetDebugString())
	notas := decoder.GetNotarizations(b, bc.(*BlockChainImpl).storage.GetThunderConfig())
	req.Equal(1, len(notas), "Fail to get nota from %s", b.GetBlockSn())
	// Expect storing the "parent-k"'s notarization.
	req.Equal(BlockSn{epoch, notaEnd}, notas[0].GetBlockSn())
	err = bc.StopCreatingNewBlocks(WaitingPeriodForStopingNewBlocks)
	req.NoError(err)
	// Expect created blocks are already inserted.
	for i := uint32(1); i <= uint32(notaEnd+unnotarizedWindow); i++ {
		b = bc.GetBlock(BlockSn{epoch, i})
		req.NotNil(b)
		req.Equal(BlockSn{epoch, i}, b.GetBlockSn())
	}

	// Create the blocks at the next epoch.
	err = bc.AddNotarization(&NotarizationFake{BlockSn{epoch, notaEnd + 1}, voterIds})
	req.NoError(err)

	epoch = epoch.NextEpoch()
	fnc := bc.GetFreshestNotarizedHead()
	ch, err = bc.StartCreatingNewBlocks(epoch, NewClockMsgNotaFake(epoch, voterIds))
	req.NoError(err)
	defer func() {
		err = bc.StopCreatingNewBlocks(WaitingPeriodForStopingNewBlocks)
		req.NoError(err)
	}()
	b = (<-ch).Block
	req.NotNil(b)
	req.Equal(BlockSn{epoch, 1}, b.GetBlockSn())
	req.Equal(fnc.GetBlockSn(), b.GetParentBlockSn())

	// Expect the first block contains previous blocks' notarizations.
	notas = decoder.GetNotarizations(b, bc.(*BlockChainImpl).storage.GetThunderConfig())
	req.Equal(unnotarizedWindow, uint32(len(notas)))
	pe, _ := epoch.PreviousEpoch()

	for i := uint32(0); i < unnotarizedWindow; i++ {
		req.Equal(BlockSn{pe, notaEnd + 1 - i}, notas[unnotarizedWindow-i-1].GetBlockSn())
	}

	for i := uint32(2); i <= unnotarizedWindow; i++ {
		b := (<-ch).Block
		req.NotNil(b)
		req.Equal(BlockSn{epoch, i}, b.GetBlockSn())

		hashn := rawdb.ReadCanonicalHash(memdb, uint64(notaEnd+1+i))
		req.Equal((common.Hash{}), hashn)
	}
}

func TestMakingBlockWithRandomCrash(t *testing.T) {
	req := require.New(t)

	db, _, err := NewThunderSinceGenesisWithMemDb()
	req.NoError(err)

	crashingDB := NewCrashingMemoryDb(t, db)
	crashTimes := uint32(100)

	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(1, 0)

	for i := uint32(1); i < crashTimes; i++ {
		tryCrashAndRecovery(t, crashingDB, NewEpoch(1, i))
	}

	chain := NewThunderWithExistingDb(t, db)
	bc, err := NewBlockChainWithFakeNota(hardforkK, db, chain, BuildTxPool(chain), nil, blockTime)
	req.NoError(err)
	t.Logf("Progress to %d", bc.GetFreshestNotarizedHeadSn())
	req.True(bc.GetFreshestNotarizedHeadSn().Compare(GetGenesisBlockSn()) > 0, "No progress")
	b := newBlock(chain.CurrentBlock(), chain.Config().Thunder)

	req.Zero(bc.GetFreshestNotarizedHeadSn().Compare(b.GetBlockSn()), "Notarization doesn't match")
}

func tryCrashAndRecovery(t *testing.T, db ethdb.Database, epoch Epoch) {
	req := require.New(t)
	unnotarizedWindow := uint32(1)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(unnotarizedWindow), 0)

	var sn BlockSn
	defer func() {
		if caught := recover(); caught != nil {
			// If you have to check the stack trace, follow this code.
			//	buf := make([]byte, 1024*1024)
			//	buf = buf[:runtime.Stack(buf, false)]
			// t.Logf("Panic Recover (%s)!! %q stack := \n%s", sn, caught, string(buf))
		}
	}()
	chain := NewThunderWithExistingDb(t, db)
	txpool := BuildTxPool(chain)
	bc, err := NewBlockChainWithFakeNota(hardforkK, db, chain, txpool, nil, blockTime)
	req.NoError(err)

	b := newBlock(chain.CurrentBlock(), chain.Config().Thunder)
	req.Zero(bc.GetFreshestNotarizedHeadSn().Compare(b.GetBlockSn()), "Notarization doesn't match")

	blkmaker := bc.(*BlockChainImpl).GetBlockMakerForTest().(*BlockMakerImpl)
	block := bc.GetFreshestNotarizedHead()
	stopEvent := make(chan struct{})
	blkmaker.notaChan = make(chan Notarization, 1024)
	for i := uint32(1); ; i++ {
		sn = BlockSn{Epoch: epoch, S: i}
		block, err = blkmaker.MakeSingleBlock(
			block,
			sn,
			NewClockMsgNotaFake(epoch, []ConsensusId{}),
			stopEvent)

		req.NoError(err)
		nota := NewNotarizationFake(sn, []ConsensusId{})
		err = bc.AddNotarization(nota)
		req.NoError(err)
		blkmaker.notaChan <- nota
	}
}

func TestBlockMakerImpGasLimit(t *testing.T) {
	t.Logf("Start %s", t.Name())
	req := require.New(t)

	maxTxPerBlock := 30
	gasLimit := protocol.BlockGasLimit.GetValueAt(1)
	protocol.BlockGasLimit.SetTestValueAt(int64(int(params.TxGas)*maxTxPerBlock), 1)
	defer func() {
		protocol.BlockGasLimit.SetTestValueAt(gasLimit, 1)
	}()

	epoch := NewEpoch(1, 1)
	numTx := uint64(maxTxPerBlock * 10)
	unnotarizedWindow := uint32(1)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(unnotarizedWindow), 0)

	bc, _, _ := setup(t, numTx, hardforkK)

	// Create the blocks.
	var b Block
	voterIds := MakeConsensusIds(strings.Repeat("v", 60))
	var cn ClockMsgNota
	bc2, _, _ := setup(t, 0, hardforkK)

	for trial := 0; trial < 3; trial++ {
		ch, err := bc.StartCreatingNewBlocks(epoch, cn)
		req.NoError(err)
		b = (<-ch).Block
		req.Equal(BlockSn{epoch, 1}, b.GetBlockSn())
		// Expect the blockchain blocks because there is no notarization.
		select {
		case <-ch:
			t.FailNow()
		case <-time.After(100 * time.Millisecond):
		}

		for i := uint32(1); i < 10; i++ {
			err = bc.AddNotarization(&NotarizationFake{BlockSn{epoch, i}, voterIds})
			req.NoError(err)
			b = (<-ch).Block
			req.Equal(epoch, b.GetBlockSn().Epoch, b.GetBlockSn())
		}
		err = bc.StopCreatingNewBlocks(WaitingPeriodForStopingNewBlocks)
		req.NoError(err)

		for i := uint32(1); i <= 10; i++ {
			// Expect created blocks are already inserted.
			b = bc.GetBlock(BlockSn{epoch, i})
			req.NotNil(b)
			req.Equal(BlockSn{epoch, i}, b.GetBlockSn())

			// Test adding to another chain.
			err := bc2.InsertBlock(b, false)
			req.NoError(err, fmt.Sprintf("sn=%s", b.GetBlockSn()))

			req.GreaterOrEqual(
				int((protocol.BlockGasLimit.GetValueAtU64(1)-getMaxConsensusTxGas(unnotarizedWindow))/params.TxGas)+1,
				len(b.(*blockImpl).B.Transactions()),
				b.GetBlockSn())
		}

		// Now we test the block after timeout, it may contain more (k * nota + clock)
		epoch = epoch.NextEpoch()
		cn = NewClockMsgNotaFake(epoch, voterIds)
	}
}

func TestBlockMakerImpl_checkStopCondition(t *testing.T) {
	type fields struct {
		bc       *core.BlockChain
		k        uint32
		txpool   *core.TxPool
		signer   types.Signer
		stopChan chan struct{}
		notaChan chan Notarization
		storage  *StorageImpl
	}
	type args struct {
		ticker        <-chan time.Time
		blockOutOfGas bool
		notaChan      <-chan Notarization
		stopChan      <-chan struct{}
		context       *blockContext
		sn            BlockSn
	}

	req := require.New(t)

	unnotarizedWindow := uint32(3)
	hardforkK := config.NewInt64HardforkConfig("consensus.k", "")
	hardforkK.SetTestValueAtSession(int64(unnotarizedWindow), 0)

	thunderCfg := newThunderConfig()
	thunderEngine := thunder.New(thunderCfg)
	memdb, chain, err := core.NewThunderCanonical(thunderEngine, 0, true)
	chain.Config().Thunder = thunderCfg
	req.NoError(err)
	txpool := BuildTxPool(chain)
	smallSn := NewBlockSn(1, 1, 1)
	largeSn := NewBlockSn(1, 1, unnotarizedWindow+1)
	storage := NewStorage(StorageConfig{
		Db:                memdb,
		Bc:                chain,
		Marshaller:        &DataUnmarshallerFake{},
		PalaFromGenesis:   true,
		UnnotarizedWindow: hardforkK,
	})

	makeTickedTimer := func() chan time.Time {
		r := make(chan time.Time, 1)
		r <- time.Now()
		return r
	}

	makeTriggeredStopChannel := func() chan struct{} {
		r := make(chan struct{}, 1)
		r <- struct{}{}
		return r
	}

	makeIncomingNotaChannel := func(sn BlockSn) chan Notarization {
		r := make(chan Notarization, 1)
		r <- NewNotarizationFake(sn, MakeConsensusIds())
		return r
	}

	makeUnExpectedNotaChannel := func(sn BlockSn) chan Notarization {
		r := make(chan Notarization, 3)
		r <- NewNotarizationFake(largeSn, MakeConsensusIds())
		r <- NewNotarizationFake(largeSn, MakeConsensusIds())
		r <- NewNotarizationFake(sn, MakeConsensusIds())
		return r
	}

	tests := []struct {
		name     string
		fields   fields
		args     args
		want     StopCondition
		expectEq bool
	}{
		{
			name: "stop by timers",
			fields: fields{
				bc:      chain,
				k:       unnotarizedWindow,
				txpool:  txpool,
				signer:  types.NewEIP155Signer(chain.Config().ChainID),
				storage: storage,
			},
			args: args{
				ticker:        makeTickedTimer(),
				blockOutOfGas: false,
				notaChan:      make(chan Notarization, 1),
				stopChan:      make(chan struct{}, 1),
				sn:            smallSn,
			},
			want:     DeliverNow,
			expectEq: true,
		},
		{
			name: "stop by gas limit still need timer tick",
			fields: fields{
				bc:      chain,
				k:       unnotarizedWindow,
				txpool:  txpool,
				signer:  types.NewEIP155Signer(chain.Config().ChainID),
				storage: storage,
			},
			args: args{
				ticker:        makeTickedTimer(),
				blockOutOfGas: true,
				notaChan:      make(chan Notarization, 1),
				stopChan:      make(chan struct{}, 1),
				sn:            smallSn,
			},
			want:     DeliverNow,
			expectEq: true,
		},
		{
			name: "stop by stop channel",
			fields: fields{
				bc:      chain,
				k:       unnotarizedWindow,
				txpool:  txpool,
				signer:  types.NewEIP155Signer(chain.Config().ChainID),
				storage: storage,
			},
			args: args{
				ticker:        make(chan time.Time, 1),
				blockOutOfGas: false,
				notaChan:      make(chan Notarization, 1),
				stopChan:      makeTriggeredStopChannel(),
				sn:            smallSn,
			},
			want:     StopMaking,
			expectEq: true,
		},

		{
			name: "large sn stop by timers",
			fields: fields{
				bc:      chain,
				k:       unnotarizedWindow,
				txpool:  txpool,
				signer:  types.NewEIP155Signer(chain.Config().ChainID),
				storage: storage,
			},
			args: args{
				ticker:        makeTickedTimer(),
				blockOutOfGas: false,
				notaChan:      make(chan Notarization, 1),
				stopChan:      make(chan struct{}, 1),
				sn:            largeSn,
			},
			want:     ContinueMaking,
			expectEq: false, // the only case timer changes.
		},
		{
			name: "large sn stop by timers with nota",
			fields: fields{
				bc:      chain,
				k:       unnotarizedWindow,
				txpool:  txpool,
				signer:  types.NewEIP155Signer(chain.Config().ChainID),
				storage: storage,
			},
			args: args{
				ticker:        makeTickedTimer(),
				blockOutOfGas: false,
				notaChan:      makeIncomingNotaChannel(smallSn),
				stopChan:      make(chan struct{}, 1),
				sn:            largeSn,
			},
			want:     DeliverNow,
			expectEq: true,
		},
		{
			name: "large sn stop by timers with nota noise",
			fields: fields{
				bc:      chain,
				k:       unnotarizedWindow,
				txpool:  txpool,
				signer:  types.NewEIP155Signer(chain.Config().ChainID),
				storage: storage,
			},
			args: args{
				ticker:        makeTickedTimer(),
				blockOutOfGas: false,
				notaChan:      makeUnExpectedNotaChannel(smallSn),
				stopChan:      make(chan struct{}, 1),
				sn:            largeSn,
			},
			want:     ContinueMaking,
			expectEq: false,
		},
		{
			name: "large sn stop by gas limit and nota still but need timer",
			fields: fields{
				bc:      chain,
				k:       unnotarizedWindow,
				txpool:  txpool,
				signer:  types.NewEIP155Signer(chain.Config().ChainID),
				storage: storage,
			},
			args: args{
				ticker:        makeTickedTimer(),
				blockOutOfGas: true,
				notaChan:      makeIncomingNotaChannel(smallSn),
				stopChan:      make(chan struct{}, 1),
				sn:            largeSn,
			},
			want:     DeliverNow,
			expectEq: true,
		},
		{
			name: "large sn stop by gas limit and timer, but with some noise in nota channel",
			fields: fields{
				bc:      chain,
				k:       unnotarizedWindow,
				txpool:  txpool,
				signer:  types.NewEIP155Signer(chain.Config().ChainID),
				storage: storage,
			},
			args: args{
				ticker:        makeTickedTimer(),
				blockOutOfGas: true,
				notaChan:      makeUnExpectedNotaChannel(smallSn),
				stopChan:      make(chan struct{}, 1),
				sn:            largeSn,
			},
			want:     DeliverNow,
			expectEq: true,
		},
		{
			// random factor here due to select{} would random the order
			name: "large sn stop by gas limit and stop channel",
			fields: fields{
				bc:      chain,
				k:       unnotarizedWindow,
				txpool:  txpool,
				signer:  types.NewEIP155Signer(chain.Config().ChainID),
				storage: storage,
			},
			args: args{
				ticker:        make(chan time.Time, 1),
				blockOutOfGas: true,
				notaChan:      make(chan Notarization, 1),
				stopChan:      makeTriggeredStopChannel(),
				sn:            largeSn,
			},
			want:     StopMaking,
			expectEq: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := config.NewInt64HardforkConfig("consensus.k", "")
			k.SetTestValueAtSession(int64(tt.fields.k), 0)

			bm := &BlockMakerImpl{
				bc:       tt.fields.bc,
				txpool:   tt.fields.txpool,
				stopChan: tt.fields.stopChan,
				notaChan: tt.fields.notaChan,
				storage:  tt.fields.storage,
				k:        k,
			}
			req = require.New(t)
			got, gotChan := bm.checkStopCondition(tt.args.ticker, tt.args.blockOutOfGas, tt.args.notaChan, tt.args.stopChan, nil, tt.args.sn)
			req.Equal(got, tt.want, "BlockMakerImpl.checkStopCondition() got = %v, want %v", got, tt.want)

			if tt.expectEq {
				req.Equal(gotChan, tt.args.ticker)
			} else {
				req.NotEqual(gotChan, tt.args.ticker)
			}
		})
	}
}
