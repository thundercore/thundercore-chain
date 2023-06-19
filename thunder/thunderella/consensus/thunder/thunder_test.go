package thunder

import (
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/thunder/thunderella/config"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	config.InitThunderConfig("../../../../config")
	os.Exit(m.Run())
}

func TestAuthor(t *testing.T) {
	assert := assert.New(t)

	thunder := New(&params.ThunderConfig{})

	coinbase, err := thunder.Author(nil)

	assert.Equal(coinbase, defaultCoinbaseAddress, "error")
	assert.Equal(err, nil, "error")
}

func TestCalcDifficulty(t *testing.T) {
	assert := assert.New(t)

	var difficulty *big.Int

	thunder := New(&params.ThunderConfig{})

	difficulty = thunder.CalcDifficulty(nil, 0, nil)

	assert.Equal(difficulty.Int64(), int64(0), "error")
}

func makeNewHeader(blockchain *core.BlockChain) *types.Header {

	currBlock := blockchain.CurrentBlock()
	header := &types.Header{
		Number:     new(big.Int).Add(currBlock.Number(), common.Big1),
		ParentHash: currBlock.Hash(),
		Time:       currBlock.Time() + 1,
	}

	return header
}

func TestThunderPrepare(t *testing.T) {

	assert := assert.New(t)

	_, blockchain, _ := MakeThunderTestChain()
	thunder := GetThunderEngine(blockchain)
	header := makeNewHeader(blockchain)

	err := thunder.Prepare(blockchain, header)
	assert.Equal(err, nil)
	assert.Equal(header.UncleHash, zeroUncleHash)
	assert.Equal(header.Coinbase, defaultCoinbaseAddress)
	assert.Equal(header.Difficulty, unityDifficulty)
	assert.Equal(header.Extra, zeroExtraData)
	assert.Equal(header.Nonce, types.BlockNonce{0, 0, 0, 0, 0, 0, 0, 0})
}

func TestVerifyHeader(t *testing.T) {

	assert := assert.New(t)

	_, blockchain, _ := MakeThunderTestChain()
	thunder := GetThunderEngine(blockchain)
	header := makeNewHeader(blockchain)

	thunder.Prepare(blockchain, header)

	err := thunder.VerifyHeader(blockchain, header, false)
	assert.Equal(err, nil)

	err = thunder.VerifyHeader(blockchain, header, true)
	assert.Equal(err, nil)

	header.Number = nil
	assert.Equal(thunder.VerifyHeader(blockchain, header, false), errUnknownBlock)

	header.Number = big.NewInt(100)
	assert.Equal(thunder.VerifyHeader(blockchain, header, false), consensus.ErrInvalidNumber)

	header.GasUsed = header.GasLimit + 1
	assert.Errorf(thunder.VerifyHeader(blockchain, header, false),
		fmt.Sprintf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit))
}

func TestSeal(t *testing.T) {

	assert := assert.New(t)

	_, blockchain, _ := MakeThunderTestChain()
	thunder := GetThunderEngine(blockchain)
	header := makeNewHeader(blockchain)

	thunder.Prepare(blockchain, header)
	block := types.NewBlock(header, nil, nil, nil, trie.NewStackTrie(nil))

	results := make(chan *types.Block, 1)
	err := thunder.Seal(blockchain, block, results, nil)
	assert.Equal(err, nil)

	header.Number = big.NewInt(0)
	block = types.NewBlock(header, nil, nil, nil, trie.NewStackTrie(nil))

	err = thunder.Seal(blockchain, block, results, nil)
	assert.Error(err, errSealOperationOnGenesisBlock)
}

func TestMakeThunderTestChainWithBlocks(t *testing.T) {
	// TODO (thunder) make this test work
	// this will crash due to genesis comm info not being set in thunder consensus engine
	// couldn't think of a good place to set it without running into circular dependency issues

	//assert := assert.New(t)
	//_, chain, err := MakeThunderTestChainWithBlocks(100)
	//assert.NoError(err, "expected no error")
	//assert.Equal(chain.CurrentHeader().Number, 100, "expected blocks")

}
