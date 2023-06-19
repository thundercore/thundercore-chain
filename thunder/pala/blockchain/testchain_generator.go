package blockchain

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/testutils"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/ethdb"
	"golang.org/x/xerrors"
)

const defaultNTxPerBlock = 100

func dumpSns(sns []Block) (output []string) {
	for _, sn := range sns {
		output = append(output, sn.GetBlockSn().String())
	}

	for i, j := 0, len(output)-1; i < j; i, j = i+1, j-1 {
		output[i], output[j] = output[j], output[i]
	}

	return output
}

// PrettifyChain prints the chain in a human readable format
func PrettifyChain(chain BlockChain, tails ...BlockSn) {
	epochMap := make(map[Epoch][]Block)

	// sort tails by epoch
	for _, tail := range tails {
		b := chain.GetBlock(tail)
		for {
			if b == nil || b.GetBlockSn() == GetGenesisBlockSn() {
				break
			}
			sn := b.GetBlockSn()
			epochMap[sn.Epoch] = append(epochMap[sn.Epoch], b)
			p := chain.GetBlock(b.GetParentBlockSn())
			if p.GetBlockSn().Epoch != b.GetBlockSn().Epoch {
				break
			}
			b = p
		}
	}

	// sort epochs by session and epoch
	orderedE := []Epoch{}
	for k := range epochMap {
		orderedE = append(orderedE, k)
	}
	sort.Slice(orderedE, func(i, j int) bool {
		return orderedE[i].Session < orderedE[j].Session || orderedE[i].E < orderedE[j].E
	})

	lines := []string{}
	epochLineIndex := make(map[Epoch]int)
	for i, e := range orderedE {
		sns := epochMap[e]
		if i == 0 {
			lines = append(lines, strings.Join(dumpSns(sns), "->"))
		} else {
			first := sns[len(sns)-1] // because blocks are reversed in list
			parent := chain.GetBlock(first.GetParentBlockSn())
			idx := epochLineIndex[parent.GetBlockSn().Epoch]
			blankNum := strings.Index(lines[idx], parent.GetBlockSn().String())

			blank := "   " // Move to center of BlockSn string
			for i := 0; i < blankNum; i++ {
				blank += " "
			}
			lines = append(lines, fmt.Sprintf("%s----->%s", blank, strings.Join(dumpSns(sns), "->")))
		}
		epochLineIndex[e] = i
	}

	fmt.Println(lines[0])
	if len(lines) == 1 {
		return
	}

	lines = lines[1:]
	sort.Slice(lines, func(i, j int) bool {
		return strings.Index(lines[i], "-") < strings.Index(lines[j], "-")
	})

	output := []string{}
	vertLineIndexes := []int{}
	for _, line := range lines {
		newLine := line
		for _, index := range vertLineIndexes {
			newLine = line[:index] + "|" + line[index+1:]
		}
		vertLineIndexes = append(vertLineIndexes, strings.Index(line, "-"))
		output = append(output, newLine)

		var gap string
		for i := 0; i < len(line); i++ {
			gap = gap + " "
		}
		newGap := false
		for _, index := range vertLineIndexes {
			gap = gap[:index] + "|" + gap[index+1:]
			newGap = true
		}
		if newGap {
			output = append(output, gap)
		}
	}

	for i, j := 0, len(output)-1; i < j; i, j = i+1, j-1 {
		output[i], output[j] = output[j], output[i]
	}
	fmt.Println(strings.Join(output, "\n"))
}

type ChainGenerator interface {
	Init(BlockSn) error
	Branch(BlockSn, BlockSn) error
	MakeBlocks(beginBlock Block, blockSns []BlockSn) ([]Block, error)
	NotarizeTail(BlockSn) error

	GetChain() BlockChain
	GetTails() []BlockSn
	GetUnnotarizedWindow() *config.Int64HardforkConfig
	SetVoters([]ConsensusId)
	SetTxsPerBlock(n int)
}

func PrettifyChainGenerator(c ChainGenerator) {
	chain := c.GetChain()
	tails := c.GetTails()
	PrettifyChain(chain, tails...)
}

type FakeChainGenerator struct {
	k *config.Int64HardforkConfig

	chain  BlockChain
	voters []ConsensusId

	// For better debuging
	tails []BlockSn
}

func (c *FakeChainGenerator) GetChain() BlockChain {
	return c.chain
}

func (c *FakeChainGenerator) GetUnnotarizedWindow() *config.Int64HardforkConfig {
	return c.k
}

func (c *FakeChainGenerator) SetVoters(voters []ConsensusId) {
	c.voters = voters
}

func (c *FakeChainGenerator) SetTxsPerBlock(n int) { panic("not implemented") }

func (c *FakeChainGenerator) GetTails() []BlockSn {
	return c.tails
}

func (c *FakeChainGenerator) Init(end BlockSn) error {
	return c.Branch(BlockSn{Epoch: end.Epoch, S: uint32(1)}, end)
}

func (c *FakeChainGenerator) Branch(begin, end BlockSn) error {
	c.tails = append(c.tails, end)

	var beginS uint32
	if begin.Epoch != end.Epoch {
		// Add new branch, S starts from 1
		beginS = uint32(1)
	} else {
		beginS = begin.S
	}

	blockSns := []BlockSn{}
	for s := beginS; s <= end.S; s++ {
		blockSns = append(blockSns, BlockSn{Epoch: end.Epoch, S: s})
	}

	var parent Block
	b := c.chain.GetBlock(begin)
	if b == nil {
		parent = c.chain.GetFreshestNotarizedHead()
	} else {
		parent = c.chain.GetBlock(begin)
	}

	blocks, err := c.MakeBlocks(parent, blockSns)
	if err != nil {
		return err
	}

	for _, blk := range blocks {
		if c.chain.InsertBlock(blk, false) != nil {
			return err
		}
	}

	return nil
}

func (c *FakeChainGenerator) MakeBlocks(beginBlock Block, blockSns []BlockSn) ([]Block, error) {
	var ret []Block

	parent := beginBlock

	for _, bs := range blockSns {
		notas := make([]Notarization, 0)
		var cNota ClockMsgNota
		k := uint32(c.k.GetValueAtSession(int64(bs.Epoch.Session)))

		if bs.S == 1 {
			np := parent
			for j := uint32(0); j < k && np != nil && !np.GetBlockSn().Epoch.IsNil(); j++ {
				notas = append(notas, NewNotarizationFake(np.GetBlockSn(), c.voters))
				np = GetParentBlock(c.chain, np)
			}
			reverse(notas)
			if bs.Epoch.E > 1 {
				cNota = NewClockMsgNotaFake(bs.Epoch, c.voters)
			}
		}

		if bs.S > k {
			notas = append(notas, NewNotarizationFake(BlockSn{Epoch: bs.Epoch, S: bs.S - k}, c.voters))
		}

		nb := NewBlockFake(bs, parent.GetBlockSn(), parent.GetNumber()+1, notas, cNota, bs.String())
		ret = append(ret, nb)

		parent = nb
	}

	return ret, nil
}

func (c *FakeChainGenerator) NotarizeTail(tail BlockSn) error {
	head := c.chain.GetFreshestNotarizedHeadSn()
	b := c.chain.GetBlock(tail)
	var notas []Notarization
	for b.GetBlockSn().Compare(head) > 0 {
		notas = append(notas, NewNotarizationFake(b.GetBlockSn(), c.voters))
		b = GetParentBlock(c.chain, b)
	}
	for i := len(notas) - 1; i >= 0; i-- {
		if err := c.chain.AddNotarization(notas[i]); err != nil {
			return err
		}
	}
	newHead := c.chain.GetFreshestNotarizedHeadSn()
	if newHead != tail {
		return xerrors.Errorf("failed to update the freshest notarized head: "+
			"new head is %s; old head is %s", newHead, head)
	}
	return nil
}

type RealChainGenerator struct {
	k *config.Int64HardforkConfig

	chain  BlockChain
	voters []ConsensusId

	// For better debuging
	tails []BlockSn

	// Additional component for real chain
	coreChain *core.BlockChain
	chainDB   ethdb.Database

	nTxPerBlock int
}

func (c *RealChainGenerator) Init(end BlockSn) error {
	return c.Branch(BlockSn{Epoch: end.Epoch, S: uint32(1)}, end)
}

func (c *RealChainGenerator) GetChain() BlockChain {
	return c.chain
}

func (c *RealChainGenerator) GetUnnotarizedWindow() *config.Int64HardforkConfig {
	return c.k
}

func (c *RealChainGenerator) SetVoters(voters []ConsensusId) {
	c.voters = voters
}

func (c *RealChainGenerator) GetTails() []BlockSn {
	return c.tails
}

func (c *RealChainGenerator) Branch(begin, end BlockSn) error {
	c.tails = append(c.tails, end)

	var beginS uint32
	if begin.Epoch != end.Epoch {
		// Add new branch, starts from S=1.
		beginS = uint32(1)
	} else {
		beginS = begin.S
	}

	blockSns := []BlockSn{}
	for s := beginS; s <= end.S; s++ {
		blockSns = append(blockSns, BlockSn{Epoch: end.Epoch, S: s})
	}

	beginBlock := c.chain.GetBlock(begin)
	if beginBlock == nil {
		beginBlock = c.chain.GetFreshestNotarizedHead()
	}

	blocks, err := c.MakeBlocks(beginBlock, blockSns)
	if err != nil {
		return xerrors.Errorf("make blocks failed: %v", err)
	}
	// fmt.Printf("Excepted: %v\n", blockSns)
	// fmt.Printf("Generated: ")
	// for _, blk := range blocks {
	// 	fmt.Printf("%v", blk.GetBlockSn().String())
	// }
	// fmt.Printf("\n")

	for _, blk := range blocks {
		// fmt.Printf("Hardfork %v %v\n", blk.GetNumber(), palaHardfork.GetValueAt(chain.Seq(blk.GetNumber())))
		err := c.chain.InsertBlock(blk, false)
		if err != nil {
			return xerrors.Errorf("insert block failed: %v", err)
		}
	}

	return nil
}

func (c *RealChainGenerator) MakeBlocks(beginBlock Block, blockSns []BlockSn) ([]Block, error) {
	blocks := GeneratePalaChain(
		c.coreChain,
		beginBlock.(*blockImpl).B,
		c.coreChain.Engine(),
		c.chainDB,
		len(blockSns),
		BlockGenWithConsensusTransaction(
			c.coreChain,
			blockSns,
			c.k,
			WithSimpleTransactionAndRandomBidForTest(c.nTxPerBlock, c.coreChain),
			true,
			c.voters,
		),
	)
	return blocks, nil
}

func (c *RealChainGenerator) NotarizeTail(tail BlockSn) error {
	debug.NotImplemented("TODO")
	return nil
}

func (c *RealChainGenerator) SetTxsPerBlock(n int) {
	c.nTxPerBlock = n
}

func NewChainGenerator(fakeChain bool, k *config.Int64HardforkConfig) (ChainGenerator, error) {
	if fakeChain {
		chain, err := NewBlockChainFake(k)
		if err != nil {
			return nil, err
		}

		return &FakeChainGenerator{
			chain: chain,
			k:     k,
		}, nil

	} else {
		memdb, coreChain, err := NewThunderSinceGenesisWithMemDb()
		if err != nil {
			return nil, err
		}

		chain, err := NewBlockChainWithFakeNota(k, memdb, coreChain, nil, nil, 100*time.Millisecond)
		if err != nil {
			return nil, err
		}

		return &RealChainGenerator{
			chain:     chain,
			k:         k,
			chainDB:   memdb,
			coreChain: coreChain,
		}, nil
	}
}

func NewRealChainGenerator(k *config.Int64HardforkConfig, chain BlockChain,
	coreChain *core.BlockChain, chainDB ethdb.Database) *RealChainGenerator {
	return &RealChainGenerator{
		k:           k,
		chain:       chain,
		coreChain:   coreChain,
		chainDB:     chainDB,
		nTxPerBlock: defaultNTxPerBlock,
	}
}

func NewChainGeneratorWithElection(k *config.Int64HardforkConfig) (ChainGenerator, error) {
	memdb, coreChain, err := NewThunderSinceGenesisWithMemDb()
	if err != nil {
		return nil, err
	}
	sessionOffsetForTest := testutils.NewElectionStopBlockSessionOffsetForTest(5, 0)

	chain, err := NewBlockChainWithFakeNota(k, memdb, coreChain, nil, sessionOffsetForTest, 100*time.Millisecond)
	if err != nil {
		return nil, err
	}

	return &RealChainGenerator{
		chain:       chain,
		k:           k,
		chainDB:     memdb,
		coreChain:   coreChain,
		nTxPerBlock: defaultNTxPerBlock,
	}, nil
}

func NewChainGeneratorWithExistedFakeChain(chain BlockChain, k *config.Int64HardforkConfig) ChainGenerator {
	return &FakeChainGenerator{
		chain: chain,
		k:     k,
	}
}

func NewChainGeneratorByEthBackend(ethBackend *eth.Ethereum, k *config.Int64HardforkConfig) ChainGenerator {
	chainDb, coreChain := ethBackend.ChainDb(), ethBackend.BlockChain()

	chain, _ := NewBlockChainWithFakeNota(k, chainDb, coreChain, nil, nil, 100*time.Millisecond)
	return &RealChainGenerator{
		chain:       chain,
		k:           k,
		chainDB:     chainDb,
		coreChain:   coreChain,
		nTxPerBlock: defaultNTxPerBlock,
	}
}
