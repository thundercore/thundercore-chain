package blockchain

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	"github.com/ethereum/go-ethereum/thunder/thunderella/election"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/thundervm"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
)

func addStakeinBalance(addrs []common.Address, state *state.StateDB, value *big.Int) error {
	for _, addr := range addrs {
		state.AddBalance(addr, value)
	}
	return nil
}

func updateVault(stateDb vm.StateDB, ci *committee.CommInfo, addrs []common.Address, value *big.Int) error {
	if len(ci.MemberInfo) != len(addrs) {
		debug.Bug("len(newCommInfo) != len(stakeinAddrs), %d != %d", len(ci.MemberInfo), len(addrs))
	}
	// See `(*VaultTPC).abiCreateAccount` in `vault.go`
	for i, m := range ci.MemberInfo {
		addr := addrs[i]
		// See `(*VaultTPC).abiBid` in `vault.go`
		keyHash := common.Hash(sha256.Sum256(m.PubVoteKey.ToBytes()))
		balanceTable := thundervm.Balances(stateDb)
		key := keyHash.Str()
		entry := thundervm.NewVaultBalanceEntry(addr /*only affects Vault.withdraw*/, addr)
		entry.Balance.Set(value)
		balanceTable.InsertOrReplace(key, entry.ToBytes())
	}
	return nil
}

func updateState(
	ethChain *core.BlockChain,
	number uint64,
	op func(state *state.StateDB, header *types.Header) error,
) (*types.Block, error) {
	blk := ethChain.GetBlockByNumber(number)
	if blk == nil {
		return nil, fmt.Errorf("Failed to get block by number %d", number)
	}
	header := blk.Header()
	state, err := ethChain.StateAt(header.Root)
	if err != nil {
		return nil, fmt.Errorf("Failed to get state of %x: %s", header.Root, err)
	}
	if err := op(state, header); err != nil {
		return nil, fmt.Errorf("Failed to update state: %s", err)
	}

	// Write the updates to the database.
	receipts := ethChain.GetReceiptsByHash(blk.Hash())
	logs := []*types.Log{}
	for _, receipt := range receipts {
		logs = append(logs, receipt.Logs...)
	}
	header.Root = state.IntermediateRoot(ethChain.Config().IsEIP158(header.Number))
	blk = types.NewBlock(header, blk.Transactions(), blk.Uncles(), receipts, trie.NewStackTrie(nil))
	if _, err := ethChain.WriteBlockWithState(blk, receipts, logs, state, false); err != nil {
		return nil, fmt.Errorf("Failed to write block with state: %s", err)
	}
	return blk, nil
}

func ReplaceCommitteeForTest(
	ethChain *core.BlockChain,
	db ethdb.Database,
	stakeInAddrs []common.Address,
	newCommInfo *committee.CommInfo,
	newEr *election.Result,
	writeLog func(s string) (int, error),
) (*election.Result, error) {
	marshaller := &DataUnmarshallerImpl{Config: ethChain.Config().Thunder}
	epocher := NewEpochManager(db, marshaller)
	session := epocher.GetEpoch().Session - 1
	writeLog(
		fmt.Sprintf("Updating session stop block number in session=%d with head=%s\n",
			session, ethChain.CurrentBlock().Hash().String()))
	header, _ := readSessionStopHeader(db, session)
	if header == nil {
		return nil, fmt.Errorf("cannot find stop block header for session %d", session)
	}
	stopBlockNumber := header.Number.Uint64()
	current := ethChain.CurrentHeader().Number.Uint64()

	parentBlk := ethChain.GetBlockByNumber(stopBlockNumber - 1)
	var blk *types.Block
	var err error
	thunderCfg := &params.ThunderConfig{
		PalaBlock: big.NewInt(1),
	}
	var er *election.Result
	// Update ethereum blockchain from the latest stop block to the head.
	for i := stopBlockNumber; i <= current; i++ {
		blk, err = updateState(ethChain, i, func(state *state.StateDB, header *types.Header) error {
			writeLog(fmt.Sprintf("> updating block number %d\n", i))
			if er == nil {
				er = thundervm.GetCurrentElectionResult(state)
			}

			// All new blocks have new parents.
			header.ParentHash = parentBlk.Hash()

			// Update election result.
			thundervm.SetCurrentElectionResult(state, newEr)

			// Add stakein accounts' balances and update stakes in the vault.
			// TODO: move balance from existing accounts
			v := big.NewInt(10)
			v.Exp(v, big.NewInt(24), nil) // 10**24
			addStakeinBalance(stakeInAddrs, state, v)

			stakeTable := thundervm.StakeMessages(state)
			stakeTable.Clear()
			err = updateVault(state, newCommInfo, stakeInAddrs, v)
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return nil, err
		}

		// Update mapping BlockSn -> block hash
		if err := writeBlockMeta(db, newBlock(blk, thunderCfg)); err != nil {
			return nil, err
		}

		parentBlk = blk
	}

	// Update the head, so all new blocks will belong the canonical chain.
	if err := ethChain.WriteKnownBlock(blk); err != nil {
		return nil, fmt.Errorf("Failed to write known block: %s", err)
	}
	writeLog(fmt.Sprintf("Updated the head to %s",
		ethChain.CurrentBlock().Hash().String()))

	return er, nil
}
