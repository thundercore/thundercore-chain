// This tests thunder stuff in "github.com/ethereum/go-ethereum/core/vm"
// This needs to be here because it depends on state.StateDB to test stuff in vm module
package thundervm

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	thunderChain "github.com/ethereum/go-ethereum/thunder/thunderella/common/chain"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/election"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/testutils"

	// Vendor imports
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bid randomly in [MinBidderStake, MinBidderStake + n), expected to be accepted
func randomAvailableBid(req *require.Assertions, chain *core.BlockChain, state vm.StateDB, bidder testBidder, n int64) *election.StakeInfo {
	amount := big.NewInt(0).Add(big.NewInt(n),
		election.MinBidderStake.GetValueAt(thunderChain.Seq(chain.CurrentHeader().Number.Int64())))
	return makeBid(req, chain, state, bidder, election.MinBidPrice.GetValueAt(config.InitialBlockNum), amount, amount)
}

// send a bid message with `stake` as satke and `value` as value transferred
func makeBid(
	req *require.Assertions,
	chain *core.BlockChain,
	state vm.StateDB,
	bidder testBidder,
	gasPrice *big.Int,
	stake *big.Int,
	value *big.Int,
) *election.StakeInfo {

	from := bidder.addr
	to := commElectionAddress
	fmt.Print(value, chain.CurrentHeader().Number, "\n")
	nonce := uint64(0)

	stakeInfo := &election.StakeInfo{
		StakeMsg: election.StakeMsg{
			Stake:      stake,
			PubVoteKey: bidder.votekey.GetPublicKey(),
			Coinbase:   bidder.addr,
			GasPrice:   gasPrice,
		},
	}
	input, err := StakeMsgToBidCall(stakeInfo)
	req.Nil(err)

	msg := newFakeMessage(from, to, value, input, nonce)
	_, _, err = run(chain, state, msg)
	req.Nil(err)

	return stakeInfo
}

func testElect(req *require.Assertions, chain *core.BlockChain, state vm.StateDB, expectedSuccess bool) *election.Result {
	from := common.Address{}
	to := commElectionAddress
	value := big.NewInt(0)
	nonce := uint64(0)
	input := []byte{}
	msg := newFakeMessage(from, to, value, input, nonce)
	_, _, err := run(chain, state, msg)
	if expectedSuccess {
		req.Nil(err)
	} else {
		req.NotNil(err)
	}
	result := GetCurrentElectionResult(state)

	req.NotNil(result)
	req.NotZero(len(result.Members))

	return result
}

func TestCommElectionBid(t *testing.T) {
	req := require.New(t)

	chain, state := newEnv(0, 0, false)
	key, err := bls.NewSigningKey()
	req.Nil(err)
	bidAmount := election.MinBidderStake.GetValueAt(config.InitialBlockNum)

	// create the ethereum ABI call args
	stakeInfo := &election.StakeInfo{
		StakeMsg: election.StakeMsg{
			Stake:      bidAmount,
			PubVoteKey: key.GetPublicKey(),
			Coinbase:   testutils.TestingAddr,
			GasPrice:   election.MinBidPrice.GetValueAt(config.InitialBlockNum),
		},
		StakingAddr: testutils.TestingAddr,
	}
	// run the call
	{
		input, err1 := StakeMsgToBidCall(stakeInfo)
		req.Nil(err1)
		from := testutils.TestingAddr
		to := commElectionAddress
		value := bidAmount
		nonce := uint64(0)
		msg := newFakeMessage(from, to, value, input, nonce)
		_, _, err2 := run(chain, state, msg)
		req.Nil(err2)
	}

	// verify the results
	{
		bids, err := GetCurrentBids(state)
		req.Nil(err)
		req.Equal(1, len(bids))
		req.Equal(0, state.GetBalance(commElectionAddress).Cmp(bidAmount))
		req.Equal(bids[0].ToBytes(), stakeInfo.ToBytes())
	}

	{
		stakeTable := NewByteMap(commElectionAddress, state, electionStakeTablePrefix)
		var current stakeValue
		err := stakeTable.FindEntry(makeRefundKey(testutils.TestingAddr, []byte{}), &current)
		req.Nil(err)
		req.Equal(0, current.Value.Cmp(bidAmount))
	}

	// verify invalid bid should fail
	stakeInfo.GasPrice.SetInt64(0)
	{
		input, err1 := StakeMsgToBidCall(stakeInfo)
		req.Nil(err1)
		from := testutils.TestingAddr
		to := commElectionAddress
		value := bidAmount
		nonce := uint64(0)
		msg := newFakeMessage(from, to, value, input, nonce)
		_, _, err2 := run(chain, state, msg)
		req.NotNil(err2)
	}
}

func TestCommElection(t *testing.T) {
	// first transfer money to auctionStakeOverMinStakeRatio accounts
	req := require.New(t)
	chain, state := newEnv(0, 0, false)

	initFund := big.NewInt(50000)

	bidders := make([]testBidder, auctionStakeOverMinStakeRatio)

	for i := int64(0); i < auctionStakeOverMinStakeRatio; i++ {
		rand.Read(bidders[i].addr[:])
		bidders[i].votekey, _ = bls.NewSigningKey()
		state.SetBalance(bidders[i].addr, initFund)
	}

	minBidderStake := election.MinBidderStake.GetValueAt(config.InitialBlockNum)
	for i := 0; i < 5; i++ {
		for _, bidder := range bidders {
			randomAvailableBid(req, chain, state, bidder, 500)
		}

		result := testElect(req, chain, state, true)

		for _, member := range result.Members {
			req.Equal(0, member.GasPrice.Cmp(
				election.MinBidPrice.GetValueAt(config.InitialBlockNum)))
			req.True(member.Stake.Cmp(
				minBidderStake) >= 0)
			balance := state.GetBalance(member.Coinbase)
			req.Equal(initFund, big.NewInt(0).Add(balance, member.Stake))
		}
	}

	currentCommittee := GetCurrentElectionResult(state)

	for i := 0; i < 1; i++ {
		// only 10 bids, insufficient stake to form committee
		for j := 0; j < 10; j++ {
			randomAvailableBid(req, chain, state, bidders[j], 500)
		}

		result := testElect(req, chain, state, false)
		// should failed
		req.Equal(currentCommittee, result)
	}

	for i := 0; i < 2; i++ {
		for _, bidder := range bidders {
			randomAvailableBid(req, chain, state, bidder, 500)
		}

		result := testElect(req, chain, state, true)

		for _, member := range result.Members {
			req.Equal(0, member.GasPrice.Cmp(
				election.MinBidPrice.GetValueAt(config.InitialBlockNum)))
			req.True(member.Stake.Cmp(
				minBidderStake) >= 0)

			balance := state.GetBalance(member.Coinbase)
			req.Equal(initFund, big.NewInt(0).Add(balance, member.Stake))
		}
	}
}

// TestCommElectionBadInput tests for bad inputs
func TestCommElectionBadInput(t *testing.T) {
	assert := assert.New(t)
	chain, state := newEnv(0, 0, false)

	from := common.Address{}
	to := commElectionAddress
	value := big.NewInt(0)
	nonce := uint64(0)

	input := []byte{1, 2, 3}

	msg := newFakeMessage(from, to, value, input, nonce)
	_, _, err := run(chain, state, msg)
	assert.NotNil(err)
}

// TestCommElectionSameRefundIdMultipleKey test when the refund infomation on different votingKeys are the same,
// commElection will save the stake in the same container, but the bids are consider different.
// the lower priority bids will be disqualified but some higher bids can still utilize the stake.
func TestCommElectionSameRefundIdMultipleKey(t *testing.T) {
	// first transfer money to auctionStakeOverMinStakeRatio accounts
	req := require.New(t)
	chain, state := newEnv(0, 0, false)

	initFund := big.NewInt(50000 * auctionStakeOverMinStakeRatio)

	bidders := make([]testBidder, auctionStakeOverMinStakeRatio)
	theSameAddr := common.Address{}
	rand.Read(theSameAddr[:])

	for i := range bidders {
		bidders[i].addr = theSameAddr
		bidders[i].votekey, _ = bls.NewSigningKey()
		state.SetBalance(bidders[i].addr, initFund)
	}

	minBidderStake := election.MinBidderStake.GetValueAt(config.InitialBlockNum).Int64()
	gasPrice := election.MinBidPrice.GetValueAt(config.InitialBlockNum)

	// normal case, sufficient funds, expect election to succeed
	for i := 0; i < 5; i++ {
		for _, bidder := range bidders {
			randomAvailableBid(req, chain, state, bidder, 500)
		}

		result := testElect(req, chain, state, true)

		total := big.NewInt(0).Set(state.GetBalance(theSameAddr))
		for _, member := range result.Members {
			total.Add(total, member.Stake)
		}
		req.Equal(total, initFund)
	}

	// accumulated stake case, sufficient funds, expect election to succeed
	for i := 0; i < 5; i++ {
		for _, bidder := range bidders {
			// accumulated stake from all bids should be exactly enough for the high priority bid to succeed
			makeBid(req, chain, state, bidder, gasPrice, big.NewInt(minBidderStake*12), big.NewInt(minBidderStake))
		}

		result := testElect(req, chain, state, true)

		total := big.NewInt(0).Set(state.GetBalance(theSameAddr))
		for _, member := range result.Members {
			total.Add(total, member.Stake)
		}
		req.Equal(total, initFund)
	}

	// must do next test casewith new committee otherwise frozen stake from previous successful election will allow this to succeed
	rand.Read(theSameAddr[:])
	for i := range bidders {
		bidders[i].addr = theSameAddr
		bidders[i].votekey, _ = bls.NewSigningKey()
		state.SetBalance(bidders[i].addr, initFund)
	}

	// insufficient funds, expect election to fail
	for i := 0; i < 5; i++ {
		for _, bidder := range bidders {
			// accumulated stake from all bids insufficient
			makeBid(req, chain, state, bidder, gasPrice, big.NewInt(minBidderStake), big.NewInt(0))
		}

		testElect(req, chain, state, false)
	}

}

// TestCommElectionRefundReentrancy tests the case refund(...) calls back into bid() or getAvailableStake()
// expected to have bid() success like normal because refund(...) is the best timing to bid for the next round.
// expect the bid() called by refund() to fail, since gas limit of refund is limited.
func TestCommElectionRefundReentrancy(t *testing.T) {
	req := require.New(t)
	chain, state := newEnv(0, 0, false)

	bidders := [6]testBidder{}
	sol := `
pragma solidity ^0.4.25;
contract SingleRepeatBidder {
    bytes votingKey;
    function SingleRepeatBidder(bytes vk) payable {
        votingKey = vk;
        // using deployer's gas
        bid();
    }
    function bid() payable {
        address etpc = 0x30d87bd4D1769437880c64A543bB649a693EB348;
        bytes memory refundinfo = abi.encodeWithSignature("refund()");
        bytes memory getStakeInput = abi.encodeWithSignature("getAvailableStake(bytes)", refundinfo);
        uint gslen = getStakeInput.length;
        uint256[1] memory avStake;
        assembly {
            if iszero(call(not(0), etpc, 0, add(getStakeInput, 32), gslen, avStake, 32)) {
                revert(0, 0)
            }
        }
        uint256 stake = this.balance + avStake[0];
        uint256 bonus = stake - avStake[0];
        bytes memory input = abi.encodeWithSignature("bid(address,uint256,uint256,bytes,bytes)", this, stake, 10000000, votingKey, refundinfo);
        uint inlen = input.length;
        assembly {
            if iszero(call(not(0), etpc, bonus, add(input, /*BYTES_HEADER_SIZE*/32), inlen, 0x0, 0x0)) {
                revert(0,0)
            }
        }
    }
    function refund() {
        // using refunder's gas
        this.bid();
    }
}
`

	// bid
	for i := range bidders {
		bidders[i].votekey, _ = bls.NewSigningKey()
		keybytes := bidders[i].votekey.PublicKey.ToBytes()
		code := compileSol(req, "SingleRepeatBidder", sol, "0.4.25")
		input := mustDecode(code)
		input = append(input, common.BigToHash(big.NewInt(32)).Bytes()...)
		input = append(input, common.BigToHash(big.NewInt(int64(len(keybytes)))).Bytes()...)
		input = append(input, keybytes...)

		bidders[i].addr = testDeployContract(req, chain, state, testutils.TestingAddr, input, big.NewInt(10000))
	}

	// the first election will success, second election will fail due to all refund failed
	testElect(req, chain, state, true)
	testElect(req, chain, state, false)
}

// TestIndirectlyCommElection tests the case someone may try to trigger election via contract
func TestIndirectlyCommElection(t *testing.T) {
	req := require.New(t)
	chain, state := newEnv(0, 0, false)
	{
		sol := `
pragma solidity ^0.4.25;
contract A {
    function A() {
        address etpc = 0x30d87bd4D1769437880c64A543bB649a693EB348;
        assembly {
            if iszero(call(not(0), etpc, 0, 0, 0, 0, 0)) {
                revert(0, 0)
            }
        }
    }
}
`
		code := compileSol(req, "A", sol, "0.4.25")
		input := mustDecode(code)
		from := testutils.TestingAddr
		to := from         // Don't care, we separate functions
		nonce := uint64(1) // It matters here because contract create by Address + nonce
		value := big.NewInt(0)
		msg := newFakeMessage(from, to, value, input, nonce)
		_, err := createContract(chain, state, msg)
		req.NotNil(err)
		t.Log(err)
	}
}

// TestCommElectionRefundFail tests the case that refund(...) may fail
// but the election should still success
func TestCommElectionRefundFail(t *testing.T) {
	req := require.New(t)
	chain, state := newEnv(0, 0, false)

	minBidderStake := election.MinBidderStake.GetValueAt(config.InitialBlockNum)
	sol := `
pragma solidity ^0.4.25;
contract B {
    function B(bytes votingKey) payable {
        address etpc = 0x30d87bd4D1769437880c64A543bB649a693EB348;
        bytes memory refundinfo = hex"aabbccdd";
        uint256 stake = msg.value;
        bytes memory input = abi.encodeWithSignature("bid(address,uint256,uint256,bytes,bytes)", this, stake, 10000000, votingKey, refundinfo);
        uint inlen = input.length;
        assembly {
            if iszero(call(not(0), etpc, stake, add(input, /*BYTES_HEADER_SIZE*/32), inlen, 0x0, 0x0)) {
                revert(0,0)
            }
        }
    }
}
`
	for i := 0; i < 2; i++ {
		for j := int64(0); j < auctionStakeOverMinStakeRatio; j++ {
			key, _ := bls.NewSigningKey()
			keybytes := key.PublicKey.ToBytes()
			// refund to contract B will fail because refundinfo is nonsense, B doesn't have any function other than constructor
			code := compileSol(req, "B", sol, "0.4.25")
			input := mustDecode(code)
			input = append(input, common.BigToHash(big.NewInt(32)).Bytes()...)
			input = append(input, common.BigToHash(big.NewInt(int64(len(keybytes)))).Bytes()...)
			input = append(input, keybytes...)

			testDeployContract(req, chain, state, testutils.TestingAddr, input, new(big.Int).Add(minBidderStake, big.NewInt(int64(j))))
		}

		testElect(req, chain, state, true)
	}
}
