// This tests thunder stuff in "github.com/ethereum/go-ethereum/core/vm"
// This needs to be here because it depends on state.StateDB to test stuff in vm module
package thundervm

import (
	"crypto/rand"
	"crypto/sha256"
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
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bid randomly in [MinBidderStake, MinBidderStake + n), expected to be accepted
func randomAvailableBidR2(req *require.Assertions, chain *core.BlockChain, state vm.StateDB, bidder testBidder, n int64, session int64) *election.SignedStakeInfo {
	amount := big.NewInt(0).Add(big.NewInt(n),
		election.MinBidderStake.GetValueAt(thunderChain.Seq(chain.CurrentHeader().Number.Int64())))
	return makeBidR2(req, chain, state, bidder, election.MinBidPrice.GetValueAt(config.InitialBlockNum), amount, amount, session)
}

// send a bid message with `stake` as satke and `value` as value transferred
func makeBidR2(
	req *require.Assertions,
	chain *core.BlockChain,
	state vm.StateDB,
	bidder testBidder,
	gasPrice *big.Int,
	stake *big.Int,
	value *big.Int,
	session int64,
) *election.SignedStakeInfo {

	from := bidder.addr
	to := commElectionAddress
	fmt.Print(value, chain.CurrentHeader().Number, "\n")
	nonce := uint64(0)
	biddingNonce := getBiddingNonce(req, chain, state, bidder.votekey.GetPublicKey())

	signedStakeInfo := &election.SignedStakeInfo{
		StakeInfo: election.StakeInfo{
			StakeMsg: election.StakeMsg{
				Stake:      stake,
				PubVoteKey: bidder.votekey.GetPublicKey(),
				Coinbase:   bidder.addr,
				GasPrice:   gasPrice,
			},
		},
		Session: big.NewInt(session),
		Nonce:   biddingNonce,
	}
	signedStakeInfo.Sign(bidder.votekey)
	input, err := StakeMsgToBidCallR2(signedStakeInfo)
	req.Nil(err)

	msg := newFakeMessage(from, to, value, input, nonce)
	_, _, err = run(chain, state, msg)
	req.Nil(err)

	return signedStakeInfo
}

func getBiddingNonce(req *require.Assertions, chain *core.BlockChain, stateDB vm.StateDB, key *bls.PublicKey) *big.Int {
	from := testutils.TestingAddr
	to := commElectionAddress
	value := big.NewInt(0)
	keyHash := sha256.Sum256(key.ToBytes())
	input, err := ElectionR2ABI.Pack("getNonce", keyHash)
	req.NoError(err)
	msg := newFakeMessage(from, to, value, input, 0)
	output, _, err := run(chain, stateDB, msg)
	req.NoError(err)
	return common.BytesToHash(output).Big()
}

func TestCommElectionR2Bid(t *testing.T) {
	req := require.New(t)

	session := VerifyBid.GetEnabledSession()
	ElectionVersion.SetTestValueAtSession("", session)
	election.ElectionScheme.SetTestValueAtSession("TotalStakeThreshold", session)
	chain, state := newEnv(0, session, true)
	key, err := bls.NewSigningKey()
	req.Nil(err)
	bidAmount := election.MinBidderStake.GetValueAtSession(0)

	// create the ethereum ABI call args, but sign it with rubbish
	signedStakeInfo := &election.SignedStakeInfo{
		StakeInfo: election.StakeInfo{
			StakeMsg: election.StakeMsg{
				Stake:      bidAmount,
				PubVoteKey: key.GetPublicKey(),
				Coinbase:   testutils.TestingAddr,
				GasPrice:   election.MinBidPrice.GetValueAtSession(0),
			},
			StakingAddr: testutils.TestingAddr,
		},
		Session: big.NewInt(session),
		Nonce:   common.Big0,
	}
	signedStakeInfo.Sig = key.Sign([]byte("rubbish"))

	// run the call, should fail due to invalid signature
	{
		input, err1 := StakeMsgToBidCallR2(signedStakeInfo)
		req.NoError(err1)
		from := testutils.TestingAddr
		to := commElectionAddress
		value := bidAmount
		nonce := uint64(0)
		msg := newFakeMessage(from, to, value, input, nonce)
		_, _, err2 := run(chain, state, msg)
		req.Error(err2)
	}

	// sign the bid and run the call
	signedStakeInfo.Sign(key)
	{
		input, err1 := StakeMsgToBidCallR2(signedStakeInfo)
		req.Nil(err1)
		from := testutils.TestingAddr
		to := commElectionAddress
		value := bidAmount
		nonce := uint64(0)
		msg := newFakeMessage(from, to, value, input, nonce)
		_, _, err2 := run(chain, state, msg)
		req.Nil(err2)
	}

	// verify biddingNonce increases
	{
		biddingNonce := getBiddingNonce(req, chain, state, key.GetPublicKey())
		req.Equal(biddingNonce, common.Big1)
	}

	// run the call again, should fail due to invalid bidding nonce
	{
		input, err1 := StakeMsgToBidCallR2(signedStakeInfo)
		req.NoError(err1)
		from := testutils.TestingAddr
		to := commElectionAddress
		value := bidAmount
		nonce := uint64(0)
		msg := newFakeMessage(from, to, value, input, nonce)
		_, _, err2 := run(chain, state, msg)
		req.Error(err2)
	}

	// verify the results
	{
		bids, err := GetCurrentBids(state)
		req.Nil(err)
		req.Equal(1, len(bids))
		req.Equal(0, state.GetBalance(commElectionAddress).Cmp(bidAmount))
		req.Equal(bids[0].ToBytes(), signedStakeInfo.StakeInfo.ToBytes())
	}

	{
		stakeTable := NewByteMap(commElectionAddress, state, electionStakeTablePrefix)
		var current stakeValue
		err := stakeTable.FindEntry(makeRefundKey(testutils.TestingAddr, []byte{}), &current)
		req.Nil(err)
		req.Equal(0, current.Value.Cmp(bidAmount))
	}

	// verify invalid bid should fail
	signedStakeInfo.StakeInfo.GasPrice.SetInt64(0)
	{
		input, err1 := StakeMsgToBidCallR2(signedStakeInfo)
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

func TestCommElectionR2(t *testing.T) {
	// first transfer money to auctionStakeOverMinStakeRatio accounts
	req := require.New(t)
	session := VerifyBid.GetEnabledSession()
	ElectionVersion.SetTestValueAtSession("", session)
	election.ElectionScheme.SetTestValueAtSession("TotalStakeThreshold", session)
	chain, state := newEnv(0, session, false)

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
			randomAvailableBidR2(req, chain, state, bidder, 500, session)
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
			randomAvailableBidR2(req, chain, state, bidders[j], 500, session)
		}

		result := testElect(req, chain, state, false)
		// should failed
		req.Equal(currentCommittee, result)
	}

	for i := 0; i < 2; i++ {
		for _, bidder := range bidders {
			randomAvailableBidR2(req, chain, state, bidder, 500, session)
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

// TestCommElectionR2BadInput tests for bad inputs
func TestCommElectionR2BadInput(t *testing.T) {
	assert := assert.New(t)
	session := VerifyBid.GetEnabledSession()
	ElectionVersion.SetTestValueAtSession("", session)
	election.ElectionScheme.SetTestValueAtSession("TotalStakeThreshold", session)
	chain, state := newEnv(0, session, false)

	from := common.Address{}
	to := commElectionAddress
	value := big.NewInt(0)
	nonce := uint64(0)

	input := []byte{1, 2, 3}

	msg := newFakeMessage(from, to, value, input, nonce)
	_, _, err := run(chain, state, msg)
	assert.NotNil(err)
}

// TestCommElectionR2SameRefundIdMultipleKey test when the refund infomation on different votingKeys are the same,
// commElection will save the stake in the same container, but the bids are consider different.
// the lower priority bids will be disqualified but some higher bids can still utilize the stake.
func TestCommElectionR2SameRefundIdMultipleKey(t *testing.T) {
	// first transfer money to auctionStakeOverMinStakeRatio accounts
	req := require.New(t)
	session := VerifyBid.GetEnabledSession()
	ElectionVersion.SetTestValueAtSession("", session)
	election.ElectionScheme.SetTestValueAtSession("TotalStakeThreshold", session)
	chain, state := newEnv(0, session, false)

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
			randomAvailableBidR2(req, chain, state, bidder, 500, session)
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
			makeBidR2(req, chain, state, bidder, gasPrice, big.NewInt(minBidderStake*12), big.NewInt(minBidderStake), session)
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
			makeBidR2(req, chain, state, bidder, gasPrice, big.NewInt(minBidderStake), big.NewInt(0), session)
		}

		testElect(req, chain, state, false)
	}

}

// TestCommElectionR2RefundReentrancy tests the case refund(...) calls back into bid() or getAvailableStake()
// expecte the bid() called by refund() to fail, since signature does not match.
func TestCommElectionR2RefundReentrancy(t *testing.T) {
	req := require.New(t)
	session := VerifyBid.GetEnabledSession()
	ElectionVersion.SetTestValueAtSession("", session)
	election.ElectionScheme.SetTestValueAtSession("TotalStakeThreshold", session)
	chain, state := newEnv(0, session, false)

	bidders := [6]testBidder{}
	stake := big.NewInt(10000)
	sol := `
pragma solidity ^0.4.25;
contract SingleRepeatBidder {
    bytes votingKey;
    uint session;
    bytes signature;
    function SingleRepeatBidder(bytes vk, uint s, bytes sig) payable {
        votingKey = vk;
        session = s;
        signature = sig;
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
        bytes memory input = abi.encodeWithSignature("bid(address,uint256,uint256,bytes,uint256,uint256,bytes,bytes)", this, stake, 10000000, votingKey, session, 0, signature, refundinfo);
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
		contractAddr := crypto.CreateAddress(testutils.TestingAddr, state.GetNonce(testutils.TestingAddr))
		sig := getStakeInfoSignature(
			stake,
			contractAddr,
			big.NewInt(10000000),
			bidders[i].votekey,
			big.NewInt(session),
			common.Big0,
		)
		sigBytes := sig.ToBytes()
		code := compileSol(req, "SingleRepeatBidder", sol, "0.4.25")
		dataPartOffset := 32 * 3 // 3 args
		input := mustDecode(code)
		// votingKey
		input = append(input, common.BigToHash(big.NewInt(int64(dataPartOffset))).Bytes()...) // offset of votingKey
		data := common.BigToHash(big.NewInt(int64(len(keybytes)))).Bytes()                    // length of votingKey
		data = append(data, keybytes...)                                                      // votingKey

		// session
		input = append(input, common.BigToHash(big.NewInt(session)).Bytes()...) // session

		// sig
		input = append(input, common.BigToHash(big.NewInt(int64(dataPartOffset+len(data)))).Bytes()...) // offset of sig
		data = append(data, common.BigToHash(big.NewInt(int64(len(sigBytes)))).Bytes()...)              // length of sig
		data = append(data, sigBytes...)                                                                // sig

		input = append(input, data...)

		input = append(input, common.BigToHash(big.NewInt(32)).Bytes()...)
		input = append(input, common.BigToHash(big.NewInt(int64(len(keybytes)))).Bytes()...)
		input = append(input, keybytes...)

		bidders[i].addr = testDeployContract(req, chain, state, testutils.TestingAddr, input, stake)
	}

	// the first election will success, second election will fail due to all refund failed
	testElect(req, chain, state, true)
	testElect(req, chain, state, false)
}

// TestIndirectlyCommElectionR2 tests the case someone may try to trigger election via contract
func TestIndirectlyCommElectionR2(t *testing.T) {
	req := require.New(t)
	session := VerifyBid.GetEnabledSession()
	ElectionVersion.SetTestValueAtSession("", session)
	election.ElectionScheme.SetTestValueAtSession("TotalStakeThreshold", session)
	chain, state := newEnv(0, session, false)
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

// TestCommElectionR2RefundFail tests the case that refund(...) may fail
// but the election should still success
func TestCommElectionR2RefundFail(t *testing.T) {
	req := require.New(t)
	session := VerifyBid.GetEnabledSession()
	ElectionVersion.SetTestValueAtSession("", session)
	election.ElectionScheme.SetTestValueAtSession("TotalStakeThreshold", session)
	chain, state := newEnv(0, session, false)

	minBidderStake := election.MinBidderStake.GetValueAt(config.InitialBlockNum)
	sol := `
pragma solidity ^0.4.25;
contract B {
    function B(bytes votingKey, uint session, bytes sig) payable {
        address etpc = 0x30d87bd4D1769437880c64A543bB649a693EB348;
        bytes memory refundinfo = hex"aabbccdd";
        uint256 stake = msg.value;
        bytes memory input = abi.encodeWithSignature("bid(address,uint256,uint256,bytes,uint256,uint256,bytes,bytes)", this, stake, 10000000, votingKey, session, 0, sig, refundinfo);
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
			stake := new(big.Int).Add(minBidderStake, big.NewInt(int64(j)))
			contractAddr := crypto.CreateAddress(testutils.TestingAddr, state.GetNonce(testutils.TestingAddr))
			sig := getStakeInfoSignature(
				stake,
				contractAddr,
				big.NewInt(10000000),
				key,
				big.NewInt(session),
				common.Big0,
			)
			sigBytes := sig.ToBytes()
			// refund to contract B will fail because refundinfo is nonsense, B doesn't have any function other than constructor
			code := compileSol(req, "B", sol, "0.4.25")

			dataPartOffset := 32 * 3 // 3 args
			input := mustDecode(code)
			// votingKey
			input = append(input, common.BigToHash(big.NewInt(int64(dataPartOffset))).Bytes()...) // offset of votingKey
			data := common.BigToHash(big.NewInt(int64(len(keybytes)))).Bytes()                    // length of votingKey
			data = append(data, keybytes...)                                                      // votingKey

			// session
			input = append(input, common.BigToHash(big.NewInt(session)).Bytes()...) // session

			// sig
			input = append(input, common.BigToHash(big.NewInt(int64(dataPartOffset+len(data)))).Bytes()...) // offset of sig
			data = append(data, common.BigToHash(big.NewInt(int64(len(sigBytes)))).Bytes()...)              // length of sig
			data = append(data, sigBytes...)                                                                // sig

			input = append(input, data...)

			testDeployContract(req, chain, state, testutils.TestingAddr, input, stake)
		}

		testElect(req, chain, state, true)
	}
}
