// This tests thunder stuff in "github.com/ethereum/go-ethereum/core/vm"
// This needs to be here because it depends on state.StateDB to test stuff in vm module
package thundervm

import (
	"crypto/sha256"
	"math/big"
	"math/rand"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/election"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Vendor imports

func TestCommElectionR3Bid(t *testing.T) {
	req := require.New(t)

	session := VerifyBid.GetEnabledSession()

	ElectionVersion.SetTestValueAtSession("", 0)
	ElectionVersion.SetTestValueAtSession("r3", session)

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

// TestCommElectionR2BadInput tests for bad inputs
func TestCommElectionR3BadInput(t *testing.T) {
	assert := assert.New(t)

	session := VerifyBid.GetEnabledSession()
	ElectionVersion.SetTestValueAtSession("", 0)
	ElectionVersion.SetTestValueAtSession("r3", session)

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
func TestCommElectionR3SameRefundIdMultipleKey(t *testing.T) {
	// first transfer money to auctionStakeOverMinStakeRatio accounts
	req := require.New(t)
	session := VerifyBid.GetEnabledSession()

	ElectionVersion.SetTestValueAtSession("", 0)
	ElectionVersion.SetTestValueAtSession("r3", session)

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

// TestCommElectionR3RefundToNonVaultAddress tests the case that refund to non vault address
// in ElectionR3, the value should be refunded but the bytecode will not be executed
func TestCommElectionR3RefundToNonVaultAddress(t *testing.T) {
	req := require.New(t)

	session := VerifyBid.GetEnabledSession()

	ElectionVersion.SetTestValueAtSession("", 0)
	ElectionVersion.SetTestValueAtSession("r3", session)
	election.ElectionScheme.SetTestValueAtSession("TopKCandidates", session)

	expectedCommSize := config.NewInt64HardforkConfig(
		"committee.expectedCommSize",
		"the expected commSize (the K value of the Top-K scheme), should be larger than minCommitteeSize")
	commSize := expectedCommSize.GetValueAtSession(session)

	chain, state := newEnv(0, session, false)

	if evmHardforkVersion.GetValueAtSession(session) == "" {
		return
	}

	minBidderStake := election.MinBidderStake.GetValueAt(config.InitialBlockNum)
	sol := `
	pragma solidity ^0.8.9;
	contract Bidder {
		address public receiver = 0x9788D0009C1F39c11eb856135710A468Eb58bDCE;

		constructor(bytes memory votingKey, uint session, bytes memory sig) payable {

			address electionTPC = 0x30d87bd4D1769437880c64A543bB649a693EB348;
			bytes memory refundData = abi.encodeWithSignature("refund()");
			uint256 stake = msg.value;
			bytes memory input = abi.encodeWithSignature("bid(address,uint256,uint256,bytes,uint256,uint256,bytes,bytes)", this, stake, 10000000, votingKey, session, 0, sig, refundData);
			uint inlen = input.length;
			assembly {
				if iszero(call(not(0), electionTPC, stake, add(input, /*BYTES_HEADER_SIZE*/32), inlen, 0x0, 0x0)) {
					revert(0,0)
				}
			}
		}

		function refund() external {
			payable(receiver).transfer(address(this).balance);
		}
	}
`

	receiver := common.HexToAddress("0x9788D0009C1F39c11eb856135710A468Eb58bDCE")
	var createdAddress common.Address

	for j := int64(0); j < commSize+1; j++ {
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
		// refund to contract Bidder will not work because refund to non vault address
		code := compileSol(req, "Bidder", sol, "0.8.9")

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

		created := testDeployContract(req, chain, state, testutils.TestingAddr, input, stake)

		if j == 0 {
			createdAddress = created
		}
	}

	testElect(req, chain, state, true)

	// refund should not be called, so receiver should not get any balance
	balance := state.GetBalance(receiver)
	req.Equal(big.NewInt(0), balance)

	refundedValue := state.GetBalance(createdAddress)
	req.Equal(minBidderStake, refundedValue)
}

// vault precompiled contract address is 0xEC45c94322EaFEEB2Cf441Cd1aB9e81E58901a08
func TestCommElectionR3RefundToVaultAddress(t *testing.T) {
	req := require.New(t)

	session := VerifyBid.GetEnabledSession()

	ElectionVersion.SetTestValueAtSession("", 0)
	ElectionVersion.SetTestValueAtSession("r3", session)
	election.ElectionScheme.SetTestValueAtSession("TopKCandidates", session)

	expectedCommSize := config.NewInt64HardforkConfig(
		"committee.expectedCommSize",
		"the expected commSize (the K value of the Top-K scheme), should be larger than minCommitteeSize")
	commSize := expectedCommSize.GetValueAtSession(session)

	chain, state := newEnv(0, session, false)

	if evmHardforkVersion.GetValueAtSession(session) == "" {
		return
	}

	minBidderStake := election.MinBidderStake.GetValueAt(config.InitialBlockNum)
	sol := `
	pragma solidity ^0.8.9;
	contract Bidder {
		constructor(bytes memory votingKey, uint session, bytes memory sig) payable {
			address vault = address(bytes20(sha256("Thunder_Vault")));
			bytes32 keyHash = sha256(votingKey);
			(bool success, ) = vault.call(abi.encodeWithSignature("createAccount(address,bytes32)", this, keyHash));
			require(success, "createAccount failed");
			(success, ) = vault.call{value: msg.value}(abi.encodeWithSignature("deposit(bytes32)", keyHash));
			require(success, "deposit failed");

			uint256 gas = 10000000;
			(success, ) = vault.call(abi.encodeWithSignature("bid(address,uint256,uint256,bytes,uint256,uint256,bytes)", this, msg.value, gas, votingKey, session, 0, sig));
			require(success, "bid failed");
		}
	}
`

	var keyHash common.Hash

	for j := int64(0); j < commSize+1; j++ {
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
		// refund to contract Bidder will not work because refund to non vault address
		code := compileSol(req, "Bidder", sol, "0.8.9")

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

		if j == 0 {
			keyHash = sha256.Sum256(keybytes)
		}
	}

	testElect(req, chain, state, true)

	encodedData, err := VaultR2ABI.Pack("getBalance", keyHash)
	req.NoError(err)

	// getBalance of keyHash in vault, should be minBidderStake because the refund will be sent to vault
	fakeMsg := newFakeMessage(testutils.TestingAddr, common.HexToAddress("0xEC45c94322EaFEEB2Cf441Cd1aB9e81E58901a08"), big.NewInt(0), encodedData, state.GetNonce(testutils.TestingAddr))
	ret, _, err := run(chain, state, fakeMsg)
	req.NoError(err)

	balance, err := VaultR2ABI.Unpack("getBalance", ret)
	req.NoError(err)

	req.Equal(minBidderStake, balance[0].(*big.Int))
}
