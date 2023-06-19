package thundervm

import (
	// Standard imports
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	gorand "math/rand"
	"testing"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chainconfig"
	"github.com/ethereum/go-ethereum/thunder/thunderella/config"
	"github.com/ethereum/go-ethereum/thunder/thunderella/election"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/testutils"

	// Vendor imports
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func testRegisterR2(req *require.Assertions, bc *core.BlockChain, state vm.StateDB, table *ByteMap, parentAddress, opAddress common.Address, votingKey []byte) {
	from := parentAddress
	to := vaultAddress
	value := big.NewInt(0)
	keyHash := sha256.Sum256(votingKey)
	input, err := VaultR2ABI.Pack("createAccount", opAddress, keyHash)
	req.NoError(err)

	nonce := uint64(2)
	msg := newFakeMessage(from, to, value, input, nonce)
	_, _, err = run(bc, state, msg)
	req.Nil(err)
	mappingKey := string(keyHash[:])

	entry, err := getVaultBalanceFromTable(table, mappingKey)
	req.Nil(err)
	req.Equal(entry.operationalAccount, opAddress)
}

func testDepositR2(req *require.Assertions, bc *core.BlockChain, state vm.StateDB, table *ByteMap, parentAddress, opAddress common.Address, val *big.Int, keyHash common.Hash) {
	// TODO hash
	from := parentAddress
	to := vaultAddress
	value := val
	input, err := VaultR2ABI.Pack("deposit", keyHash)
	req.NoError(err)

	nonce := uint64(3)
	msg := newFakeMessage(from, to, value, input, nonce)
	_, _, err = run(bc, state, msg)
	req.Nil(err)
	entry, err := getVaultBalanceFromTable(table, keyHash.Str())
	req.Nil(err)
	req.Equal(entry.operationalAccount, opAddress)
	req.Equal(entry.Balance.Int64(), value.Int64())
}

func getElectionBidMapKeyR2(req *require.Assertions, keybytes []byte, keyHash common.Hash) string {
	refundID, err := VaultR2ABI.Pack("deposit", common.Hash(keyHash))
	req.Nil(err)

	key := makeRefundKey(vaultAddress, refundID)
	return string(keybytes) + key
}

func testVaultBidR2(req *require.Assertions, bc *core.BlockChain, state vm.StateDB, table *ByteMap, parentAddress, opAddress common.Address,
	stake, expectedBalance *big.Int, key bls.BlsSigner, s int64) {
	from := opAddress
	to := vaultAddress
	value := big.NewInt(0)
	keybytes := key.GetPublicKey().ToBytes()
	keyHash := sha256.Sum256(keybytes)
	session := big.NewInt(s)
	gasPrice := election.MinBidPrice.GetValueAt(config.InitialBlockNum)
	biddingNonce := getBiddingNonce(req, bc, state, key.GetPublicKey())

	sig := getStakeInfoSignature(stake, parentAddress, gasPrice, key, session, biddingNonce)

	input, err := VaultR2ABI.Pack("bid", parentAddress, stake, gasPrice, keybytes, session, biddingNonce, sig.ToBytes())
	req.NoError(err)

	nonce := uint64(4)
	msg := newFakeMessage(from, to, value, input, nonce)
	_, _, err = run(bc, state, msg)
	req.Nil(err)
	entry, err := getVaultBalanceFromTable(table, common.BytesToHash(keyHash[:]).Str())
	req.Nil(err)

	uniqueKey := getElectionBidMapKeyR2(req, keybytes, keyHash)
	stakeInfo := findElectionStakeInfo(req, state, uniqueKey)
	req.Equal(stakeInfo.StakeMsg.Coinbase, parentAddress)

	req.Equal(entry.operationalAccount, opAddress)
	if expectedBalance != nil {
		req.Equal(expectedBalance, entry.Balance)
	}
}

func TestVaultR2Simple(t *testing.T) {
	req := require.New(t)
	session := VerifyBid.GetEnabledSession()
	bc, state := newEnv(0, session, false)
	opAccount, _ := crypto.GenerateKey()
	opAddress := crypto.PubkeyToAddress(opAccount.PublicKey)
	parentAddress := chainconfig.TestnetTestingAddr

	ratio := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	toTt := func(input int64) *big.Int {
		return new(big.Int).Mul(big.NewInt(input), ratio)
	}
	startingBalance := toTt(250000)

	table := NewByteMap(vaultAddress, state, vaultBalancePrefix)
	// transfer some money to op account as bidding intrinsic fee
	from := parentAddress
	to := opAddress
	txFeeTransferAmount := big.NewInt(500000)
	nonce := uint64(1)
	input := []byte{}

	signKey, err := bls.NewSigningKey()
	req.Nil(err)
	keybytes := signKey.GetPublicKey().ToBytes()
	keyHash := sha256.Sum256(keybytes)

	msg := newFakeMessage(from, to, txFeeTransferAmount, input, nonce)

	run(bc, state, msg)
	req.Equal(0, txFeeTransferAmount.Cmp(state.GetBalance(to)))

	t.Run("createAccount", func(t *testing.T) {
		req := require.New(t)
		testRegisterR2(req, bc, state, table, parentAddress, opAddress, keybytes)
	})

	t.Run("deposit", func(t *testing.T) {
		req := require.New(t)
		testDepositR2(req, bc, state, table, parentAddress, opAddress, startingBalance, keyHash)
	})

	t.Run("bid", func(t *testing.T) {
		req := require.New(t)
		testVaultBidR2(req, bc, state, table, parentAddress, opAddress, toTt(100000), toTt(150000), signKey, session)
		// want to increase bid
		testVaultBidR2(req, bc, state, table, parentAddress, opAddress, toTt(120000), toTt(130000), signKey, session)
		// want to decrease bid (amount transferred from last bid still frozen in ETPC until election)
		testVaultBidR2(req, bc, state, table, parentAddress, opAddress, toTt(110000), toTt(130000), signKey, session)
	})

	t.Run("getBalance", func(t *testing.T) {
		req := require.New(t)
		from = parentAddress
		to = vaultAddress
		value := big.NewInt(0)
		input, err := VaultR2ABI.Pack("getBalance", keyHash)
		req.NoError(err)
		nonce = uint64(5)
		msg = newFakeMessage(from, to, value, input, nonce)
		output, _, err := run(bc, state, msg)
		req.Nil(err)
		entry, err := getVaultBalanceFromTable(table, string(keyHash[:]))
		req.Nil(err)
		req.True(entry.Balance.Cmp(common.BytesToHash(output).Big()) == 0)
	})

	t.Run("getOwner", func(t *testing.T) {
		req := require.New(t)
		from = parentAddress
		to = vaultAddress
		value := big.NewInt(0)
		input, err := VaultR2ABI.Pack("getOwner", keyHash)
		req.NoError(err)
		nonce = uint64(5)
		msg = newFakeMessage(from, to, value, input, nonce)
		output, _, err := run(bc, state, msg)
		req.Nil(err)
		entry, err := getVaultBalanceFromTable(table, string(keyHash[:]))
		req.Nil(err)
		req.True(bytes.Equal(entry.parentAccount.Hash().Bytes(), output))
	})

	t.Run("getOperator", func(t *testing.T) {
		req := require.New(t)
		from = parentAddress
		to = vaultAddress
		value := big.NewInt(0)
		input, err := VaultR2ABI.Pack("getOperator", keyHash)
		req.NoError(err)
		nonce = uint64(5)
		msg = newFakeMessage(from, to, value, input, nonce)
		output, _, err := run(bc, state, msg)
		req.Nil(err)
		entry, err := getVaultBalanceFromTable(table, string(keyHash[:]))
		req.Nil(err)
		req.True(bytes.Equal(entry.operationalAccount.Hash().Bytes(), output))
	})

	t.Run("getAvailableBalance", func(t *testing.T) {
		req := require.New(t)
		from = parentAddress
		to = vaultAddress
		value := big.NewInt(0)
		input, err := VaultR2ABI.Pack("getAvailableBalance", keyHash)
		req.NoError(err)
		nonce = uint64(5)
		msg = newFakeMessage(from, to, value, input, nonce)
		output, _, err := run(bc, state, msg)
		req.Nil(err)
		req.True(startingBalance.Cmp(common.BytesToHash(output).Big()) == 0)
	})

	t.Run("refund", func(t *testing.T) {
		req := require.New(t)
		from = commElectionAddress
		to = vaultAddress
		value := toTt(120000)
		input, err := VaultR2ABI.Pack("deposit", keyHash)
		req.NoError(err)
		nonce = uint64(0)
		msg = newFakeMessage(from, to, value, input, nonce)
		_, _, err = run(bc, state, msg)
		req.Nil(err)
		entry, err := getVaultBalanceFromTable(table, string(keyHash[:]))
		req.Nil(err)
		req.Equal(entry.Balance.String(), toTt(250000).String())
	})

	t.Run("withdraw", func(t *testing.T) {
		req := require.New(t)
		from = parentAddress
		to = vaultAddress
		value := big.NewInt(0)
		input, err := VaultR2ABI.Pack("withdraw", keyHash, toTt(150000))
		req.NoError(err)
		nonce = uint64(7)
		msg = newFakeMessage(from, to, value, input, nonce)
		_, _, err = run(bc, state, msg)
		req.Nil(err)
		entry, err := getVaultBalanceFromTable(table, string(keyHash[:]))
		req.Nil(err)
		req.Equal(entry.operationalAccount, opAddress)
		req.Equal(entry.Balance.String(), toTt(100000).String())
	})

}

func TestVaultR2ParentIsContract(t *testing.T) {
	req := require.New(t)
	session := VerifyBid.GetEnabledSession()
	bc, state := newEnv(0, session, false)
	deployAccount, _ := crypto.GenerateKey()
	deployAddress := crypto.PubkeyToAddress(deployAccount.PublicKey)

	signKey, err := bls.NewSigningKey()
	req.Nil(err)
	keybytes := signKey.GetPublicKey().ToBytes()
	keyHash := sha256.Sum256(keybytes)
	// we use this as op this time..
	opAddress := chainconfig.TestnetTestingAddr
	var parentAddress common.Address

	table := NewByteMap(vaultAddress, state, vaultBalancePrefix)
	// transfer some money to op account as bidding intrinsic fee
	from := opAddress
	to := deployAddress
	txFeeTransferAmount := big.NewInt(500000)
	nonce := uint64(1)
	input := []byte{}

	msg := newFakeMessage(from, to, txFeeTransferAmount, input, nonce)

	_, _, err = run(bc, state, msg)
	req.Nil(err)
	req.Equal(0, txFeeTransferAmount.Cmp(state.GetBalance(to)))

	t.Run("create contract", func(t *testing.T) {
		req := require.New(t)
		sol := `
pragma solidity ^0.4.25;
contract ParentContract {
    function halfDeposit(address op, bytes votingKey) payable {
        address vault = address(bytes20(sha256("Thunder_Vault")));
        bytes32 keyHash = sha256(votingKey);
        require(vault.call(bytes4(keccak256("createAccount(address,bytes32)")), op, keyHash));
        require(vault.call.value(msg.value)(bytes4(keccak256("deposit(bytes32)")), keyHash));
        uint half = msg.value/2;
        require(vault.call(bytes4(keccak256("withdraw(bytes32,uint256)")), keyHash, half));
    }
}
`
		code := compileSol(req, "ParentContract", sol, "0.4.25")
		input := mustDecode(code)
		parentAddress = testDeployContract(req, bc, state, deployAddress, input, big.NewInt(0))
	})

	t.Run("run contract", func(t *testing.T) {
		req := require.New(t)
		from = deployAddress
		to = parentAddress
		value := big.NewInt(20000)
		nonce = uint64(2)
		input = append(crypto.Keccak256([]byte("halfDeposit(address,bytes)"))[:4], common.LeftPadBytes(opAddress.Bytes(), 32)...)
		input = append(input, common.BigToHash(big.NewInt(32+32)).Bytes()...)                // offset
		input = append(input, common.BigToHash(big.NewInt(int64(len(keybytes)))).Bytes()...) // length
		input = append(input, keybytes...)
		msg = newFakeMessage(from, to, value, input, nonce)
		_, _, err = run(bc, state, msg)
		req.Nil(err)
		entry, err := getVaultBalanceFromTable(table, string(keyHash[:]))
		req.Nil(err)
		req.Equal(entry.operationalAccount, opAddress)
		req.Equal(entry.parentAccount, parentAddress)
		req.Equal(entry.Balance.Int64(), int64(10000))
	})

	t.Run("bid", func(t *testing.T) {
		req := require.New(t)
		testVaultBidR2(req, bc, state, table, parentAddress, opAddress, big.NewInt(1000), big.NewInt(9000), signKey, session)
	})
}

func TestVaultR2OpIsContract(t *testing.T) {
	req := require.New(t)
	session := VerifyBid.GetEnabledSession()
	bc, state := newEnv(0, session, false)
	signKey, err := bls.NewSigningKey()
	req.Nil(err)
	keybytes := signKey.GetPublicKey().ToBytes()
	keyHash := sha256.Sum256(keybytes)
	parentAddress := chainconfig.TestnetTestingAddr
	var opAddress common.Address

	table := NewByteMap(vaultAddress, state, vaultBalancePrefix)

	t.Run("create bid contract", func(t *testing.T) {
		req := require.New(t)
		sol := `
pragma solidity ^0.4.25;
contract AgentContract {
    function go(bytes votingkey, uint session, bytes sig) {
        address father = 0x9A78d67096bA0c7C1bCdc0a8742649Bc399119c0;
        uint256 stake = 100;
        uint256 gas = 10000000;
        address vault = address(bytes20(sha256("Thunder_Vault")));
        bytes memory input = abi.encodeWithSignature("bid(address,uint256,uint256,bytes,uint256,uint256,bytes)", father, stake, gas, votingkey, session, 0, sig);
        uint inlen = input.length;
        assembly {
            if iszero(call(not(0), vault, 0, add(input, /*BYTES_HEADER_SIZE*/32), inlen, 0x0, 0x0)) {
                revert(0,0)
            }
        }
    }
}
`
		code := compileSol(req, "AgentContract", sol, "0.4.25")
		input := mustDecode(code)
		opAddress = testDeployContract(req, bc, state, parentAddress, input, big.NewInt(0))
	})

	t.Run("register", func(t *testing.T) {
		req := require.New(t)
		testRegisterR2(req, bc, state, table, parentAddress, opAddress, keybytes)
	})

	t.Run("deposit", func(t *testing.T) {
		req := require.New(t)
		testDepositR2(req, bc, state, table, parentAddress, opAddress, big.NewInt(250000), keyHash)
	})

	t.Run("run bid contract", func(t *testing.T) {
		req := require.New(t)
		from := parentAddress
		sig := getStakeInfoSignature(big.NewInt(100),
			common.HexToAddress("0x9A78d67096bA0c7C1bCdc0a8742649Bc399119c0"),
			big.NewInt(10000000),
			signKey,
			big.NewInt(session),
			common.Big0,
		)
		sigBytes := sig.ToBytes()
		dataPartOffset := 32 * 3 // 3 args

		input := crypto.Keccak256([]byte("go(bytes,uint256,bytes)"))[:4]
		// voting key
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
		nonce := uint64(4)
		value := big.NewInt(0)
		to := opAddress
		msg := newFakeMessage(from, to, value, input, nonce)
		_, _, err := run(bc, state, msg)
		req.Nil(err)
		entry, err := getVaultBalanceFromTable(table, string(keyHash[:]))
		req.Nil(err)
		req.Equal(entry.operationalAccount, opAddress)
		req.Equal(entry.Balance.Int64(), int64(250000-100))
	})
}

func TestVaultR2WorkWithElection(t *testing.T) {
	req := require.New(t)
	testCases := [100]testBidder{}

	for i := range testCases {
		rand.Read(testCases[i].addr[:])
		testCases[i].votekey, _ = bls.NewSigningKey()
	}
	session := VerifyBid.GetEnabledSession()
	bc, state := newEnv(0, session, false)
	table := NewByteMap(vaultAddress, state, vaultBalancePrefix)
	// createMultiple Accounts
	initFund := big.NewInt(1000000)
	for _, c := range testCases {
		keybytes := c.votekey.PublicKey.ToBytes()
		keyHash := sha256.Sum256(keybytes)
		testRegisterR2(req, bc, state, table, testutils.TestingAddr, c.addr, keybytes)
		testDepositR2(req, bc, state, table, testutils.TestingAddr, c.addr, initFund, keyHash)
	}

	// loop tests

	for i := 0; i < 5; i++ {
		// bid for them
		for _, c := range testCases {
			stake := big.NewInt(0).Add(big.NewInt(gorand.Int63n(500)),
				election.MinBidderStake.GetValueAt(config.InitialBlockNum))
			testVaultBidR2(req, bc, state, table, testutils.TestingAddr, c.addr, stake, nil, c.votekey, session)
		}

		testElect(req, bc, state, true)

		// check the balance..
		for _, c := range testCases {
			keyHash := sha256.Sum256(c.votekey.PublicKey.ToBytes())
			_, err := getVaultBalanceFromTable(table, string(keyHash[:]))
			req.Nil(err)
		}
	}

}
