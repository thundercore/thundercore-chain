package thundervm

import (
	// Standard imports

	"math/big"
	"testing"

	// Thunder imports
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/thunder/thunderella/testutils"

	// Vendor imports
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestRandomV4RequiredGas(t *testing.T) {
	expectedGas := (params.Sha256BaseGas + params.Sha256PerWordGas*2 + params.Pala2P5SLoad + params.SstoreResetGas) * 6 / 5 * params.RNGGasBumpV4

	require := require.New(t)
	from := testutils.TestingAddr
	to := randomAddress
	value := big.NewInt(0)
	input := append(crypto.Keccak256([]byte("generateRandom()"))[:4])
	nonce := uint64(0)
	msg := newFakeMessage(from, to, value, input, nonce)
	bc, state := newEnv(int(IsRNGActive.GetEnabledBlockNum()), rngV4EnableSession, false)

	msg.nonce = 1
	_, leftOverGas, err := run(bc, state, msg)

	require.Nil(err)
	require.Equal(uint64(msg.Gas()-expectedGas), leftOverGas)
}

// Test random number query in same block.
func TestEnhancedRandomGen(t *testing.T) {
	require := require.New(t)
	from := testutils.TestingAddr
	to := randomAddress
	value := big.NewInt(0)
	input := append(crypto.Keccak256([]byte("generateRandom()"))[:4])
	nonce := uint64(0)
	msg := newFakeMessage(from, to, value, input, nonce)
	bc, state := newEnv(int(IsRNGActive.GetEnabledBlockNum()), rngV3EnableSession, false)

	addr := common.BytesToAddress([]byte("random"))
	state.AddBalance(addr, big.NewInt(1))

	randomNumber, _, err := run(bc, state, msg)
	require.NotNil(randomNumber)
	require.Nil(err)

	state.AddBalance(addr, big.NewInt(1))

	msg.nonce = 1
	randomNumber1, _, err := run(bc, state, msg)
	require.NotNil(randomNumber1)
	require.Nil(err)

	require.NotEqual(randomNumber, randomNumber1)
}

func TestEnhancedRandomGenSameNonce(t *testing.T) {
	require := require.New(t)
	from := testutils.TestingAddr
	to := randomAddress
	value := big.NewInt(0)
	input := append(crypto.Keccak256([]byte("generateRandom()"))[:4])
	nonce := uint64(0)
	msg := newFakeMessage(from, to, value, input, nonce)
	bc, state := newEnv(int(IsRNGActive.GetEnabledBlockNum()), rngV3EnableSession, false)

	randomNumber, _, err := run(bc, state, msg)
	require.NotNil(randomNumber)
	require.Nil(err)

	randomNumber1, _, err := run(bc, state, msg)
	require.NotNil(randomNumber1)
	require.Nil(err)

	require.NotEqual(randomNumber, randomNumber1)
}

// Test random number query in same block.
func TestRandomGen(t *testing.T) {
	require := require.New(t)

	from := testutils.TestingAddr
	to := randomAddress
	value := big.NewInt(0)
	input := append(crypto.Keccak256([]byte("generateRandom()"))[:4])
	nonce := uint64(0)
	msg := newFakeMessage(from, to, value, input, nonce)
	bc, state := newEnv(int(IsRNGActive.GetEnabledBlockNum()), 0, false)

	IsRNGActive.SetTestValueAt(true, 1)

	randomNumber, _, err := run(bc, state, msg)
	require.NotNil(randomNumber)
	require.Nil(err)

	msg.nonce = 1
	randomNumber1, _, err := run(bc, state, msg)
	require.NotNil(randomNumber1)
	require.Nil(err)

	require.NotEqual(randomNumber, randomNumber1)
}

// Test random number generator failure if invoked before hardfork block number
func TestRandomGenFail(t *testing.T) {
	require := require.New(t)
	from := testutils.TestingAddr
	to := randomAddress
	value := big.NewInt(0)
	input := append(crypto.Keccak256([]byte("generateRandom;()"))[:4])

	nonce := uint64(0)
	msg := newFakeMessage(from, to, value, input, nonce)
	bc, state := newEnv(0, 0, false)

	IsRNGActive.SetTestValueAt(false, 0)
	IsRNGActive.SetTestValueAt(false, 1)
	// Ensure that that hardfork config inactivated the RNG TPC at seq number 0
	require.False(IsRNGActive.GetValueAt(0))

	randomNumber, _, err := run(bc, state, msg)
	require.Nil(randomNumber)
	require.Nil(err)
}

// Test multiple random number generation.
func TestMultipleRandomGen(t *testing.T) {
	require := require.New(t)
	from := testutils.TestingAddr
	to := randomAddress
	value := big.NewInt(0)
	input := append(crypto.Keccak256([]byte("generateRandom()"))[:4])

	nonce := uint64(0)
	msg := newFakeMessage(from, to, value, input, nonce)
	bc, state := newEnv(int(IsRNGActive.GetEnabledBlockNum()), 0, false)
	IsRNGActive.SetTestValueAt(true, 1)

	// Store in array.
	numbers := make([]string, 100)
	for i := 0; i < 100; i++ {
		randomNumber, _, err := run(bc, state, msg)

		require.NotNil(randomNumber)
		require.Nil(err)
		numbers[i] = common.BytesToHash(randomNumber).String()
	}

	for i := 0; i < len(numbers); i++ {
		for j := i; j < len(numbers); j++ {
			if i != j {
				require.NotEqual(numbers[i], numbers[j])
			}
		}
	}
}

func TestRandomGenGasUsage(t *testing.T) {
	req := require.New(t)
	from := testutils.TestingAddr
	to := randomAddress
	value := big.NewInt(0)
	input := append(crypto.Keccak256([]byte("generateRandom()"))[:4])
	nonce := uint64(0)
	msg := newFakeMessage(from, to, value, input, nonce)

	tests := []struct {
		name    string
		session int64
		gasUsed uint64
	}{
		{
			name:    "before pala2.5 gas table change",
			session: palaR2P5GasTableEnabledSession - 1,
			gasUsed: _random.RequiredGas(input),
		},
		{
			name:    "after pala2.5 gas table change",
			session: palaR2P5GasTableEnabledSession,
			gasUsed: _randomR2P5.RequiredGas(input),
		},
		{
			name:    "after enhanced RNG",
			session: rngV3EnableSession,
			gasUsed: _randomV3.RequiredGas(input),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			IsRNGActive.SetTestValueAt(true, 1)
			bc, state := newEnv(int(IsRNGActive.GetEnabledBlockNum()), tt.session, false)
			_, leftOverGas, err := run(bc, state, msg)
			req.NoError(err)
			req.Equal(tt.gasUsed, msg.Gas()-leftOverGas)
		})
	}
}
