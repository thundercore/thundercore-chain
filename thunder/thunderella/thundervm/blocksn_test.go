package thundervm

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/thunder/thunderella/testutils"

	"github.com/stretchr/testify/require"
)

func TestGetSessionPrecompiledContract(t *testing.T) {
	t.Run("Successfully get blocksn", func(t *testing.T) {
		require := require.New(t)

		from := testutils.TestingAddr
		to := blockSnAddress
		value := big.NewInt(0)
		input := []byte{}
		nonce := uint64(0)

		msg := newFakeMessage(from, to, value, input, nonce)
		bc, state := newEnvWithBlockSn(0, 1, 1, 25, false)

		IsBlockSnGetterActive.SetTestValueAtSession(true, 0)

		returnData, _, err := run(bc, state, msg)
		require.Nil(err)
		require.NotNil(returnData)

		session := new(big.Int).SetBytes(returnData[0:32])
		epoch := new(big.Int).SetBytes(returnData[32:64])
		S := new(big.Int).SetBytes(returnData[64:96])

		require.Equal(session, big.NewInt(1))
		require.Equal(epoch, big.NewInt(1))
		require.Equal(S, big.NewInt(25))
	})

	t.Run("Expect no return data before hardfork", func(t *testing.T) {
		require := require.New(t)

		from := testutils.TestingAddr
		to := blockSnAddress
		value := big.NewInt(0)
		input := []byte{}
		nonce := uint64(0)

		msg := newFakeMessage(from, to, value, input, nonce)
		bc, state := newEnvWithBlockSn(0, 4, 1, 25, false)

		IsBlockSnGetterActive.SetTestValueAtSession(false, 0)
		IsBlockSnGetterActive.SetTestValueAtSession(true, 10)

		returnData, _, err := run(bc, state, msg)
		require.Nil(err)
		require.Nil(returnData)
	})
}
