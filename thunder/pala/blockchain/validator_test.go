package blockchain

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/thunder/thunderella/testutils"
	"github.com/ethereum/go-ethereum/thunder/thunderella/txutils"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/stretchr/testify/require"
)

type NiceValidator struct{}

func (*NiceValidator) ValidateBody(block *types.Block) error {
	return nil
}

func (*NiceValidator) ValidateState(block *types.Block, state *state.StateDB, receipts types.Receipts, usedGas uint64) error {
	return nil
}

func TestConsensusTxValidator_ValidateBody(t *testing.T) {
	newSimpleTx := func(gp int) *types.Transaction {
		from := testutils.TestingKey
		to := testutils.TestingAddr
		amount := new(big.Int).SetInt64(1)
		gasPrice := new(big.Int).SetInt64(int64(gp))
		return txutils.MakeSignedTxWithData(from, &to, 1, amount, new(big.Int).SetInt64(1), nil, gasPrice)
	}
	tests := []struct {
		name    string
		args    *types.Block
		wantErr error
	}{
		{
			name:    "empty block",
			args:    types.NewBlock(&types.Header{}, nil, nil, nil, trie.NewStackTrie(nil)),
			wantErr: nil,
		},
		{
			name: "no underpriced",
			args: types.NewBlock(&types.Header{}, types.Transactions{
				newSimpleTx(1), newSimpleTx(2), newSimpleTx(3),
			}, nil, nil, trie.NewStackTrie(nil)),
			wantErr: nil,
		},
		{
			name: "normal case: only consensus underpriced",
			args: types.NewBlock(&types.Header{}, types.Transactions{
				newSimpleTx(1), newSimpleTx(2), newSimpleTx(0),
			}, nil, nil, trie.NewStackTrie(nil)),
			wantErr: nil,
		},
		{
			name: "one underpriced",
			args: types.NewBlock(&types.Header{}, types.Transactions{
				newSimpleTx(1), newSimpleTx(0), newSimpleTx(0),
			}, nil, nil, trie.NewStackTrie(nil)),
			wantErr: core.ErrUnderpriced,
		},
	}
	for _, tt := range tests {
		validator := WithConsensusTxValidator(&NiceValidator{})
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			got := validator.ValidateBody(tt.args)
			if tt.wantErr == nil {
				req.NoError(got)
			} else {
				req.Error(got)
				req.Equal(tt.wantErr.Error(), got.Error())
			}

		})
	}
}

type fakeEvm int

func (f fakeEvm) GetGasPrice() *big.Int {
	return new(big.Int).SetInt64(int64(f))
}

func TestIsInConsensusTx(t *testing.T) {
	type args struct {
		e params.Evm
	}

	tests := []struct {
		name string
		args params.Evm
		want bool
	}{
		{
			name: "invalid interface",
			args: nil,
			want: false,
		},
		{
			name: "with gas price",
			args: fakeEvm(1),
			want: false,
		},
		{
			name: "no gas price",
			args: fakeEvm(0),
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsInConsensusTx(tt.args); got != tt.want {
				t.Errorf("IsInConsensusTx() = %v, want %v", got, tt.want)
			}
		})
	}
}
