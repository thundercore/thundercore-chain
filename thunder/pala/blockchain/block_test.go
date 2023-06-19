package blockchain

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/require"
)

// make sure it can still work with rlp.Encode() when we change blockImpl to private,
// after this, we can compare two BlockImpl by compare the bytes returned from GetBody()
func Test_blockImpl_GetBody(t *testing.T) {
	type fields struct {
		B *types.Block
	}
	tests := []struct {
		name   string
		fields fields
	}{
		{
			name: "empty block",
			fields: fields{
				B: types.NewBlock(&types.Header{}, nil, nil, nil, trie.NewStackTrie(nil)),
			},
		},
	}
	dataUnmarshaller := &DataUnmarshallerImpl{
		Config: newThunderConfig(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			b := newBlock(
				tt.fields.B,
				newThunderConfig(),
			)
			got := b.GetBody()
			req.NotNil(got)
			b2, rest, err := dataUnmarshaller.UnmarshalBlock(got)
			req.NoError(err)
			req.Empty(rest)
			req.True(b2.(*blockImpl).equals(b.(*blockImpl)))
		})
	}
}

func Test_blockImpl_GetParentBlockSn_GetBlockSn(t *testing.T) {
	type fields struct {
		B *types.Block
	}
	tests := []struct {
		name       string
		fields     fields
		wantParent BlockSn
		want       BlockSn
	}{
		{
			name: "block 0",
			fields: fields{
				B: types.NewBlock(&types.Header{
					Difficulty: EncodeBlockSnToNumber(
						BlockSn{}, GetGenesisBlockSn()),
					Number: new(big.Int).SetUint64(0),
				}, nil, nil, nil, trie.NewStackTrie(nil)),
			},
			wantParent: BlockSn{},
			want: BlockSn{
				S: 1,
			},
		},

		{
			name: "block 1",
			fields: fields{
				B: types.NewBlock(&types.Header{
					Difficulty: EncodeBlockSnToNumber(
						GetGenesisBlockSn(), BlockSn{
							S: 2,
						}),
					Number: new(big.Int).SetUint64(1),
				}, nil, nil, nil, trie.NewStackTrie(nil)),
			},
			wantParent: GetGenesisBlockSn(),
			want: BlockSn{
				S: 2,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newBlock(tt.fields.B, newThunderConfig())
			req := require.New(t)
			req.Equal(b.GetParentBlockSn(), tt.wantParent)
			req.Equal(b.GetBlockSn(), tt.want)
			t.Logf("block info: %s", b.GetBodyString())
		})
	}
}

func Test_BlockImplDecoder_ToRawBlock(t *testing.T) {
	req := require.New(t)

	header := &types.Header{
		Difficulty: EncodeBlockSnToNumber(
			GetGenesisBlockSn(), BlockSn{
				S: 2,
			}),
		Number: new(big.Int).SetUint64(1),
	}
	tx := types.NewTransaction(10, common.Address{2}, big.NewInt(123), 456, big.NewInt(789), []byte{10, 11, 12})
	body := &types.Body{
		Transactions: []*types.Transaction{tx},
	}

	block := types.NewBlockWithHeader(header).WithBody(body.Transactions, body.Uncles)

	decoder := BlockImplDecoder{}

	headerRLP, err := rlp.EncodeToBytes(header)
	req.NoError(err)

	bodyRLP, err := rlp.EncodeToBytes(body)
	req.NoError(err)

	blockRLP, err := rlp.EncodeToBytes(block)
	req.NoError(err)

	rawBlock, err := decoder.ToRawBlock(headerRLP, bodyRLP)
	req.NoError(err)
	req.True(bytes.Equal(rawBlock, blockRLP))
}

func TestGetBlockSnFromDifficulty(t *testing.T) {
	palaBlock := int64(10)
	palaBlockBN := big.NewInt(palaBlock)
	hardforkCfg := InitHardforkValueForTest()
	hardforkCfg.PalaBlock = palaBlockBN
	cfg := NewThunderConfig(hardforkCfg)
	type fields struct {
		difficulty  *big.Int
		blockNumber *big.Int
	}
	tests := []struct {
		name   string
		fields fields
		want   BlockSn
	}{
		{
			name: "before-pala",
			fields: fields{
				difficulty:  EncodeBlockSnToNumber(BlockSn{}, NewBlockSn(1, 1, 2)),
				blockNumber: big.NewInt(palaBlock - 1),
			},
			want: NewBlockSn(0, 0, uint32(palaBlock-1)),
		}, {
			name: "hit-pala",
			fields: fields{
				difficulty:  EncodeBlockSnToNumber(BlockSn{}, NewBlockSn(1, 1, 2)),
				blockNumber: palaBlockBN,
			},
			want: NewBlockSn(1, 1, 2),
		}, {
			name: "after-pala",
			fields: fields{
				difficulty:  EncodeBlockSnToNumber(BlockSn{}, NewBlockSn(1, 1, 2)),
				blockNumber: big.NewInt(palaBlock + 1),
			},
			want: NewBlockSn(1, 1, 2),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			sn := GetBlockSnFromDifficulty(tt.fields.difficulty, tt.fields.blockNumber, cfg)
			req.Equal(sn, tt.want)
		})
	}
}

func TestGetSessionFromDifficulty(t *testing.T) {
	palaBlock := int64(10)
	palaBlockBN := big.NewInt(palaBlock)
	hardforkCfg := InitHardforkValueForTest()
	hardforkCfg.PalaBlock = palaBlockBN
	cfg := NewThunderConfig(hardforkCfg)
	type fields struct {
		difficulty  *big.Int
		blockNumber *big.Int
	}
	tests := []struct {
		name   string
		fields fields
		want   uint32
	}{
		{
			name: "before-pala",
			fields: fields{
				difficulty:  EncodeBlockSnToNumber(BlockSn{}, NewBlockSn(1, 1, 2)),
				blockNumber: big.NewInt(palaBlock - 1),
			},
			want: 0,
		}, {
			name: "hit-pala",
			fields: fields{
				difficulty:  EncodeBlockSnToNumber(BlockSn{}, NewBlockSn(1, 1, 2)),
				blockNumber: palaBlockBN,
			},
			want: 1,
		}, {
			name: "after-pala",
			fields: fields{
				difficulty:  EncodeBlockSnToNumber(BlockSn{}, NewBlockSn(1, 1, 2)),
				blockNumber: big.NewInt(palaBlock + 1),
			},
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			s := GetSessionFromDifficulty(tt.fields.difficulty, tt.fields.blockNumber, cfg)
			req.Equal(s, tt.want)
		})
	}
}
