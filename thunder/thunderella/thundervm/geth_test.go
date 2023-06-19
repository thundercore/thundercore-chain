// Contains tests and benchmarks for geth code.
// TODO move me out of here
package thundervm

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/thunder/thunderella/testutils"

	// Vendor imports
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

func makeTxacts(n int, dataSize uint, signer *types.Signer) []*types.Transaction {

	txs := make([]*types.Transaction, n)
	for i := 0; i < n; i++ {
		toAddr := common.HexToAddress("0xff9A2eAcF66049B3822cC8720B868031782cf45f")
		var gasLimit uint64 = 0
		gasPrice := big.NewInt(1)
		amount := big.NewInt(1)
		data := make([]byte, dataSize)
		for i := range data {
			data[i] = 0xF
		}

		txact := types.NewTransaction(uint64(i), toAddr, amount, gasLimit, gasPrice, data)
		signed, err2 := types.SignTx(txact, *signer, testutils.TestingKey)
		if err2 != nil {
			panic(err2)
		}
		txs[i] = signed
	}
	return txs
}

func BenchmarkEIP155Signer(b *testing.B) {
	var cfg = *params.ThunderChainConfig()
	var signer = types.MakeSigner(&cfg, new(big.Int).SetUint64(uint64(0)), 0)

	b.Run("no data", func(b *testing.B) {
		b.StopTimer()
		txs := makeTxacts(b.N, 0, &signer)
		b.StartTimer()
		for i := 0; i < b.N; i++ {
			txs[i].AsMessage(signer, nil)
		}
	})

	b.Run("10000 bytes data", func(b *testing.B) {
		b.StopTimer()
		txs := makeTxacts(b.N, 10000, &signer)
		b.StartTimer()
		for i := 0; i < b.N; i++ {
			txs[i].AsMessage(signer, nil)
		}
	})

}
