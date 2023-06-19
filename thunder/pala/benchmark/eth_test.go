package benchmark

import (
	"crypto/ecdsa"
	"math/big"
	"runtime"
	"testing"

	"github.com/ethereum/go-ethereum/thunder/thunderella/common/chainconfig"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

func BenchmarkEthereumCreatePrivateKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = crypto.GenerateKey()
	}
}

func BenchmarkEthereumCreatePrivateKeyInParallel(b *testing.B) {
	ch := make(chan interface{}, 1024)
	for i := 0; i < b.N; i++ {
		go func() {
			privateKey, _ := crypto.GenerateKey()
			ch <- privateKey
		}()
	}

	for i := 0; i < b.N; i++ {
		<-ch
	}
}

func BenchmarkEthereumCreatePrivateKeyInParallel2(b *testing.B) {
	n := runtime.NumCPU()
	ch := make(chan interface{}, 1024)
	for k := 0; k < n; k++ {
		m := b.N / n
		if k < b.N%n {
			m++
		}
		go func(m int) {
			for i := 0; i < m; i++ {
				privateKey, _ := crypto.GenerateKey()
				ch <- privateKey
			}
		}(m)
	}

	for i := 0; i < b.N; i++ {
		<-ch
	}
}

func BenchmarkEthereumPublicKeyAddress(b *testing.B) {
	privateKey, _ := crypto.GenerateKey()
	for i := 0; i < b.N; i++ {
		publicKey := privateKey.Public()
		publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
		_ = crypto.PubkeyToAddress(*publicKeyECDSA)
	}
}

func BenchmarkEthereumNewTx(b *testing.B) {
	var addr common.Address
	amount := big.NewInt(1)
	price := big.NewInt(1)
	for i := 0; i < b.N; i++ {
		_ = types.NewTransaction(0, addr, amount, 1, price, nil)
	}
}

func BenchmarkEthereumSignTx(b *testing.B) {
	var addr common.Address
	amount := big.NewInt(1)
	price := big.NewInt(1)
	tx := types.NewTransaction(0, addr, amount, 1, price, nil)
	privateKey, _ := crypto.GenerateKey()
	chainId := big.NewInt(chainconfig.MainnetChainID)
	for i := 0; i < b.N; i++ {
		_, _ = types.SignTx(tx, types.NewEIP155Signer(chainId), privateKey)
	}
}

// To use thie benchmark, please comment out the cache in types.Sender() and uncomment this.
/*
func BenchmarkEthereumSenderAddress(b *testing.B) {
	req := require.New(b)

	var addr common.Address
	amount := big.NewInt(1)
	price := big.NewInt(1)
	tx := types.NewTransaction(0, addr, amount, 1, price, nil)
	privateKey, _ := crypto.GenerateKey()
	chainId := big.NewInt(chainconfig.MainnetChainID)
	signer := types.NewEIP155Signer(chainId)
	tx, err := types.SignTx(tx, signer, privateKey)
	req.NoError(err)
	for i := 0; i < b.N; i++ {
		_, err := types.Sender(signer, tx)
		req.NoError(err)
	}
}
*/
