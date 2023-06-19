package bls

import (
	// Standard imports.
	"crypto/rand"
	"testing"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls/bn256"

	"github.com/stretchr/testify/assert"
)

// newRandomMsg returns 1MB long random byte array
func newRandomMsg() []byte {
	msg := make([]byte, 1024*1024)
	rand.Read(msg)
	return msg
}

// newRandomKeyPair returns a newly generated random pair of public and signing keys
func newRandomKeyPair(tb testing.TB) (*PublicKey, *SigningKey) {
	sk, err := NewSigningKey()
	assert.NoError(tb, err, "error making key : %s ", err)
	return sk.GetPublicKey(), sk
}

func TestBLSSign(t *testing.T) {
	assert := assert.New(t)
	msg := []byte("hello")

	pk, sk := newRandomKeyPair(t)
	sig := sk.Sign(msg)
	assert.True(pk.VerifySignature(msg, sig), "sig verification failed")
	t.Logf("Signature: %v\n", sig.sigma)

	pk2, sk2 := newRandomKeyPair(t)
	sig2 := sk2.Sign(msg)
	assert.True(pk2.VerifySignature(msg, sig2), "sig verification failed")
	t.Logf("Signature2: %v\n", sig2.sigma)

	sig3, pk3 := CombineSignatures(sig, sig2, pk, pk2)
	assert.True(pk3.VerifySignature(msg, sig3), "sig verification failed")
}

func TestBLSConcurrentToBytes(t *testing.T) {
	assert := assert.New(t)

	sk, err := NewSigningKey()

	sk = SigningKeyFromBytes(sk.ToBytes())
	assert.Nil(err, "NewSigningKey() failed.")

	for i := 0; i < 666; i++ {
		pk := *sk.GetPublicKey()
		t.Run("test", func(t *testing.T) {
			t.Parallel()

			for i := 0; i < 5; i++ {
				assert.Equal(pk.ToBytes(), sk.GetPublicKey().ToBytes())
			}
		})
	}
}

func BenchmarkBLSSign(b *testing.B) {
	_, sk := newRandomKeyPair(b)
	msg := newRandomMsg()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sk.Sign(msg)
	}
}

func BenchmarkBLSHash(b *testing.B) {
	msg := newRandomMsg()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bn256.HashG1(msg)
	}
}

func BenchmarkBLSVerify(b *testing.B) {
	pk, sk := newRandomKeyPair(b)
	msg := newRandomMsg()
	sig := sk.Sign(msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !pk.VerifySignature(msg, sig) {
			b.Fail()
		}
	}
}

func BenchmarkBLSCombine(b *testing.B) {
	pk, sk := newRandomKeyPair(b)
	pk2, sk2 := newRandomKeyPair(b)
	msg := newRandomMsg()
	sig := sk.Sign(msg)
	sig2 := sk2.Sign(msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CombineSignatures(sig, sig2, pk, pk2)
	}
}
