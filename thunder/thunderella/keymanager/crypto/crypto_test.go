package crypto

import (
	// Standard imports
	"encoding/hex"
	"math/big"
	"testing"

	// Vendor imports
	"github.com/stretchr/testify/assert"
)

var (
	emptySalt []byte
	testPwd   = "TestForAESKey"
)

func TestGenAESKeyByPwd(t *testing.T) {
	assert := assert.New(t)

	aesKeyBlob, err := GenAESKeyByPwd(testPwd, emptySalt)
	assert.Nil(err, "failed to generate an AES key")
	assert.Equal(aesKeyLen, len(aesKeyBlob.KeyValue),
		"generated AES key length is not 256 bits")

	// The salt should be a valid hex string.
	_, err = GenAESKeyByPwd(testPwd, []byte("not a hex string"))
	assert.NotNil(err, "successfully decoded an invalid hex string for salt")

	// The salt should be a valid hex string with the correct length.
	_, err = GenAESKeyByPwd(testPwd, []byte("abc123"))
	assert.NotNil(err, `successfully generated AES key from
		salt of invalid length`)

	aesKeyBlobDup, err := GenAESKeyByPwd(testPwd, aesKeyBlob.Salt)
	assert.Nil(err, "failed to generate an AES key")
	assert.Equal(aesKeyBlob.KeyValue, aesKeyBlobDup.KeyValue,
		"failed to generate same keys from a same password and salt")
	assert.Equal(aesKeyBlob.Salt, aesKeyBlobDup.Salt,
		"failed to get same salt for same key blobs")
}

func TestAESEncryptionDecryption(t *testing.T) {
	assert := assert.New(t)

	testPlainText := []byte("This is a thunder token admin key")
	aesKeyBlob, err := GenAESKeyByPwd(testPwd, emptySalt)
	assert.Nil(err, "failed to generate an AES key")

	cipherBlob, err := EncryptWithAES(testPlainText, aesKeyBlob.KeyValue)
	assert.Nil(err, "failed to encrypt with AES key")

	decrypted, err := DecryptWithAES(cipherBlob, aesKeyBlob.KeyValue)
	assert.Nil(err, "failed to decrypt with AES key")

	assert.Equal(testPlainText, decrypted,
		"encrypted msg is not same as the decrypted")

	// An invalid key shouldn't successfully decrypt the ciphertext.
	aesKey, err := hex.DecodeString("abc123")
	assert.Nil(err, "failed to decode key value from hex")
	_, err = DecryptWithAES(cipherBlob, aesKey)
	assert.NotNil(err, "decryption succeeded with incorrect key")
}

// Mess with an ECDSA signature so that tests using it for
// verification will fail.
func (sig *ECDSASignature) perturb() {
	sig.R = big.NewInt(42)
}

func TestECDSASignAndVerify(t *testing.T) {
	assert := assert.New(t)

	data := []byte("The quick brown fox")

	priv, err := GenECDSAKey()
	assert.Nil(err, "failed to generate an ECDSA keypair")

	sig, err := SignWithECDSA(data, priv)
	assert.Nil(err, "failed to sign data with ECDSA private key")

	pub := GetECDSAPublicKey(priv)
	verified, err := VerifyWithECDSA(data, pub, sig)
	assert.Nil(err, "error verifying signature")
	assert.True(verified, "failed to verify the signed data")

	sig.perturb()
	verified, err = VerifyWithECDSA(data, pub, sig)
	assert.Nil(err, "error verifying signature")
	assert.False(verified, "successfully verified an incorrect signature")
}
