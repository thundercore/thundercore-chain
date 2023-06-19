// Core crypto module.
//
// This module deals with all crypto relevant functions, including encryption,
// non-BLS sign and verify, password based key derivation, etc.
//
// TODO: investigate if/how we move bls under crypto as well.
//
// It works as a wrapper of crypto libraries of golang and provides clean crypto
// APIs for other Thunder modules.

package crypto

import (
	// Standard imports
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"

	// Vendor imports
	"golang.org/x/crypto/pbkdf2"
)

var (
	errNilSignature  = errors.New("ECDSA signature pointer is nil")
	errNilPrivateKey = errors.New("private key pointer is nil")
	errNilPublicKey  = errors.New("public key pointer is nil")
	errEmptyData     = errors.New("data is an empty byte array")
)

// Cipher blob for AES encryption/decryption includes both the cipher text and
// nonce (IV). Both are HEX encoded.
type CipherBlob struct {
	CipherText []byte
	Nonce      []byte
}

// PBKDFKeyBlob includes a salt in plaintext used to generated the key and the
// key value.
type PBKDFKeyBlob struct {
	Salt     []byte
	KeyValue []byte
}

// ECDSASignature wraps ECDSA signature. It is also used for JSON serialization
type ECDSASignature struct {
	R *big.Int
	S *big.Int
}

const (
	aesKeyLen = 32    // AES-256 key size in bytes
	nonceLen  = 12    // Default length of nonce (IV) in bytes (96 bits) for AES-GCM
	saltLen   = 24    // Salt length in bytes for password based key derivation function
	iter      = 30000 // SHA256 on 64 bytes for 1 second
)

// GenAESKeyByPwd generates a 256-bit AES key from a password and a salt using
// predefined iteration.
//
// The password is in plaintext. If the input salt is empty, a new salt will be
// generated.
func GenAESKeyByPwd(password string, salt []byte) (*PBKDFKeyBlob, error) {
	var err error
	if len(salt) == 0 {
		if salt, err = genRandom(saltLen); err != nil {
			return nil, err
		}
	} else if len(salt) != saltLen {
		return nil, fmt.Errorf(
			"invalid salt length: %d", len(salt))
	}

	keyValue := pbkdf2.Key([]byte(password), salt, iter, aesKeyLen,
		sha256.New)
	keyBlob := &PBKDFKeyBlob{
		salt,
		keyValue,
	}
	return keyBlob, nil
}

// EncryptWithAES encrypts a string with AES-256-GCM.
// It returns a CipherBlob including ciphertext and IV. Both are HEX encoded.
func EncryptWithAES(plaintext, key []byte) (*CipherBlob, error) {
	if err := checkAESKeyLen(key); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce, err := genRandom(nonceLen)
	if err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	return &CipherBlob{
		ciphertext,
		nonce,
	}, nil
}

// DecryptWithAES decrypts ciphertext with AES-256-GCM
func DecryptWithAES(cipherblob *CipherBlob, key []byte) ([]byte, error) {
	var empty []byte

	if cipherblob == nil {
		return empty, fmt.Errorf("CipherBlob is nil")
	}

	if err := checkAESKeyLen(key); err != nil {
		return empty, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return empty, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return empty, err
	}

	plaintext, err := aesgcm.Open(nil,
		cipherblob.Nonce, cipherblob.CipherText, nil)
	if err != nil {
		return empty, err
	}
	return plaintext, nil
}

// checksum returns the SHA-256 checksum of a byte array
func checksum(data []byte) []byte {
	hashed := sha256.Sum256(data)
	return hashed[:]
}

// GenECDSAKey generates an ECDSA public and private keypair as defined in
// FIPS 186-3. The public key is an unexported field of the
// PrivateKey struct type, accessible via (*PrivateKey).Public().
// See also: https://golang.org/pkg/crypto/ecdsa/#PrivateKey
func GenECDSAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// SignWithECDSA signs the SHA256 hash of the input byte array with an ECDSA
// private key and returns the signature.
func SignWithECDSA(data []byte,
	priv *ecdsa.PrivateKey,
) (sig *ECDSASignature, err error) {
	if len(data) == 0 {
		return nil, errEmptyData
	}
	digest := checksum(data)
	if priv == nil {
		return nil, errNilPrivateKey
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		return nil, err
	}
	return &ECDSASignature{r, s}, nil
}

// GetECDSAPublicKey get a pointer to the ECDSA public key from an
// ecdsa.PrivateKey struct. A type assertion is necessary since
// the PublicKey field in the ecdsa.PrivateKey struct is an
// interface field.
func GetECDSAPublicKey(priv *ecdsa.PrivateKey) *ecdsa.PublicKey {
	return priv.Public().(*ecdsa.PublicKey)
}

// VerifyWithECDSA uses a public ECDSA key and a signature to verify that the
// signature was obtained from the corresponding private key on the hash of
// the given data.
func VerifyWithECDSA(data []byte, pub *ecdsa.PublicKey,
	sig *ECDSASignature,
) (bool, error) {
	if len(data) == 0 {
		return false, errEmptyData
	}
	digest := checksum(data)
	if pub == nil {
		return false, errNilPublicKey
	} else if sig == nil {
		return false, errNilSignature
	}
	return ecdsa.Verify(pub, digest, sig.R, sig.S), nil
}

// checkAESKeyLen returns an error if the input AES key does not have
// the expected length (we only use AES-256).
func checkAESKeyLen(key []byte) error {
	if len(key) != aesKeyLen {
		return fmt.Errorf("key length is not %d bytes", aesKeyLen)
	}
	return nil
}

// genRandom generates a byte array with the specified length and fills it
// with random values.
func genRandom(length uint) ([]byte, error) {

	random := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return nil, err
	}
	return random, nil
}
