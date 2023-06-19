/*
 * BLS library based on BN256.
 */

package bls

import (
	// Standard imports.
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"

	// Thunder imports.
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls/bn256"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/ethereum/go-ethereum/rlp"
)

//
// Recall the signature scheme here is
//  pk : g2^x
//  sk : x
//  sign(sk, m) : H(m)^x  where H(m) maps m to the G1 curve
//  ver(pk, m, sigma) : check e(sigma, g2) =? e(H(m), pk )
//
//  Aggregation can occur as follows:
//
//

// PublicKey is the BLS public key.
type PublicKey struct {
	Pk *bn256.G2
}

// SigningKey is the BLS private key.
type SigningKey struct {
	PublicKey
	x *big.Int
}

// Signature is BLS signature
type Signature struct {
	sigma *bn256.G1
}

var (
	// Is this the only way to get g2 generator?
	one = (&big.Int{}).SetInt64(1)
	g2  = (&bn256.G2{}).ScalarBaseMult(one)

	// JSON keys.
	skJSONKey = "SigningKey"
)

// NewSigningKey generates a new BLS key pair.
func NewSigningKey() (*SigningKey, error) {
	var sk SigningKey
	var err error

	sk.x, sk.Pk, err = bn256.RandomG2(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &sk, nil
}

// GetPublicKey returns the public key of the BLS key pair.
func (sk *SigningKey) GetPublicKey() *PublicKey {
	var pk PublicKey
	pk.Pk = sk.Pk
	return &pk
}

// Sign signs a piece of data (byte array) using the BLS private key.
func (sk *SigningKey) Sign(msg []byte) *Signature {
	//  H(m)^x
	sigma := bn256.HashG1(msg)

	sigma = sigma.ScalarMult(sigma, sk.x)

	return &Signature{sigma: sigma}
}

// VerifySignature verifies the BLS signature using the public key.
func (pk *PublicKey) VerifySignature(msg []byte, sig *Signature) bool {
	//  check e(sigma, g2) =? e(H(m), pk )
	h := bn256.HashG1(msg)

	rhs := bn256.Pair(h, pk.Pk)
	lhs := bn256.Pair(sig.sigma, g2)

	return rhs.Eql(lhs)
}

// CombineSignatures and CombinePublicKeys combine signatures and public keys.
//   - sig1 = H(m)^x1 and sig2 = H(m)^x2
//   - pk1 = g2^x1 and pk2 = g2^x2
// therefore, the combined signature is simple sig1*sig1 for the
// new pk is pk1*pk2
func CombineSignatures(sig1, sig2 *Signature,
	pk1, pk2 *PublicKey,
) (*Signature, *PublicKey) {
	sig := Signature{
		sigma: new(bn256.G1).Add(sig1.sigma, sig2.sigma),
	}
	return &sig, CombinePublicKeys(pk1, pk2)
}

// CombinePublicKeys combines two BLS public keys.
func CombinePublicKeys(pk1, pk2 *PublicKey) *PublicKey {
	pk := PublicKey{
		Pk: new(bn256.G2).Add(pk1.Pk, pk2.Pk),
	}

	return &pk
}

func (sk *SigningKey) Copy() *SigningKey {
	newSk := SigningKey{
		x: new(big.Int).Set(sk.x),
	}

	newSk.PublicKey.Pk = new(bn256.G2).ScalarBaseMult(sk.x)

	return &newSk
}

// ToBytes serializes the BLS private key to byte array.
func (sk *SigningKey) ToBytes() []byte {
	return sk.x.Bytes()
}

// SigningKeyFromBytes de-serializes a byte array to a BLS private key.
func SigningKeyFromBytes(b []byte) *SigningKey {
	var sk SigningKey
	sk.x = new(big.Int).SetBytes(b)
	if sk.x.Cmp(bn256.Order) >= 0 {
		debug.Bug("Signing key out of range")
	}
	sk.Pk = new(bn256.G2).ScalarBaseMult(sk.x)
	return &sk
}

// SigningKeyFromJSONFile constructs a BLS private key from a JSON file.
// This function is actually used for BLS unit test.
func SigningKeyFromJSONFile(filename *string) (*SigningKey, error) {
	bytes, err := utils.BytesFromJSONFile(filename, &skJSONKey)
	if err != nil {
		return nil, err
	}
	sk := SigningKeyFromBytes(*bytes)
	return sk, nil
}

func (pk *PublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(pk.Pk.Marshal())
}

func (pk *PublicKey) UnmarshalJSON(buf []byte) error {
	var bytes []byte
	json.Unmarshal(buf, &bytes)
	return pk.FromBytes(bytes)
}

func (pk *PublicKey) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, pk.ToBytes())
}

func (pk *PublicKey) DecodeRLP(s *rlp.Stream) error {
	var bytes []byte
	if err := s.Decode(&bytes); err != nil {
		return err
	}
	return pk.FromBytes(bytes)
}

// ToBytes serializes the BLS public key to byte array.
func (pk *PublicKey) ToBytes() []byte {
	return pk.Pk.Marshal()
}

// ToBytes serializes the BLS public key to byte array.
func (pk *PublicKey) FromBytes(bytes []byte) error {
	g2x, ok := (&bn256.G2{}).Unmarshal(bytes)
	if !ok {
		return fmt.Errorf("cannot parse public key")
	}
	pk.Pk = g2x
	return nil
}

// PublicKeyFromBytes de-serializes a byte array to a BLS public key.
func PublicKeyFromBytes(data []byte) (*PublicKey, error) {
	pk := PublicKey{}
	if err := pk.FromBytes(data); err != nil {
		return nil, err
	}
	return &pk, nil
}

// ToBytes serializes the BLS signature to byte array.
func (sig *Signature) ToBytes() []byte {
	return sig.sigma.Marshal()
}

// SignatureFromBytes de-serializes a byte array to a BLS signature.
func SignatureFromBytes(data []byte) (*Signature, error) {
	sigma, ok := (&bn256.G1{}).Unmarshal(data)
	if !ok {
		return nil, fmt.Errorf("cannot parse signature")
	}
	sig := Signature{
		sigma: sigma,
	}
	return &sig, nil
}

func (sig *Signature) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, sig.ToBytes())
}

func (sig *Signature) DecodeRLP(s *rlp.Stream) error {
	var bytes []byte
	if err := s.Decode(&bytes); err != nil {
		return err
	}
	var sig2 *Signature
	var err error
	if sig2, err = SignatureFromBytes(bytes); err == nil {
		sig.sigma = sig2.sigma
		return nil
	}
	return err
}
