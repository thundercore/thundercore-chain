package keymanager

import (
	// Standard imports
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"time"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/keymanager/crypto"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
)

const (
	// CertificateIssuer is Thunder Token by default.
	CertificateIssuer = "Thunder Token Inc."
)

// AccelCertificate binds the identity of an accel with its public key and
// signed by Accel's master key.
//
// If the key is the Accel master key, the certificate will be self-signed.
type AccelCertificate struct {
	Version      uint32 // version number
	SerialNumber *big.Int

	// All time values are in seconds since the epoch, typecasted to
	// uint64 from int64.
	NotBefore, NotAfter uint64 // Validity bounds.
	IssueDate           uint64 // The time when the certificate was issued.

	// We hex-encode the ToBytes() encoding of the PublicKey since
	// it contains private / unexported fields (see BLS module).
	PublicKey []byte

	// The base type is x509.SignatureAlgorithm. We use uint32 to have a
	// predictable integer width.
	// Only ever takes the value ECDSAWithSHA256.
	SignatureAlgorithm uint32
	// TODO: change Issuer and Subject to pkix.Name
	Issuer  string // Accel admin (Thunder Token)
	Subject string // Accel name or id

	// The base type is x509.KeyUsage. We use uint32 to have a predictable
	// integer width.
	// Only ever takes the value KeyUsageDigitalSignature.
	KeyUsage  uint32
	Signature *crypto.ECDSASignature // Certificate signature
}

// Validate checks the validity of an accelerator certificate. Currently it only checks time ranges.
// The checkNow parameter specifies if we want to consider the certificate as active right now or
// not. If yes, then we perform an additional verification of checking that the current time is
// between NotBefore and NotAfter.
func (cert *AccelCertificate) Validate(checkNow bool) error {
	// Time range validation.
	// TODO: what other validations should we perform?
	now := uint64(time.Now().Unix())
	if cert.NotAfter <= cert.NotBefore {
		return errInvalidBounds
	}
	if cert.IssueDate > cert.NotBefore {
		return errIssueDateLaterThanNotBefore
	}
	if checkNow {
		if now < cert.NotBefore {
			return errCertNotValidYet
		} else if now > cert.NotAfter {
			return errCertExpired
		}
	}
	return nil
}

// Verify verifies an accelerator certificate against the signature that
// it contains.
func (cert *AccelCertificate) Verify(pub *ecdsa.PublicKey) error {
	verified, err := crypto.VerifyWithECDSA(
		cert.ToBytesWithoutSignature(), pub, cert.Signature)
	if err != nil {
		return err
	} else if !verified {
		return errCertVerificationFailed
	} else {
		return nil
	}
}

// GetPublicKey hex-decodes the PublicKey field of an AccelCertificate,
// then decodes the resultant bytes back into a bls.PublicKey struct.
func (cert *AccelCertificate) GetPublicKey() (*bls.PublicKey, error) {
	return bls.PublicKeyFromBytes(cert.PublicKey)
}

// newAccelCertificate generates an accelerator certificate with some
// standard field values without the signature.
// The Version field is 2 as described in
//    https://tools.ietf.org/html/rfc5280#section-4.1.2.1

func newAccelCertificate(
	accelSubject string,
	propKey *bls.SigningKey,
	notBefore,
	notAfter,
	issueDate time.Time,
) (*AccelCertificate, error) {
	sn := make([]byte, 20)
	_, err := rand.Read(sn)
	if err != nil {
		return nil, err
	}
	return &AccelCertificate{
		Version:            uint32(1),
		SerialNumber:       big.NewInt(0).SetBytes(sn),
		NotBefore:          uint64(notBefore.Unix()),
		NotAfter:           uint64(notAfter.Unix()),
		IssueDate:          uint64(issueDate.Unix()),
		PublicKey:          propKey.PublicKey.ToBytes(),
		SignatureAlgorithm: uint32(x509.ECDSAWithSHA256),
		Issuer:             CertificateIssuer,
		Subject:            accelSubject,
		KeyUsage:           uint32(x509.KeyUsageDigitalSignature),
		Signature:          nil,
	}, nil
}

// signAndStore signs an accelerator certificate with the given private
// master key, then stores the signature in the certificate.
func (cert *AccelCertificate) signAndStore(privKey *ecdsa.PrivateKey) (
	*crypto.ECDSASignature, error,
) {
	sig, err := crypto.SignWithECDSA(cert.ToBytesWithoutSignature(), privKey)
	if err != nil {
		return nil, err
	}
	cert.Signature = sig
	return sig, nil
}
