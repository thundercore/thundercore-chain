package keymanager

import (
	// Standard imports
	"encoding/binary"
	"encoding/json"
)

// This file contains utility methods for serializing and
// deserializing an accelerator certificate.

// appendMultiple appends multiple byte arrays together into
// one byte array.  The lengths of the arrays are prepended
// onto the list to make the serialization format canonical.
func appendMultiple(byteArrays ...[]byte) []byte {
	totalLen := 0
	for _, array := range byteArrays {
		totalLen += len(array) + 4
	}

	result := make([]byte, totalLen)
	offset := 0
	for _, array := range byteArrays {
		lenArray := uint32ToBytes(uint32(len(array)))
		copy(result[offset:offset+4], lenArray)
		offset += 4
		copy(result[offset:offset+len(array)], array)
		offset += len(array)
	}

	return result
}

// uint32 <-> []byte
func uint32ToBytes(n uint32) []byte {
	var result [4]byte
	binary.LittleEndian.PutUint32(result[:], n)
	return result[:]
}

func bytesToUint32(bytes []byte) uint32 {
	return binary.LittleEndian.Uint32(bytes)
}

// uint64 <-> bytes
func uint64ToBytes(n uint64) []byte {
	var result [8]byte
	binary.LittleEndian.PutUint64(result[:], n)
	return result[:]
}

func bytesToUint64(bytes []byte) uint64 {
	return binary.LittleEndian.Uint64(bytes)
}

// ToBytes serializes an AccelCertificate to byte array, excluding the signature field.
func (cert *AccelCertificate) ToBytesWithoutSignature() []byte {
	version := uint32ToBytes(cert.Version)
	serialNumber := cert.SerialNumber.Bytes()
	notBefore := uint64ToBytes(cert.NotBefore)
	notAfter := uint64ToBytes(cert.NotAfter)
	issueDate := uint64ToBytes(cert.IssueDate)
	publicKey := cert.PublicKey
	signatureAlgorithm := uint32ToBytes(cert.SignatureAlgorithm)
	issuer := []byte(cert.Issuer)
	subject := []byte(cert.Subject)
	keyUsage := uint32ToBytes(cert.KeyUsage)
	return appendMultiple(
		version,
		serialNumber,
		notBefore,
		notAfter,
		issueDate,
		publicKey,
		signatureAlgorithm,
		issuer,
		subject,
		keyUsage)
}

func (cert *AccelCertificate) ToBytes() ([]byte, error) {
	return json.Marshal(cert)
}

func AccelCertificateFromBytes(b []byte) (*AccelCertificate, error) {
	var cert AccelCertificate
	if err := json.Unmarshal(b, &cert); err != nil {
		return nil, err
	}
	return &cert, nil
}
