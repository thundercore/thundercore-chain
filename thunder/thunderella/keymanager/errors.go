package keymanager

import (
	"errors"
)

var (
	// Accelerator certificate errors
	errIssueDateLaterThanNotBefore = errors.New(
		"issue date must be earlier than NotBefore date")

	errCertNotValidYet = errors.New(
		"certificate is not valid until NotBefore date")

	errCertExpired = errors.New(
		"certificate is only valid before NotAfter date")

	errCertVerificationFailed = errors.New(
		"failed to verify proposing key certificate")

	errInvalidBounds = errors.New(
		"NotAfter date must be strictly after NotBefore date")

	errPropKeyFilePathEmpty = errors.New(
		"no accel proposing key file path specified")

	errCommVoteKeyFilePathEmpty = errors.New(
		"no comm voting key file path specified")

	errAccountKeyFilePathEmpty = errors.New(
		"no account key file path specified")

	// Misc errors
	errUnencryptedPrivateKeyIsEmpty = errors.New(
		`PrivateKey in key blob is empty even though private key
		encryption is disabled`)

	errEncryptedPrivateKeyIsNil = errors.New(
		`EncryptedPrivateKey in key blob is nil even though private key
		encryption is disabled`)
)
