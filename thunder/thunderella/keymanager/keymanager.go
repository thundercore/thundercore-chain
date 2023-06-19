// KeyManager module.
//
// This module provides the core functions of the management of the committee's proposing/voting key,
// including key generation, storage, retrieval and possible rotation. In
// the future, the module can also handles other types of key pairs.
//
// This module is mainly used by the accel admin tool for generating, signing and encrypting accel
// prod's proposing key pairs, by the accel prod for loading BLS key pair, and by the comm prod for
// generating and encrypting their BLS key pairs.
//
// KeyManager handles the following types of keys:
//
// - Comm Voting Key: BLS key pair for signing votes
//
// Considering different options for secure key storage, like password protected key encryption
// with local file storage, AWS and other third party solutions, the design is modularized for
// different options.

package keymanager

import (
	// Standard imports
	"crypto/ecdsa"
	"fmt"
	"sync"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/keymanager/crypto"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/awsutil"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	// Vender imports
	gethCrypto "github.com/ethereum/go-ethereum/crypto"
)

var logger = lgr.NewLgr("/KeyManager")

// SignKeyBlob contains encrypted or un-encrypted private signing key and the meta data.
// The struct is basically designed for serialization to JSON
type SignKeyBlob struct {
	EncryptedPrivateKey *crypto.CipherBlob
	AESKeySalt          []byte
	PrivateKey          []byte
}

// Config contains the information like the owner of key manager, the paths to
// key files, etc.
type Config struct {
	// in base config since password encryption of key data is agnostic to storage (even if
	// some storages are already secure and may not need it, like AWS KMS)
	MustEncryptPrivateKeys bool
}

// KeyManager provides the getters to get different types of keys.
// To provide a consistent interface and more flexibility to the implementations,
// the common argument keyID is unique among different getters.
type KeyManager struct {
	cfg      Config
	keystore Keystore
}

// NewKeyManager returns a KeyManager instance backed by given keystore
func NewKeyManager(config Config, ks Keystore) *KeyManager {
	return &KeyManager{config, ks}
}

func GetTestingKeyGroup(prefix string) string {
	return awsutil.GetFixedUniquePrefix(prefix)
}

// GetCommPrivateVoteKey returns a committee's voting key. Password is used to decrypt the key if
// encryption is enabled.
func (keymgr KeyManager) GetCommPrivateVoteKey(keyID string, commVoteKeyPwd string,
) (*bls.SigningKey, error) {
	keyBlob, err := keymgr.keystore.getCommVoteKey(keyID)
	if err != nil {
		return nil, err
	}
	if keyBlob == nil {
		return nil, fmt.Errorf("%s not found", keyID)
	}
	key, err := getSigningKeyFromKeyBlob(commVoteKeyPwd, keyBlob,
		keymgr.cfg.MustEncryptPrivateKeys)
	if err != nil {
		return nil, err
	}
	logger.Info("Got the committee member private vote key (keyID=%s)", keyID)
	return key, err
}

// GetCommPublicVoteKeys loads all comm's public voting keys from keystore and returns them.
// Note that it may return a non-nil empty data if the non-nil empty data have been stored.
func (keymgr KeyManager) GetCommPublicVoteKeys(
	keyIDs []string, passwords []string) ([]*bls.PublicKey, error) {
	if passwords == nil {
		passwords = make([]string, len(keyIDs))
	}

	if len(keyIDs) != len(passwords) {
		return nil, fmt.Errorf("unmatched length: %d != %d", len(keyIDs), len(passwords))
	}

	var wg sync.WaitGroup
	nKey := uint(len(keyIDs))
	var lock sync.Mutex
	errors := make([]error, nKey)
	pubKeys := make([]*bls.PublicKey, nKey)
	for i, kid := range keyIDs {
		wg.Add(1)
		go func(index int, keyID string) {
			defer wg.Done()

			key, err := keymgr.GetCommPrivateVoteKey(keyID, passwords[index])
			if err != nil {
				lock.Lock()
				defer lock.Unlock()
				errors[index] = err
				return
			}

			lock.Lock()
			defer lock.Unlock()
			pubKeys[index] = &key.PublicKey
		}(i, kid)
	}
	wg.Wait()

	// Check errors.
	for _, err := range errors {
		if err != nil {
			return nil, utils.MergeErrors("ERROR: failed to get some keys.", errors)
		}
	}

	logger.Info("Got the committee member public vote keys")
	return pubKeys, nil
}

// decrypt and store the private key to keyBlob.PrivateKey
func (keyBlob *SignKeyBlob) decryptWithPassword(password string) error {
	// Generate an AES key to decrypt the encrypted private key.
	aesKeyBlob, err := crypto.GenAESKeyByPwd(password, keyBlob.AESKeySalt)
	if err != nil {
		return err
	}

	// Decrypt the encrypted private key.
	keyBlob.PrivateKey, err = crypto.DecryptWithAES(
		keyBlob.EncryptedPrivateKey, aesKeyBlob.KeyValue)
	if err != nil {
		return err
	}

	return nil
}

// GetAccountKey loads the account key from keystore and return it.
// Use password to decrypt the encrypted key if hasPassword is true, otherwise
// read password from console if the key is encrypted.
func (keymgr KeyManager) GetAccountKey(keyID, password string,
	prompt string, hasPassword bool) (*ecdsa.PrivateKey, error) {
	keyBlob, err := keymgr.keystore.getAccountKey(keyID)
	if err != nil {
		return nil, err
	}

	if keyBlob == nil {
		return nil, fmt.Errorf("%s not found", keyID)
	}

	if keyBlob.PrivateKey == nil {
		if keyBlob.EncryptedPrivateKey == nil {
			return nil, fmt.Errorf("there is no key")
		}

		if !hasPassword {
			password, err = utils.ReadPassword(prompt)
			if err != nil {
				return nil, fmt.Errorf("failed to read password: %s", err)
			}
		}
		err := keyBlob.decryptWithPassword(password)
		if err != nil {
			return nil, err
		}
	}

	key, err := gethCrypto.ToECDSA(keyBlob.PrivateKey)
	if err != nil {
		return nil, err
	}
	logger.Info("Got the committee member stake-in account key (keyID=%s)", keyID)
	return key, err
}
