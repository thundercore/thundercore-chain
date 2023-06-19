// This library provides in-memory implementation of Keystore and methods to instantiate KeyManager
// backed by this in-memory keystore. They prove very useful in writing unit tests in modules like
// daemon & consensus, which needs keys only ephimerally (for the duration of tests) and don't need
// the hassle of managing test keys in git repo.
package keymanager

import (
	"fmt"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"
)

type MemKeyStoreConfig struct {
	AccelIDs          []string
	VoteKeyIDs        []string
	AccountKeyIDs     []string
	MakeEmptyVoteKeys bool
}

// SetupTestingKeystore instantiates an in-memory keystore, generates accels' prop key pair,
// committee members' vote key pairs, and returns the keystore.
// Note that accelerator ids used are "0", "1", "2", ...
func SetupTestingKeystore(cfg MemKeyStoreConfig) Keystore {
	var err error
	keystore := newMemKeystore()
	keygen := &KeyGenerator{keystore: keystore}
	// Generate committee public voting keys and Accelerators' proposing keys
	if len(cfg.AccelIDs) > 0 || cfg.MakeEmptyVoteKeys {
		err = keygen.GenAndStoreMultiCommVoteKey(cfg.AccelIDs)
		if err != nil {
			debug.Fatal("Failed to generate vote keys. err=%s", err)
		}
	}
	commSize := uint(len(cfg.VoteKeyIDs))
	if commSize > 0 || cfg.MakeEmptyVoteKeys {
		err = keygen.GenAndStoreMultiCommVoteKey(cfg.VoteKeyIDs)
		if err != nil {
			debug.Fatal("Failed to generate vote keys. err=%s", err)
		}
	}
	passwords := make([]string, len(cfg.AccountKeyIDs))
	err = keygen.GenAndStoreMultiAccountKeys(cfg.AccountKeyIDs, passwords)
	if err != nil {
		debug.Fatal("Failed to generate account keys. err=%s", err)
	}
	return keystore
}

// NewKeyManagerFromMemKeystore instantiates new keymanager backed by given memKeystore
func NewKeyManagerFromMemKeystore(keystore Keystore) *KeyManager {
	return &KeyManager{
		keystore: keystore,
	}
}

func newMemKeystore() *memKeystore {
	return &memKeystore{
		keys: make(map[string]interface{}),
	}
}

// memKeystore is goroutine-safe.
type memKeystore struct {
	utils.CheckedLock
	keys map[string]interface{}
}

func (mk *memKeystore) getMasterCert() ([]byte, error) {
	mk.Lock()
	defer mk.Unlock()
	// Read in the certificate bytes from hard-coded certificate
	logger.Info("Loading Accel Master Key Cert from built-in PEM")
	return []byte(masterCert), nil
}

func (mk *memKeystore) getMasterKey() ([]byte, error) {
	mk.Lock()
	defer mk.Unlock()
	return []byte(encryptedMasterKey), nil
}

func (mk *memKeystore) getKey(keyID string) (interface{}, error) {
	mk.CheckIsLocked("lock is not hold")
	v, ok := mk.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%s does not exist", keyID)
	}
	return v, nil
}

func (mk *memKeystore) getCommVoteKey(keyID string) (*SignKeyBlob, error) {
	mk.Lock()
	defer mk.Unlock()
	v, err := mk.getKey(keyID)
	if err != nil {
		return nil, err
	}
	v2, ok := v.(*SignKeyBlob)
	if !ok {
		return nil, fmt.Errorf("%s is not SignKeyBlob. type=%T", keyID, v)
	}
	return v2, nil
}

func (mk *memKeystore) storeCommVoteKey(keyID string, key *SignKeyBlob) error {
	mk.Lock()
	defer mk.Unlock()
	mk.keys[keyID] = key
	return nil
}
func (mk *memKeystore) getAccountKey(keyID string) (*SignKeyBlob, error) {
	mk.Lock()
	defer mk.Unlock()
	v, err := mk.getKey(keyID)
	if err != nil {
		return nil, err
	}
	v2, ok := v.(*SignKeyBlob)
	if !ok {
		return nil, fmt.Errorf("%s is not SignKeyBlob. type=%T", keyID, v)
	}
	return v2, nil
}

func (mk *memKeystore) storeAccountKey(keyID string, key *SignKeyBlob) error {
	mk.Lock()
	defer mk.Unlock()
	mk.keys[keyID] = key
	return nil
}
