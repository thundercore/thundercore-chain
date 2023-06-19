package keymanager

import (
	"crypto/ecdsa"
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/thunder/thunderella/keymanager/crypto"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	gethCrypto "github.com/ethereum/go-ethereum/crypto"
)

// KeyGenerator provides functionality to generate proposing keys for accelerator and signing keys
// for committee members.
type KeyGenerator struct {
	// cfg is read-only after KeyGenerator is created.
	cfg Config
	// keystore's operations are all goroutine-safe.
	keystore Keystore
}

type StoreProposalKeyInput struct {
	KeyID              string
	PrivateKey         *bls.SigningKey
	PrivateKeyPassword string
	Certificate        *AccelCertificate
}

type StoreVoteKeyInput struct {
	KeyID              string
	PrivateKey         *bls.SigningKey
	PrivateKeyPassword string
}

type StoreAccountKeyInput struct {
	KeyID      string
	Password   string
	PrivateKey *ecdsa.PrivateKey
}

// NewKeyManager returns a KeyManager instance backed by given keystore
// TODO: maybe we can remove the rolechecks in functions below now that we have split out
// admin functionality into separate struct
func NewKeyGenerator(config Config, keystore Keystore) *KeyGenerator {
	return &KeyGenerator{config, keystore}
}

// GenAndStoreMultiCommVoteKey generates multiple committee voting keys and saves them to the keystore.
// Private keys are stored separately, whereas all public keys get saved together as a slice.
//
// NOTE:
// 1. An empty keyIDs is allowed.
// 2. Expect only used by thundertool.
func (keygen KeyGenerator) GenAndStoreMultiCommVoteKey(keyIDs []string) error {
	commSize := uint(len(keyIDs))
	// Prepare the passwords.
	passwords := []string{}
	for i := uint(0); i < commSize; i++ {
		var commVoteKeyPwd string
		if keygen.cfg.MustEncryptPrivateKeys {
			tempVoteKeyPwd, err := utils.ReadVerifiedPassword(fmt.Sprintf(
				"Enter passphrase for committee %d voting key: ", i))
			if err != nil {
				debug.Fatal("Cannot process the password: %s\n", err)
			}
			commVoteKeyPwd = tempVoteKeyPwd
		}
		passwords = append(passwords, commVoteKeyPwd)
	}

	// Generate keys.
	var err error
	inputs := make([]StoreVoteKeyInput, commSize)
	keys := make([]*bls.SigningKey, commSize)
	for i := 0; i < len(keys); i++ {
		inputs[i].PrivateKey, err = bls.NewSigningKey()
		if err != nil {
			return err
		}
		inputs[i].KeyID = keyIDs[i]
		inputs[i].PrivateKeyPassword = passwords[i]
	}

	return keygen.StoreVoteKeys(inputs)
}

func (keygen KeyGenerator) StoreVoteKeys(inputs []StoreVoteKeyInput) error {
	// Store keys in parallel.
	var wg sync.WaitGroup
	var lock sync.Mutex // Protect commInfo.MemberInfo and errors.
	commSize := uint(len(inputs))
	errors := make([]error, commSize)
	// Make pub key array.
	pubKeys := make([]*bls.PublicKey, commSize)
	for i := uint(0); i < commSize; i++ {
		wg.Add(1)
		go func(index uint) {
			defer wg.Done()

			commVoteKeyBlob, err := getKeyBlobFromSigningKey(
				inputs[index].PrivateKeyPassword,
				inputs[index].PrivateKey,
				keygen.cfg.MustEncryptPrivateKeys)
			if err == nil {
				err = keygen.keystore.storeCommVoteKey(inputs[index].KeyID, commVoteKeyBlob)
			}

			lock.Lock()
			defer lock.Unlock()
			if err != nil {
				err = fmt.Errorf(
					"ERROR: Cannot generate committee %d's voting key. err=%v",
					index, err)
				errors[index] = err
			} else {
				logger.Info("Generated committee %d's voting key with KeyID=%s.",
					index, inputs[index].KeyID)
				pubKeys[index] = &bls.PublicKey{
					Pk: inputs[index].PrivateKey.GetPublicKey().Pk}
			}
		}(i)
	}
	wg.Wait()

	// Combine the results in order.
	return utils.MergeErrors("Cannot generate committee voting key:", errors)
}

// GenAndStoreMultiAccountKeys generates multiple account keys
// and saves them to the keystore. If private keys should be encrypted, given passwords are
// used for encryption. Ask the user the passwords if passwords is nil
// and keygen.cfg.MustEncryptPrivateKeys is true.
func (keygen KeyGenerator) GenAndStoreMultiAccountKeys(
	keyIDs []string, passwords []string,
) error {
	numKeys := uint(len(keyIDs))
	if keygen.cfg.MustEncryptPrivateKeys {
		if passwords == nil {
			passwords = preparePasswords(numKeys, true)
		}
	} else {
		// Ensure passwords contain empty strings,
		// so genAndStoreAccountKey() will not encrypt the key.
		passwords = preparePasswords(numKeys, false)
	}

	// Generate keys.
	inputs := make([]StoreAccountKeyInput, numKeys)
	var err error
	for i := uint(0); i < numKeys; i++ {
		// NOTE: Because the stake-in account key is used in go-ethereum,
		// Follow go-ethereum to generate the key using secp256k1.
		inputs[i].PrivateKey, err = gethCrypto.GenerateKey()
		if err != nil {
			return err
		}
		inputs[i].KeyID = keyIDs[i]
		inputs[i].Password = passwords[i]
	}

	return keygen.StoreMultiAccountKeys(inputs)
}

func (keygen KeyGenerator) StoreMultiAccountKeys(inputs []StoreAccountKeyInput) error {
	// Store keys in parallel.
	var wg sync.WaitGroup
	var errorsLock sync.Mutex
	numKeys := uint(len(inputs))
	errors := make([]error, numKeys)
	for i := uint(0); i < numKeys; i++ {
		wg.Add(1)
		go func(index uint) {
			defer wg.Done()
			// Convert ecdsa.PrivateKey to SignKeyBlob.
			keyBlob, err := toAccountKeyBlob(&inputs[index], keygen.cfg.MustEncryptPrivateKeys)
			if err == nil {
				err = keygen.keystore.storeAccountKey(inputs[index].KeyID, keyBlob)
			}
			if err != nil {
				errorsLock.Lock()
				defer errorsLock.Unlock()
				err = fmt.Errorf(
					"ERROR: Cannot store committee %d's stake-in account key. err=%s",
					index, err)
				errors[index] = err
				return
			}
			logger.Info("Generated committee %d's stake-in account key with KeyID=%s.",
				index, inputs[index].KeyID)
		}(i)
	}
	wg.Wait()

	// Combine the results in order.
	return utils.MergeErrors("Cannot generate committee stake-in account key:", errors)
}

func toAccountKeyBlob(input *StoreAccountKeyInput, mustEncrypt bool) (*SignKeyBlob, error) {
	var keyBlob SignKeyBlob
	keyBlob.PrivateKey = gethCrypto.FromECDSA(input.PrivateKey)
	if keyBlob.PrivateKey == nil {
		return nil, fmt.Errorf("cannot convert ECDSA key to bytes")
	}
	if mustEncrypt {
		// Generate an AES key to encrypt the private key.
		aesKeyBlob, err := crypto.GenAESKeyByPwd(input.Password, []byte(nil))
		if err != nil {
			return nil, err
		}

		// Encrypt the private proposing key.
		cipherBlob, err := crypto.EncryptWithAES(keyBlob.PrivateKey, aesKeyBlob.KeyValue)
		if err != nil {
			return nil, err
		}
		keyBlob.EncryptedPrivateKey = cipherBlob
		keyBlob.AESKeySalt = aesKeyBlob.Salt
		keyBlob.PrivateKey = nil
	}
	return &keyBlob, nil
}

func preparePasswords(numPasswords uint, askUser bool) []string {
	passwords := make([]string, numPasswords)
	if !askUser {
		return passwords
	}

	var err error
	for i := uint(0); i < numPasswords; i++ {
		passwords[i], err = utils.ReadVerifiedPassword(fmt.Sprintf(
			"Enter passphrase for committee %d stake-in account key: ", i))
		if err != nil {
			debug.Fatal("Cannot process the password: %s\n", err)
		}
	}
	return passwords
}
