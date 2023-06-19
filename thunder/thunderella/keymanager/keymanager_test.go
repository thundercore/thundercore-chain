package keymanager

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/thunder/thunderella/keymanager/crypto"

	// Vendor imports
	"github.com/stretchr/testify/require"
)

var (
	accelCertNotBefore = time.Now().AddDate(0, 0, -1)
	accelCertNotAfter  = time.Now().AddDate(2, 0, -1)
	accelCertIssueDate = time.Now().AddDate(0, 0, -2)
)

// Interface to test keymanager/store functionality in abstract way where different keystore
// implementations can share common test function by injecting Keystore specific impl.
// The functions should return new instances, but backed by same config across calls so that actions
// in test simulate same behavior as user interaction over time (passing in same flags) and
// qualities like consistency, persistence, etc.
type keyStoreTester interface {
	config() *Config
	newKeystore() Keystore
}

type keyManagerTester struct {
	keyStoreTester
	keyDir string
}

func (tkm keyManagerTester) newKeymgr() *KeyManager {
	return NewKeyManager(*tkm.config(), tkm.newKeystore())
}

func (tkm keyManagerTester) newKeygen() *KeyGenerator {
	return NewKeyGenerator(*tkm.config(), tkm.newKeystore())
}

func (tkm *keyManagerTester) clean() {
	os.RemoveAll(tkm.keyDir)
}

// Tester for filesystem based implementation of keystore.
// TODO: move fs specific logic out of this file just like aws specific testing logic lives
// in separate file.
type fsKeyStoreTester struct {
	cfg FsKeystoreConfig
}

func (fsT *fsKeyStoreTester) newKeystore() Keystore {
	return NewFsKeystore(fsT.cfg)
}

func (fsT *fsKeyStoreTester) config() *Config {
	return &fsT.cfg.Config
}

func newFSTestingKeyManager(encryptKeys bool, keyDir string, t *testing.T) keyManagerTester {
	if keyDir == "" {
		// Make a temp dir in the default location.
		var err error
		keyDir, err = ioutil.TempDir("", "keystore_")
		require.Nil(t, err, "Can't create home dir for keys %s: %s", keyDir, err)
	}
	fsKeyStore := &fsKeyStoreTester{
		cfg: FsKeystoreConfig{
			Config: Config{
				MustEncryptPrivateKeys: encryptKeys,
			},
			DirPath: keyDir,
		},
	}
	return keyManagerTester{
		keyStoreTester: fsKeyStore,
		keyDir:         keyDir,
	}

}

func checkFileWasWrittenToDisk(t *testing.T, path string, desc string) {
	require := require.New(t)
	_, err := os.Stat(path)
	report := fmt.Sprintf("%s file '%s' wasn't written to disk", desc, path)
	require.Nil(err, report)
}

func testGenAndLoadMultiCommVoteKeys(t *testing.T, mustEncryptPrivateKeys bool) {
	require := require.New(t)
	const commSize = 5

	testkm := newFSTestingKeyManager(mustEncryptPrivateKeys, "", t)

	keyIDs := GetKeyIDsForFS(commSize, VotingKeyType, 0)
	err := testkm.newKeygen().GenAndStoreMultiCommVoteKey(keyIDs)
	require.NoError(err)

	// Check if all key files are written to the disk
	fsKeystore := testkm.newKeystore().(*fsKeystore)
	path := filepath.Join(fsKeystore.cfg.DirPath, fsKeyStoreFilename)
	for i := 0; i < commSize; i++ {
		curID := fmt.Sprint(i)
		// Check the files have been created
		checkFileWasWrittenToDisk(t, path, "voting key blob file for Comm"+curID)
	}
	keymgr := testkm.newKeymgr()
	pubVoteKeys, err := keymgr.GetCommPublicVoteKeys(keyIDs, nil)
	require.Nil(err, "failed to load multi comm public voting keys")

	for i, publicKey := range pubVoteKeys {
		signKey, err := keymgr.GetCommPrivateVoteKey(keyIDs[i], "")
		require.NoError(err, "error getting private key for comm %d", i)
		require.True(checkPublicAndSignKeyPair(publicKey, signKey),
			"signkey and public key for comm %d do not match", i)
	}
	testkm.clean()
}

func TestGenAndLoadCommVoteKeyFromFileSystem(t *testing.T) {
	testGenAndLoadMultiCommVoteKeys(t, true)
	testGenAndLoadMultiCommVoteKeys(t, false)
}

func TestGenAndLoadAccountKeysFromFileSystem(t *testing.T) {
	keyIDs := GetKeyIDsForFS(2, StakeInAccountKeyType, 0)
	testkm := newFSTestingKeyManager(true, "", t)
	defer testkm.clean()
	testGenAndLoadAccountKeys(t, testkm, keyIDs)

	testkm = newFSTestingKeyManager(false, "", t)
	defer testkm.clean()
	testGenAndLoadAccountKeys(t, testkm, keyIDs)
}

func testGenAndLoadAccountKeys(t *testing.T, testkm keyManagerTester, keyIDs []string) {
	require := require.New(t)
	passwords := make([]string, len(keyIDs))
	if testkm.config().MustEncryptPrivateKeys {
		for i := 0; i < len(passwords); i++ {
			passwords[i] = fmt.Sprintf("pass%d", i)
		}
	}

	err := testkm.newKeygen().GenAndStoreMultiAccountKeys(keyIDs, passwords)
	require.NoError(err, "failed to generate committee stake-in account keys")

	for i, keyID := range keyIDs {
		// Test getting the key.
		key, err := testkm.newKeymgr().GetAccountKey(keyID, passwords[i], "", true)
		require.NoError(err, "i=%d, keyID=%s", i, keyID)

		// Verify the key.
		data := []byte("hello, world")
		sig, err := crypto.SignWithECDSA(data, key)
		require.NoError(err, "failed to sign data with ECDSA private key")

		pub := crypto.GetECDSAPublicKey(key)
		verified, err := crypto.VerifyWithECDSA(data, pub, sig)
		require.NoError(err, "error verifying signature")
		require.True(verified, "failed to verify the signed data")
	}
}

func TestGetNonexistentKey(t *testing.T) {
	require := require.New(t)

	keyID := "nonexistent-key"

	keymgrs := make(map[string]*KeyManager)
	// Test the file-based keystore
	testkm := newFSTestingKeyManager(false, "", t)
	keymgrs["file-based"] = testkm.newKeymgr()

	// Test the memory-based keystore as the role Accelerator.
	cfg := MemKeyStoreConfig{}
	keymgrs["memory-based"] = NewKeyManagerFromMemKeystore(SetupTestingKeystore(cfg))

	for typ, keymgr := range keymgrs {
		_, err := keymgr.GetAccountKey(keyID, "", "", true)
		require.NotNil(
			err, "%s KeyManager returns no error when there is no such key", typ)

		_, err = keymgr.GetCommPrivateVoteKey(keyID, "")
		require.NotNil(
			err, "%s KeyManager returns no error when there is no such key", typ)

		_, err = keymgr.GetCommPublicVoteKeys([]string{keyID}, []string{""})
		require.NotNil(
			err, "%s KeyManager returns no error when there is no such key", typ)
	}
}
