//go:build testaws
// +build testaws

package keymanager

import (
	"io/ioutil"
	"testing"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/awsutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	awsRegion      = "us-west-2"
	keyGroupPrefix = "ut-chain"
)

type awsKeyStoreTester struct {
	cfg    AWSKeystoreConfig
	region string
}

func (awsT *awsKeyStoreTester) newKeystore() Keystore {
	return NewAWSKeystore(awsT.cfg, awsT.region)
}

func (awsT *awsKeyStoreTester) config() *Config {
	return &awsT.cfg.Config
}

func newAWSTestingKeyManager(t *testing.T) keyManagerTester {
	// Setup constants
	keyDir, err := ioutil.TempDir("", "keystore_")
	require.Nil(t, err, "Can't create home dir for keys %s: %s", keyDir, err)
	awsKeyStoreTester := &awsKeyStoreTester{
		cfg:    AWSKeystoreConfig{},
		region: awsRegion,
	}
	return keyManagerTester{
		keyStoreTester: awsKeyStoreTester,
		keyDir:         keyDir,
	}
}

func deleteSecrets(t *testing.T, secretIDs []string) {
	for _, secretID := range secretIDs {
		_, err := awsutil.DeleteSecret(awsRegion, secretID)
		assert.NoError(t, err)
	}
}

func TestAWSGenAndLoadCommVoteKeys(t *testing.T) {
	t.Parallel()

	require := require.New(t)

	const commSize = 2

	// Ensure the secret exists.
	testkm := newAWSTestingKeyManager(t)
	keygen := testkm.newKeygen()
	cmkKeyID := "" // NOTE: In the production configuration, we should use our imported CMK.
	keyGroup := GetTestingKeyGroup(keyGroupPrefix)
	keyIDs := GetKeyIDsForAWS(commSize, keyGroup, "vote", 0)
	helper := NewAWSHelper(keygen, awsRegion, cmkKeyID)
	err := helper.CreateSecrets(keyIDs, true)
	defer deleteSecrets(t, keyIDs)
	require.NoError(err)

	// Generate keys.
	err = keygen.GenAndStoreMultiCommVoteKey(keyIDs)
	require.NoError(err)

	// Get public keys and verify.
	publicKeys, err := testkm.newKeymgr().GetCommPublicVoteKeys(keyIDs, nil)
	require.Nil(err, "failed to load multi comm public voting keys")
	require.Equal(commSize, len(publicKeys))

	for _, v := range publicKeys {
		require.NotNil(v, "public key pointer is %d", len(publicKeys))
		require.NotNil(v.Pk, "public key has nil Pk value")
	}

	// Get private keys and verify.
	keymgr := testkm.newKeymgr()
	for i, keyID := range keyIDs {
		privateKey, err := keymgr.GetCommPrivateVoteKey(keyID, "")
		require.NoError(err)
		require.True(checkPublicAndSignKeyPair((publicKeys)[i], privateKey))
	}

	testkm.clean()
}
