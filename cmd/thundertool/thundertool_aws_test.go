//go:build testaws
// +build testaws

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"

	// Thunder imports.
	"github.com/ethereum/go-ethereum/thunder/thunderella/keymanager"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/awsutil"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

type testAWSConfig struct {
	numKeys        uint
	keyIDStartFrom uint
	keyGroup       string
	srcDir         string
}

func getTestingKeyGroup() string {
	return keymanager.GetTestingKeyGroup("tt-chain")
}

func getDefaultTestAWSConfig() *testAWSConfig {
	config := getDefaultTestConfig()
	return &testAWSConfig{
		numKeys:        config.numKeys,
		keyIDStartFrom: config.keyIDStartFrom,
		keyGroup:       getTestingKeyGroup(),
		srcDir:         "",
	}
}

func createFSKeyManager(
	kt keymanager.KeyType, mustEncrypt bool, keyDir string) *keymanager.KeyManager {
	cfg := keymanager.FsKeystoreConfig{
		Config: keymanager.Config{
			MustEncryptPrivateKeys: mustEncrypt,
		},
		DirPath: keyDir,
	}
	return keymanager.NewKeyManager(cfg.Config,
		keymanager.NewFsKeystore(cfg))
}

func createAWSKeyManager(
	kt keymanager.KeyType, mustEncrypt bool, keyGroup, region string) *keymanager.KeyManager {
	cfg := keymanager.AWSKeystoreConfig{
		Config: keymanager.Config{
			MustEncryptPrivateKeys: mustEncrypt,
		},
	}
	return keymanager.NewKeyManager(cfg.Config,
		keymanager.NewAWSKeystore(cfg, region))
}

func createAWSGenKeyCmd(cmdType, srcDir string, numKeys, keyIDStartFrom uint, keyGroup string) *exec.Cmd {
	cmd := exec.Command(
		"thundertool", "--noencrypt", cmdType,
		"--num-keys", fmt.Sprint(numKeys),
		"--padding-number-start-with", fmt.Sprint(keyIDStartFrom),
		"--key-manager", "aws",
		"--aws-srcdir", srcDir,
		"--key-group", keyGroup)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

func createAWSGetKeyCmd(
	kt keymanager.KeyType, outputFileName string, numKeys, keyIDStartFrom uint, keyGroup string) *exec.Cmd {
	cmd := exec.Command(
		"thundertool", "getkeys",
		"--num-keys", fmt.Sprint(numKeys),
		"--padding-number-start-with", fmt.Sprint(keyIDStartFrom),
		"--key-manager", "aws",
		"--key-group", keyGroup,
		"--key-type", string(kt),
		"--output", outputFileName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

func TestAWSLoadFromFileAndStoreToAWSVoteKeys(t *testing.T) {
	t.Parallel()

	require := require.New(t)
	config := getDefaultTestAWSConfig()
	ksDir, err := ioutil.TempDir("", "keystore_")
	require.NoError(err)
	defer os.RemoveAll(config.srcDir)

	// Generate keys and store them in files.
	cmdType := "genvotekeys"
	fmt.Printf(">>> Run file-based \"thundertool %s\"\n", cmdType)
	cmd := createFSGenKeyCmd(cmdType, ksDir, config.numKeys, config.keyIDStartFrom)
	err = cmd.Run()
	require.NoError(err)

	// Load the keys from the files and store them to AWS.
	fmt.Printf(">>> Run AWS-based \"thundertool %s\"\n", cmdType)
	cmd = createAWSGenKeyCmd(cmdType, ksDir, config.numKeys, config.keyIDStartFrom, config.keyGroup)
	err = cmd.Run()
	require.NoError(err)

	// Prepare key managers.
	kt := keymanager.VotingKeyType
	fsKM := createFSKeyManager(kt, false, ksDir)
	awsKM := createAWSKeyManager(kt, false, config.keyGroup, awsRegion)

	// Verify keys.
	fsKeyIDs := getKeyIDsForFS(config.numKeys, keymanager.VotingKeyType, config.keyIDStartFrom)
	awsKeyIDs := getKeyIDsForAWS(config.numKeys, config.keyGroup, kt, config.keyIDStartFrom)
	for i := uint(0); i < config.numKeys; i++ {
		expected, err := fsKM.GetCommPrivateVoteKey(fsKeyIDs[i], "")
		require.NoError(err)
		actual, err := awsKM.GetCommPrivateVoteKey(awsKeyIDs[i], "")
		require.NoError(err)
		require.Equal(expected, actual)
	}

	// Veirfy certificates.
	expected, err := fsKM.GetCommPublicVoteKeys(fsKeyIDs, nil)
	require.NoError(err)
	actual, err := awsKM.GetCommPublicVoteKeys(awsKeyIDs, nil)
	require.NoError(err)
	require.Equal(expected, actual)
}

func TestAWSLoadFromFileAndStoreToAWSAuxNetKeys(t *testing.T) {
	testAWSLoadFromFileAndStoreToAWSAccountKeys(t, "genauxnetkeys", keymanager.AuxNetAccountKeyType)
}

func TestAWSLoadFromFileAndStoreToAWSStakeInKeys(t *testing.T) {
	testAWSLoadFromFileAndStoreToAWSAccountKeys(t, "genstakeinkeys", keymanager.StakeInAccountKeyType)
}

func testAWSLoadFromFileAndStoreToAWSAccountKeys(
	t *testing.T, cmdType string, kt keymanager.KeyType) {
	t.Parallel()

	require := require.New(t)
	config := getDefaultTestAWSConfig()
	ksDir, err := ioutil.TempDir("", "keystore_")
	require.NoError(err)
	defer os.RemoveAll(config.srcDir)

	// Generate keys and store them in files.
	fmt.Printf(">>> Run file-based \"thundertool %s\"\n", cmdType)
	cmd := createFSGenKeyCmd(cmdType, ksDir, config.numKeys, config.keyIDStartFrom)
	err = cmd.Run()
	require.NoError(err)

	// Load the keys from the files and store them to AWS.
	fmt.Printf(">>> Run AWS-based \"thundertool %s\"\n", cmdType)
	cmd = createAWSGenKeyCmd(cmdType, ksDir, config.numKeys, config.keyIDStartFrom, config.keyGroup)
	err = cmd.Run()
	require.NoError(err)

	// Prepare key managers.
	fsKM := createFSKeyManager(kt, false, ksDir)
	awsKM := createAWSKeyManager(kt, false, config.keyGroup, awsRegion)

	// Verify keys.
	outputFileName := createTempFile(t, "")
	fmt.Printf(">>> Run AWS-based \"thundertool getkeys\"\n")
	cmd = createAWSGetKeyCmd(kt, outputFileName, config.numKeys, config.keyIDStartFrom, config.keyGroup)
	err = cmd.Run()
	require.NoError(err)

	blob := loadKeysBlob(t, outputFileName, "")
	require.Equal(config.numKeys, blob.NumKey)
	require.Equal(kt, blob.Type)
	require.Equal(config.numKeys, uint(len(blob.PrivateKeys)),
		"key type=%s", string(kt))
	require.Equal(config.numKeys, uint(len(blob.PublicKeys)),
		"key type=%s", string(kt))
	require.Equal(config.numKeys, uint(len(blob.Addresses)),
		"key type=%s", string(kt))

	fsKeyIDs := getKeyIDsForFS(config.numKeys, kt, config.keyIDStartFrom)
	awsKeyIDs := getKeyIDsForAWS(config.numKeys, config.keyGroup, kt, config.keyIDStartFrom)
	for i := uint(0); i < config.numKeys; i++ {
		expected, err := fsKM.GetAccountKey(fsKeyIDs[i], "", "", true)
		require.NoError(err, "i=%d", i)
		actual, err := awsKM.GetAccountKey(awsKeyIDs[i], "", "", true)
		require.NoError(err, "i=%d", i)
		require.Equal(expected, actual)
		// Verify the key from the command getkeys.
		bytes, err := decodeString(blob.PublicKeys[i])
		require.NoError(err, "i=%d", i)
		pubKey, _ := crypto.UnmarshalPubkey(bytes)
		require.Equal(expected.PublicKey, *pubKey, "i=%d", i)
		addr := crypto.PubkeyToAddress(*pubKey)
		require.Equal(20, len(addr), "i=%d", i)
	}
}

func TestAWSUpdateCMKForAccountKeys(t *testing.T) {
	t.Parallel()

	require := require.New(t)
	config := getDefaultTestAWSConfig()
	require.True(config.numKeys > 0)

	// Use a different keyGroup, so we can run this with
	// testAWSLoadFromFileAndStoreToAWSAccountKeys() simultaneously.
	config.keyGroup = getTestingKeyGroup() + "-x-"
	kt := keymanager.StakeInAccountKeyType
	kg := &awsAccountKeyGenerator{
		newBaseKeyGenerator(config.keyGroup, kt, awsutil.TestingKMSKeyID, "", false),
	}
	errPrefix := fmt.Sprintf("Failed to generate account keys (%s):", string(kt))

	// Setup the keys.
	err := generateAWSKeys(kg, "", "", errPrefix, config.numKeys, config.keyIDStartFrom, false)
	require.NoError(err)

	// Verify CMK key ID.
	keyIDs := kg.getKeyIDs(config.numKeys, config.keyIDStartFrom)
	for i := uint(0); i < config.numKeys; i++ {
		result, err := awsutil.GetSecretDescription(awsRegion, keyIDs[i])
		require.NoError(err)
		require.NotNil(result.KmsKeyId)
		require.Equal(awsutil.TestingKMSKeyID, *result.KmsKeyId)
	}

	// Update keys without updating the CMK key ID.
	err = generateAWSKeys(kg, "", "", errPrefix, config.numKeys, config.keyIDStartFrom, false)
	require.NoError(err)

	// Verify CMK key ID is not changed.
	for i := uint(0); i < config.numKeys; i++ {
		result, err := awsutil.GetSecretDescription(awsRegion, keyIDs[i])
		require.NoError(err)
		require.NotNil(result.KmsKeyId)
		require.Equal(awsutil.TestingKMSKeyID, *result.KmsKeyId)
	}

	// Update keys and the CMK key ID.
	kg = &awsAccountKeyGenerator{
		newBaseKeyGenerator(config.keyGroup, kt, awsutil.TestingKMSKeyID2, "", false),
	}
	err = generateAWSKeys(kg, "", "", errPrefix, config.numKeys, config.keyIDStartFrom, false)
	require.NoError(err)

	// Verify CMK key ID is changed.
	for i := uint(0); i < config.numKeys; i++ {
		result, err := awsutil.GetSecretDescription(awsRegion, keyIDs[i])
		require.NoError(err)
		require.NotNil(result.KmsKeyId)
		require.Equal(awsutil.TestingKMSKeyID2, *result.KmsKeyId)
	}

}

func TestMergeTwoConfigToAWSVoteKeys(t *testing.T) {
	t.Parallel()

	require := require.New(t)
	config := getDefaultTestAWSConfig()
	config.numKeys = 3
	config.keyIDStartFrom = 0
	config2 := getDefaultTestAWSConfig()
	config2.numKeys = 2
	config2.keyIDStartFrom = 3
	ksDir, err := ioutil.TempDir("", "keystore_")
	require.NoError(err)
	defer os.RemoveAll(config.srcDir)

	// Generate keys and store them in files.
	cmdType := "genvotekeys"
	fmt.Printf(">>> Run file-based \"thundertool %s\"\n", cmdType)
	cmd := createFSGenKeyCmd(cmdType, ksDir, config.numKeys, config.keyIDStartFrom)
	err = cmd.Run()
	require.NoError(err)
	cmd = createFSGenKeyCmd(cmdType, ksDir, config2.numKeys, config2.keyIDStartFrom)
	err = cmd.Run()
	require.NoError(err)

	// Load the keys from the files and store them to AWS.
	fmt.Printf(">>> Run AWS-based \"thundertool %s\"\n", cmdType)
	cmd = createAWSGenKeyCmd(cmdType, ksDir, config.numKeys, config.keyIDStartFrom, config.keyGroup)
	err = cmd.Run()
	require.NoError(err)
	cmd = createAWSGenKeyCmd(cmdType, ksDir, config2.numKeys, config2.keyIDStartFrom, config2.keyGroup)
	err = cmd.Run()
	require.NoError(err)

	// Prepare key managers.
	kt := keymanager.VotingKeyType
	fsKM := createFSKeyManager(kt, false, ksDir)
	awsKM := createAWSKeyManager(kt, false, config.keyGroup, awsRegion)

	// Verify keys.
	// Current key's id: vote0, vote1, vote2, vote3, vote4
	// vote0, vote1, vote2 is generated by config
	// vote3, vote4 is generated by config2
	totalNumKeys := config.numKeys + config2.numKeys
	fsKeyIDs := getKeyIDsForFS(totalNumKeys, keymanager.VotingKeyType, 0)
	awsKeyIDs := getKeyIDsForAWS(totalNumKeys, config.keyGroup, kt, 0)
	for i := uint(0); i < totalNumKeys; i++ {
		expected, err := fsKM.GetCommPrivateVoteKey(fsKeyIDs[i], "")
		require.NoError(err)
		actual, err := awsKM.GetCommPrivateVoteKey(awsKeyIDs[i], "")
		require.NoError(err)
		require.Equal(expected, actual)
	}

	// Veirfy certificates.
	expected, err := fsKM.GetCommPublicVoteKeys(fsKeyIDs, nil)
	require.NoError(err)
	actual, err := awsKM.GetCommPublicVoteKeys(awsKeyIDs, nil)
	require.NoError(err)
	require.Equal(expected, actual)
}
