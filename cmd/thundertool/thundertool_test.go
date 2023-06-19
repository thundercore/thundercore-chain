package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/thunder/thunderella/keymanager"

	"github.com/stretchr/testify/require"
)

type testConfig struct {
	numKeys        uint
	keyIDStartFrom uint
}

func getDefaultTestConfig() *testConfig {
	return &testConfig{
		numKeys:        3,
		keyIDStartFrom: 8,
	}
}

func TestMain(m *testing.M) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		fmt.Printf("Failed to start the test. err=%s\n", err)
		os.Exit(1)
	}
	binPath := strings.TrimSuffix(string(out), "\n") + "/build/bin"

	path := os.Getenv("PATH")
	if path[len(path)-1:] != ":" {
		path += ":"
	}
	path += binPath
	fmt.Println(path)
	os.Setenv("PATH", path)
	os.Exit(m.Run())
}

func createFSGenKeyCmd(cmdType, dstDir string, numKeys, keyIDStartFrom uint) *exec.Cmd {
	args := []string{
		"--noencrypt", cmdType,
		"--num-keys", fmt.Sprint(numKeys),
		"--key-id-start-from", fmt.Sprint(keyIDStartFrom),
		"--fs-destdir", dstDir,
	}
	cmd := exec.Command("thundertool", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

func createFSGetKeyCmd(
	cmdType string, kt keymanager.KeyType, srcDir, outputFileName string, numKeys, keyIDStartFrom uint) *exec.Cmd {
	cmd := exec.Command(
		"thundertool", "--noencrypt", cmdType,
		"--num-keys", fmt.Sprint(numKeys),
		"--key-id-start-from", fmt.Sprint(keyIDStartFrom),
		"--key-type", string(kt),
		"--fs-srcdir", srcDir,
		"--output", outputFileName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

func TestGetKeyCmd(t *testing.T) {
	t.Parallel()

	require := require.New(t)
	config := getDefaultTestConfig()
	ksDir, err := ioutil.TempDir("", "keystore_")
	require.NoError(err)
	defer os.RemoveAll(ksDir)

	keyTypes := []keymanager.KeyType{
		keymanager.VotingKeyType,
		keymanager.StakeInAccountKeyType,
		keymanager.AuxNetAccountKeyType,
	}
	genCmdTypes := []string{
		"genvotekeys",
		"genstakeinkeys",
		"genauxnetkeys",
	}
	for i := range genCmdTypes {
		kt := keyTypes[i]

		// Generate keys.
		cmdType := genCmdTypes[i]
		cmd := createFSGenKeyCmd(cmdType, ksDir, config.numKeys, config.keyIDStartFrom)
		err = cmd.Run()
		require.NoError(err, "key type=%s", string(kt))

		// Get keys.
		errMsg := "key type=" + string(kt)
		outputFileName := createTempFile(t, errMsg)
		cmdType = "getkeys"
		cmd = createFSGetKeyCmd(cmdType, kt, ksDir, outputFileName, config.numKeys, config.keyIDStartFrom)
		err = cmd.Run()
		require.NoError(err, "key type=%s", string(kt))

		// Verify keys.
		blob := loadKeysBlob(t, outputFileName, errMsg)

		require.Equal(config.numKeys, blob.NumKey, "key type=%s", string(kt))
		require.Equal(kt, blob.Type, "key type=%s", string(kt))
		require.Equal(config.numKeys, uint(len(blob.PublicKeys)), "key type=%s", string(kt))
		for i, privatekey := range blob.PrivateKeys {
			privateKey, err := decodeString(privatekey)
			require.NoError(err)
			if kt == keymanager.VotingKeyType {
				// The length varies.
				require.NotEmpty(privateKey, "key type=%s, i=%d", string(kt), i)
			} else {
				require.Equal(32, len(privateKey), "key type=%s, i=%d", string(kt), i)
			}
		}
		for i, pubkey := range blob.PublicKeys {
			pubkey, err := decodeString(pubkey)
			require.NoError(err)
			if kt == keymanager.VotingKeyType {
				// The length varies.
				require.NotEmpty(pubkey, "key type=%s, i=%d", string(kt), i)
			} else {
				require.Equal(65, len(pubkey), "key type=%s, i=%d", string(kt), i)
			}
		}
		require.Equal(config.numKeys, uint(len(blob.Addresses)))
		for i, addr := range blob.Addresses {
			addr, err := decodeString(addr)
			require.NoError(err)
			if kt == keymanager.VotingKeyType {
				// No address
				require.Empty(addr, "key type=%s, i=%d", string(kt), i)
			} else {
				require.Equal(20, len(addr), "key type=%s, i=%d", string(kt), i)
			}
		}
	}
}

func createTempFile(t *testing.T, msg string) string {
	file, err := ioutil.TempFile("", "keys_out_")
	require.NoError(t, err, msg)
	file.Close()
	return file.Name()
}

func loadKeysBlob(
	t *testing.T, fileName, msg string) *keymanager.KeysBlob {
	defer os.Remove(fileName)

	bytes, err := ioutil.ReadFile(fileName)
	require.NoError(t, err, msg)

	var blob keymanager.KeysBlob
	err = json.Unmarshal(bytes, &blob)
	require.NoError(t, err, msg)
	return &blob
}
