// Accelerator Admin functions and configures.

package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"

	// Thunder imports.
	"github.com/ethereum/go-ethereum/thunder/thunderella/common/committee"
	"github.com/ethereum/go-ethereum/thunder/thunderella/keymanager"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	// Vendor imports

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"gopkg.in/urfave/cli.v1"
)

type KeyGetter interface {
	// Return privateKey, publicKey, address, error.
	// privateKey is non-empty string if error is nil;
	// publicKey is non-empty string if error is nil;
	// address is non-empty string if key type is StakeInAccountKeyType/AuxNetAccountKeyType
	getKeys(keyID, password string) (string, string, string, error)
	getKeyType() keymanager.KeyType
}

type blsKeyGetter struct {
	keymgr *keymanager.KeyManager
	kt     keymanager.KeyType
}

type ecdsaKeyGetter struct {
	keymgr *keymanager.KeyManager
	kt     keymanager.KeyType
}

type keyIDBlob struct {
	fsKeyID         string
	fsKeyIDPassword string
	awsKeyID        string
}

// awsKeyGenerator provides the template methods used in generateAWSKeys().
type awsKeyGenerator interface {
	// setUp() is called first.
	setUp() (*keymanager.AWSHelper, error)

	getKeyType() keymanager.KeyType

	getKeyIDs(nKeys uint, keyIDStartFrom uint) []string

	// If isGeneratingNewKeys() is true, call genAndStoreKeys();
	// otherwise, call loadAndStoreKeys().
	isGeneratingNewKeys() bool
	// genAndStoreKeys generates new keys and store them to AWS.
	genAndStoreKeys(keyIDs []string) error
	// loadAndStoreKeys loads existed keys from the files and store them to AWS.
	// NOTE: The file-baed KeyManager/KeyGenerator and the AWS-based
	// KeyManager/KeyGenerator use different patterns for secret IDs.
	// Use the corresponding secret ID to load/store.
	loadAndStoreKeys(keyIDBlobs []keyIDBlob) error

	// Either done() or failed() is guaranteed to be called.
	done(keyIDs []string) error
	failed(err error)
}

type awsBaseKeyGenerator struct {
	keyGroup    string
	kt          keymanager.KeyType
	cmkKeyID    string
	keysSrcDir  string
	mustEncrypt bool
	helper      *keymanager.AWSHelper
	keygen      *keymanager.KeyGenerator
	keymgr      *keymanager.KeyManager
}

type awsVoteKeyGenerator struct {
	awsBaseKeyGenerator
}

type awsAccountKeyGenerator struct {
	awsBaseKeyGenerator
}

const (
	// By default it is valid for 10 years.
	// TODO (JZ) Set the default value with a configuration file
	// TODO (JZ) Discuss with business and security audit team for an appropriate value.
	defaultValidity        = 10
	rfc3339FullDate string = "2006-01-02" // This is the canonical date for time.Parse

	errGenVotingKeys = "Failed to generate Committee Vote Keys: "
)

var (
	debugLog         = false
	thunderToolFlags = []cli.Flag{
		cli.BoolFlag{
			Name:        "noencrypt",
			Usage:       "No encryption of private proposing or voting keys",
			Destination: &thunderNoEncryption,
		},
	}

	// Common arguments for all key generation commands.
	keyManagerType             = "fs"
	thunderNoEncryption        = false
	numKeys                    = uint(1)
	cliKeyIDStartFrom          = uint(0)
	keyGroup                   = ""
	awsCMKKeyID                = ""
	awsReadOnlyRoleNamePrefix  = ""
	awsReadOnlyRoleSessionName = ""
	awsRegion                  = "us-west-2"
	keyManagerFlags            = []cli.Flag{
		cli.StringFlag{
			Name:        "key-manager",
			Usage:       "Choose the type of the key manager: fs | aws. The default value is `fs`",
			Value:       "fs",
			Destination: &keyManagerType,
		},
		cli.UintFlag{
			Name:        "num-keys",
			Usage:       "Number of keys",
			Value:       1,
			Destination: &numKeys,
		},
		cli.UintFlag{
			Name:        "key-id-start-from",
			Usage:       "The key of id index start from, The default value is 0",
			Value:       0,
			Destination: &cliKeyIDStartFrom,
		},
		cli.StringFlag{
			Name: "key-group",
			Usage: "This is a part of the path to store/load keys. " +
				"Currently only AWS Secrets Manager and S3 Bucket use it",
			Value:       "",
			Destination: &keyGroup,
		},
		cli.StringFlag{
			Name: "aws-region",
			Usage: "AWS region. Follow AWS SDK's convention to get the value " +
				"if it is not specified",
			Value:       "",
			Destination: &awsRegion,
		},
	}

	keyManagerGeneratorFlags = append(keyManagerFlags,
		cli.StringFlag{
			Name:        "fs-destdir",
			Usage:       "Set the home directory for keystore.",
			Value:       "",
			Destination: &keysDestDir,
		},
		cli.StringFlag{
			Name: "aws-cmk-key-id",
			Usage: "The AWS CMK to encrypt/decrypt private keys stored in " +
				"Secrets Manager. Use the original value if this argument " +
				"is not specified.",
			Value:       "",
			Destination: &awsCMKKeyID,
		},
		cli.StringFlag{
			Name: "aws-read-only-role-name-prefix",
			Usage: "If specified, also set the resource-based policy in created secrets: " +
				"Only allow the role ${ROLE_NAME_PREFIX}-NNN to get the corresponding " +
				"secret where NNN is a number from 000 to 999. " +
				"Note that aws-read-only-role-session-name must be applied together.",
			Value:       "",
			Destination: &awsReadOnlyRoleNamePrefix,
		},
		cli.StringFlag{
			Name: "aws-read-only-role-session-name",
			Usage: "If specified, also set the resource-based policy in created secrets: " +
				"This is used to set the session name of the assumed-role. " +
				"Note that aws-read-only-role-name-prefix must be applied together.",
			Value:       "",
			Destination: &awsReadOnlyRoleSessionName,
		},
		cli.StringFlag{
			Name: "aws-srcdir",
			Usage: "Load keys from a designated directory " +
				"instead of generating new ones.",
			Value:       "",
			Destination: &awsKeysSrcDir,
		},
	)

	// genVotingKeyCommand flags
	keysDestDir         = ""
	accelURI            = ""
	accelHostPort       = ""
	genVotingKeyCommand = cli.Command{
		Action:    genVotingKeyCmd,
		Name:      "genvotekeys",
		Usage:     "generate and store the committee vote private/public keys.",
		ArgsUsage: "",
		Flags: append(keyManagerGeneratorFlags,
			cli.StringFlag{
				Name:        "fs-acceluri",
				Usage:       "Set CDN URI",
				Value:       "",
				Destination: &accelURI,
			},
			cli.StringFlag{
				Name:        "fs-accelhostport",
				Usage:       "Set the accel host port.",
				Value:       "",
				Destination: &accelHostPort,
			},
		),
		Category: "Key generator",
		Description: `
Generate Committee members' voting keys and save them at designated location.

Example:

(fs ) thundertool genvotekeys --num-keys 6 --fs-destdir ./keystore
(aws) thundertool genvotekeys --num-keys 6 --key-manager aws --key-group local-chain-101`,
	}

	// Account key commands.
	genAuxNetKeyCommand = cli.Command{
		Action:    genAuxNetKeyCmd,
		Name:      "genauxnetkeys",
		Usage:     "generate and store the auxnet account private/public keys.",
		ArgsUsage: "",
		Flags:     keyManagerGeneratorFlags,
		Category:  "Key generator",
		Description: `
Generate Accelerators' AuxNet account keys and save them at designated location.

Example:

(fs ) thundertool genauxnetkeys --num-keys 6 --fs-destdir ./keystore
(aws) thundertool genauxnetkeys --num-keys 6 --key-manager aws --key-group local-chain-101`,
	}

	genStakeInKeyCommand = cli.Command{
		Action:    genStakeInKeyCmd,
		Name:      "genstakeinkeys",
		Usage:     "generate and store the committee stake-in account private/public keys.",
		ArgsUsage: "",
		Flags:     keyManagerGeneratorFlags,
		Category:  "Key generator",
		Description: `
Generate Committee members' stake-in account keys and save them at designated location.

Example:

(fs ) thundertool genstakeinkeys --num-keys 6 --fs-destdir ./keystore
(aws) thundertool genstakeinkeys --num-keys 6 --key-manager aws --key-group local-chain-101`,
	}

	keyType                   = ""
	keysSrcDir                = ""
	stakeInKeysOutputFileName = "public_keys.json"
	getKeyCommand             = cli.Command{
		Action:    getKeyCmd,
		Name:      "getkeys",
		Usage:     "Get public keys and account addresses when getting the account keys.",
		ArgsUsage: "",
		Flags: append(keyManagerFlags,
			cli.StringFlag{
				Name:        "output",
				Usage:       "The output file name",
				Value:       "public_keys.json",
				Destination: &stakeInKeysOutputFileName,
			},
			cli.StringFlag{
				Name:        "key-type",
				Usage:       "The type of keys (proposal, vote, stakein, auxnet).",
				Value:       "",
				Destination: &keyType,
			},
			cli.StringFlag{
				Name:        "fs-srcdir",
				Usage:       "Load keys from a designated directory.",
				Value:       "",
				Destination: &keysSrcDir,
			},
		),
		Category: "Key getter",
		Description: `
Get public keys and account addresses (if the keys are account keys) and output the designated file.
The caller must call gen*keys before and the command arguments must match the arguments of gen*keys.

Example (assume genstakeinkeys is called):

(fs ) thundertool getkeys --num-keys 6 --key-type stakein --fs-srcdir ./keystore \
					--output public_stakein_keys.json
(aws) thundertool getkeys --num-keys 6 --key-manager aws --key-group local-chain-101 \
					--key-type stakein --output public_stakein_keys.json`,
	}

	awsKeysSrcDir = ""

	numPropKeys        = uint(1)
	nodeConfigPath     = ""
	genesisCommPath    = "./genesis_comm_info.json"
	r2CommPath         = "./r2_comm_info.json"
	genCommInfoCommand = cli.Command{
		Action:    genCommInfoCmd,
		Name:      "gencomminfo",
		Usage:     "Generate comminfo from key store.",
		ArgsUsage: "",
		Flags: append(keyManagerFlags,
			cli.UintFlag{
				Name:        "num-prop-keys",
				Usage:       "Number of proposing keys",
				Value:       1,
				Destination: &numPropKeys,
			},
			cli.StringFlag{
				Name:        "config",
				Usage:       "Ignoring nom-prop-key, read the config to get expected key.",
				Destination: &nodeConfigPath,
			},
			cli.StringFlag{
				Name:        "fs-srcdir",
				Usage:       "Load keys from a designated directory.",
				Value:       "",
				Destination: &keysSrcDir,
			},
			cli.StringFlag{
				Name:        "output",
				Usage:       "The output path",
				Value:       "genesis_comm_info.json",
				Destination: &genesisCommPath,
			},
			cli.StringFlag{
				Name:        "r2",
				Usage:       "The r2 hardfork output path",
				Value:       "r2_comm_info.json",
				Destination: &r2CommPath,
			},
		),
		Category: "Key getter",
		Description: `
Generate CommInfo from a given keystore.
Note that the URI, HostPort, TxPoolAddr and Coinbase in AccelInfo are not handled.

Example:

(fs ) thundertool gencomminfo --fs-srcdir ./keystore
(aws) thundertool gencomminfo --key-manager aws --key-group local-chain-101`,
	}
	verifyCommInfoCommand = cli.Command{
		Action:    verifyCommInfoCmd,
		Name:      "verifycomminfo",
		Usage:     "Verify comminfo.json file.",
		ArgsUsage: "COMM_INFO.json",
		Flags:     []cli.Flag{},
		Category:  "Verify",
	}
)

// genVotingKeyCmd sub-command generates Comm vote key.
//
// This subcommand is developed for Testnet v1 only because we need generate the voting keys
// in a centralized way. It might be deprecated for prod after we implement Mainnet or a simulated
// slowchain.
func genVotingKeyCmd(ctx *cli.Context) error {
	if err := processCommVoteKeyFlags(ctx); err != nil {
		log.Fatalf("%s%s\n", errGenVotingKeys, err)
	}
	if keyManagerType == "fs" {
		return commVoteKeyCmdForFS(ctx)
	} else if keyManagerType == "aws" {
		return commVoteKeyCmdForAWS(keyGroup, awsKeysSrcDir, numKeys, cliKeyIDStartFrom, !thunderNoEncryption)
	}
	return fmt.Errorf("unknown key manager type: %s", keyManagerType)
}

// NOTE: we can use any format of key IDs as long as thunder and thundertool are consistent.
// It's okay to Use keymanager's helper function directly.
func getKeyIDsForFS(size uint, kt keymanager.KeyType, keyIDStartFrom uint) []string {
	return keymanager.GetKeyIDsForFS(size, kt, keyIDStartFrom)
}

// NOTE: we can use any format of key IDs as long as thunder and thundertool are consistent.
// It's okay to Use keymanager's helper function directly.
func getKeyIDsForAWS(size uint, keyGroup string, kt keymanager.KeyType, keyIDStartFrom uint) []string {
	return keymanager.GetKeyIDsForAWS(size, keyGroup, string(kt), keyIDStartFrom)
}

func commVoteKeyCmdForFS(ctx *cli.Context) error {
	if keysDestDir == "" {
		exec, err := os.Executable()
		if err != nil {
			log.Fatalf("Cannot get the working directory: %s", err)
		}
		keysDestDir = filepath.Dir(exec)
	}
	fsCfg := keymanager.FsKeystoreConfig{
		Config: keymanager.Config{
			MustEncryptPrivateKeys: !thunderNoEncryption,
		},
		DirPath: keysDestDir,
	}
	keymgr := keymanager.NewKeyGenerator(fsCfg.Config, keymanager.NewFsKeystore(fsCfg))
	keyIDs := getKeyIDsForFS(numKeys, "vote", cliKeyIDStartFrom)
	err := keymgr.GenAndStoreMultiCommVoteKey(keyIDs)
	if err != nil {
		return err
	}
	fmt.Println("Committee voting key files generated at: ", keysDestDir)
	return nil
}

func commVoteKeyCmdForAWS(
	keyGroup, awsKeysSrcDir string, nKeys uint, keyIDStartFrom uint, mustEncrypt bool) error {
	kg := &awsVoteKeyGenerator{
		newBaseKeyGenerator(
			keyGroup, keymanager.VotingKeyType, awsCMKKeyID, awsKeysSrcDir, mustEncrypt),
	}
	return generateAWSKeys(
		kg, awsReadOnlyRoleNamePrefix, awsReadOnlyRoleSessionName, errGenVotingKeys,
		nKeys, keyIDStartFrom, mustEncrypt)
}

func processCommVoteKeyFlags(ctx *cli.Context) error {
	if numKeys > committee.MaxCommSize {
		return fmt.Errorf("committee size must be less than MaxCommsize %d",
			committee.MaxCommSize)
	}
	return nil
}

func genCommInfoCmdForAWS(nPropKeys, nVoterKeys, keyIDStartFrom uint, keyGroup, filename string) error {
	awsCfg := keymanager.AWSKeystoreConfig{}
	keymgr := keymanager.NewKeyManager(
		awsCfg.Config, keymanager.NewAWSKeystore(awsCfg, awsRegion))

	if nodeConfigPath == "" {
		ids := getKeyIDsForAWS(nPropKeys+nVoterKeys, keyGroup, keymanager.VotingKeyType, keyIDStartFrom)
		pid := ids[:nPropKeys]
		vid := ids
		cInfo, err := committee.NewCommInfoFromKeyManager(keymgr, pid, vid)
		if err != nil {
			return err
		}

		return ioutil.WriteFile(genesisCommPath, cInfo.ToJSON(), 0644)
	} else {
		return genCommInfoFromConfig(keymgr, nodeConfigPath, func(i int, keyIDStartFrom uint) string {
			return fmt.Sprintf("%s/%d/%s", keyGroup, i+int(keyIDStartFrom), string(keymanager.VotingKeyType))
		}, keyIDStartFrom)
	}
}

func genCommInfoCmdForFS(nPropKeys, nVoterKeys, keyIDStartFrom uint, srcDir string, encrypted bool, filename string) error {
	fsCfg := keymanager.FsKeystoreConfig{
		Config: keymanager.Config{
			MustEncryptPrivateKeys: encrypted,
		},
		DirPath: srcDir,
	}
	keymgr := keymanager.NewKeyManager(
		fsCfg.Config, keymanager.NewFsKeystore(fsCfg))

	if nodeConfigPath == "" {
		ids := getKeyIDsForFS(nPropKeys+nVoterKeys, "vote", keyIDStartFrom)
		pid := ids[:nPropKeys]
		vid := ids
		cInfo, err := committee.NewCommInfoFromKeyManager(keymgr, pid, vid)
		if err != nil {
			return err
		}
		return ioutil.WriteFile(genesisCommPath, cInfo.ToJSON(), 0644)
	} else {
		return genCommInfoFromConfig(keymgr, nodeConfigPath, nil, keyIDStartFrom)
	}
}

type NodeConfig struct {
	Roles      []string `json:"role"`
	HostIpPort string   `json:"name"`
}

type NodesConfig []NodeConfig

func genCommInfoFromConfig(keymgr *keymanager.KeyManager, path string, indexToKeyId func(int, uint) string, keyIDStartFrom uint) error {
	var cfg NodesConfig

	data, err := ioutil.ReadFile(nodeConfigPath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, &cfg)
	if err != nil {
		return err
	}
	info := &committee.CommInfo{}
	r2Info := &committee.CommInfo{
		Name: "r2",
	}

	var hasR2Config bool

	keyIdx := 0
	keyIds := getKeyIDsForFS(uint(len(cfg)), keymanager.VotingKeyType, keyIDStartFrom)
	for i, n := range cfg {
		var hasConsensusRole bool
		for _, role := range n.Roles {
			stake := big.NewInt(int64(i + 100))
			switch role {
			case "proposer":
				hasConsensusRole = true
				var keyId string
				if indexToKeyId != nil {
					keyId = indexToKeyId(i, keyIDStartFrom)
				} else {
					keyId = keyIds[keyIdx]
				}
				key, err := keymgr.GetCommPrivateVoteKey(keyId, "")
				if err != nil {
					return err
				}

				mInfo := committee.MemberInfo{
					Stake:      stake,
					Coinbase:   common.BigToAddress(big.NewInt(int64(i) + 64)),
					PubVoteKey: key.GetPublicKey(),
					GasPrice:   big.NewInt(10000000),
				}
				info.AccelInfo = append(info.AccelInfo, committee.AccelInfo{
					MemberInfo: mInfo,
					HostPort:   fmt.Sprintf("%s:%d", n.HostIpPort, 8888),
				})
			case "voter":
				hasConsensusRole = true
				var keyId string
				if indexToKeyId != nil {
					keyId = indexToKeyId(i, keyIDStartFrom)
				} else {
					keyId = keyIds[keyIdx]
				}
				key, err := keymgr.GetCommPrivateVoteKey(keyId, "")
				if err != nil {
					return err
				}

				mInfo := committee.MemberInfo{
					Stake:      stake,
					Coinbase:   common.BigToAddress(big.NewInt(int64(i))),
					PubVoteKey: key.GetPublicKey(),
					GasPrice:   big.NewInt(10000000),
				}
				info.MemberInfo = append(info.MemberInfo, mInfo)
			case "r2proposer":
				hasConsensusRole = true
				var keyId string
				if indexToKeyId != nil {
					keyId = indexToKeyId(i, keyIDStartFrom)
				} else {
					keyId = keyIds[keyIdx]
				}
				key, err := keymgr.GetCommPrivateVoteKey(keyId, "")
				if err != nil {
					return err
				}

				mInfo := committee.MemberInfo{
					Stake:      stake,
					Coinbase:   common.BigToAddress(big.NewInt(int64(i) + 64)),
					PubVoteKey: key.GetPublicKey(),
					GasPrice:   big.NewInt(10000000),
				}
				r2Info.AccelInfo = append(r2Info.AccelInfo, committee.AccelInfo{
					MemberInfo: mInfo,
					HostPort:   fmt.Sprintf("%s:%d", n.HostIpPort, 8888),
				})

				hasR2Config = true
			}
		}
		if hasConsensusRole {
			keyIdx++
		}
	}

	if hasR2Config {
		r2Infos := []*committee.CommInfo{r2Info}
		buf, err := json.MarshalIndent(r2Infos, "", " ")
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(r2CommPath, buf, 0644)
		if err != nil {
			return err
		}
	}

	return ioutil.WriteFile(genesisCommPath, info.ToJSON(), 0644)
}

func genCommInfoCmd(ctx *cli.Context) error {
	if keyManagerType == "fs" {
		if keysSrcDir == "" {
			return fmt.Errorf("--fs-srcdir is required")
		}
		return genCommInfoCmdForFS(numPropKeys, numKeys, cliKeyIDStartFrom, keysSrcDir, !thunderNoEncryption, genesisCommPath)
	} else if keyManagerType == "aws" {
		return genCommInfoCmdForAWS(numPropKeys, numKeys, cliKeyIDStartFrom, keyGroup, genesisCommPath)
	}
	return fmt.Errorf("unknown key manager type: %s", keyManagerType)
}

func verifyCommInfoCmd(ctx *cli.Context) error {
	if len(ctx.Args()) != 1 {
		return fmt.Errorf("Wrong number of arguments\nUsage: thundertool verifycomminfo COMM_INFO.json")
	}
	cInfoPath := ctx.Args()[0]
	cInfo := &committee.CommInfo{}
	data, err := ioutil.ReadFile(cInfoPath)
	if err != nil {
		return fmt.Errorf("failed to read JSON file %q", cInfoPath)
	}
	err = cInfo.FromJSON(data)
	if err != nil {
		return fmt.Errorf("FromJSON(%q) failed: %s", cInfoPath, err)
	}

	if err != nil {
		return fmt.Errorf("Failed: %s", err)
	}

	errChan := make(chan error, len(cInfo.AccelInfo))
	for i := 0; i < len(cInfo.AccelInfo); i++ {
		if err := <-errChan; err != nil {
			return err
		}
	}
	return nil
}

func genStakeInKeyCmd(ctx *cli.Context) error {
	return genAccountKeyCmd(ctx, keymanager.StakeInAccountKeyType)
}

func genAuxNetKeyCmd(ctx *cli.Context) error {
	return genAccountKeyCmd(ctx, keymanager.AuxNetAccountKeyType)
}

func genAccountKeyCmd(ctx *cli.Context, kt keymanager.KeyType) error {
	if numKeys > committee.MaxCommSize {
		return fmt.Errorf("number of keys must be less than MaxCommsize %d",
			committee.MaxCommSize)
	}

	if keyManagerType == "fs" {
		return genAccountKeyCmdForFS(ctx, kt)
	} else if keyManagerType == "aws" {
		return genAccountKeyCmdForAWS(keyGroup, awsKeysSrcDir, kt, numKeys, cliKeyIDStartFrom, !thunderNoEncryption)
	}
	return fmt.Errorf("unknown key manager type: %s", keyManagerType)
}

func genAccountKeyCmdForFS(ctx *cli.Context, kt keymanager.KeyType) error {
	if keysDestDir == "" {
		exec, err := os.Executable()
		if err != nil {
			log.Fatalf("Cannot get the working directory: %s", err)
		}
		keysDestDir = filepath.Dir(exec)
	}
	fsCfg := keymanager.FsKeystoreConfig{
		Config: keymanager.Config{
			MustEncryptPrivateKeys: !thunderNoEncryption,
		},
		DirPath: keysDestDir,
	}
	keymgr := keymanager.NewKeyGenerator(fsCfg.Config, keymanager.NewFsKeystore(fsCfg))
	keyIDs := getKeyIDsForFS(numKeys, kt, cliKeyIDStartFrom)
	keymgr.GenAndStoreMultiAccountKeys(keyIDs, nil)
	fmt.Println("Account key files generated at: ", keysDestDir)
	return nil
}

func genAccountKeyCmdForAWS(
	keyGroup, awsKeysSrcDir string, kt keymanager.KeyType, nKeys, keyIDStartFrom uint, mustEncrypt bool) error {
	kg := &awsAccountKeyGenerator{
		newBaseKeyGenerator(keyGroup, kt, awsCMKKeyID, awsKeysSrcDir, mustEncrypt),
	}
	errPrefix := fmt.Sprintf("Failed to generate account keys (%s):", string(kt))
	return generateAWSKeys(
		kg, awsReadOnlyRoleNamePrefix, awsReadOnlyRoleSessionName, errPrefix,
		nKeys, keyIDStartFrom, mustEncrypt)
}

//--------------------------------------------------------------------
// Get keys
//--------------------------------------------------------------------

func (g *blsKeyGetter) getKeys(
	keyID, password string) (string, string, string, error) {
	var key *bls.SigningKey
	var err error
	switch g.kt {
	case keymanager.VotingKeyType:
		key, err = g.keymgr.GetCommPrivateVoteKey(keyID, password)
	default:
		return "", "", "", fmt.Errorf("unknown key type: %s", g.kt)
	}
	if err != nil {
		return "", "", "", err
	}
	return encodeBytes(key.ToBytes()), encodeBytes(key.PublicKey.ToBytes()), "", nil
}

func (g *blsKeyGetter) getKeyType() keymanager.KeyType {
	return g.kt
}

func (g *ecdsaKeyGetter) getKeys(
	keyID, password string) (string, string, string, error) {
	var key *ecdsa.PrivateKey
	var err error
	switch g.kt {
	case keymanager.StakeInAccountKeyType, keymanager.AuxNetAccountKeyType:
		key, err = g.keymgr.GetAccountKey(keyID, password, "", true)
	default:
		return "", "", "", fmt.Errorf("unknown key type: %s", g.kt)
	}
	if err != nil {
		return "", "", "", err
	}
	privateKey := encodeBytes(crypto.FromECDSA(key))
	pubKey := encodeBytes(crypto.FromECDSAPub(&key.PublicKey))
	tmp := crypto.PubkeyToAddress(key.PublicKey)
	addr := encodeBytes(tmp[:])
	return privateKey, pubKey, addr, nil
}

func encodeBytes(bytes []byte) string {
	return hex.EncodeToString(bytes)
}

func decodeString(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func (g *ecdsaKeyGetter) getKeyType() keymanager.KeyType {
	return g.kt
}

func newKeysGetter(
	keymgr *keymanager.KeyManager, kt keymanager.KeyType,
) KeyGetter {
	switch kt {
	case keymanager.VotingKeyType:
		return &blsKeyGetter{keymgr, kt}
	case keymanager.StakeInAccountKeyType, keymanager.AuxNetAccountKeyType:
		return &ecdsaKeyGetter{keymgr, kt}
	}
	return nil
}

func getKeyCmd(ctx *cli.Context) error {
	if numKeys > committee.MaxCommSize {
		return fmt.Errorf("number of keys must be less than MaxCommsize %d",
			committee.MaxCommSize)
	}

	kt, err := keymanager.ToKeyType(keyType)
	if err != nil {
		return err
	}
	if keyManagerType == "fs" {
		if keysSrcDir == "" {
			return fmt.Errorf("--fs-srcdir is required")
		}
		return getKeyCmdForFS(
			numKeys,
			cliKeyIDStartFrom,
			kt,
			keysSrcDir,
			!thunderNoEncryption,
			stakeInKeysOutputFileName)
	} else if keyManagerType == "aws" {
		return getKeyCmdForAWS(
			numKeys,
			cliKeyIDStartFrom,
			kt,
			keyGroup,
			stakeInKeysOutputFileName)
	}
	return fmt.Errorf("unknown key manager type: %s", keyManagerType)
}

func getKeyCmdForFS(
	nKey, keyIDStartFrom uint, kt keymanager.KeyType, srcDir string, encrypted bool, outputFileName string) error {
	fsCfg := keymanager.FsKeystoreConfig{
		Config: keymanager.Config{
			MustEncryptPrivateKeys: encrypted,
		},
		DirPath: keysSrcDir,
	}
	keymgr := keymanager.NewKeyManager(
		fsCfg.Config, keymanager.NewFsKeystore(fsCfg))
	getter := newKeysGetter(keymgr, kt)

	return getKeysAndWriteToFile(
		getter, getKeyIDsForFS(nKey, kt, keyIDStartFrom), encrypted, outputFileName)
}

func getKeyCmdForAWS(nKey, keyIDStartFrom uint, kt keymanager.KeyType, keyGroup, outputFileName string) error {
	awsCfg := keymanager.AWSKeystoreConfig{}
	keymgr := keymanager.NewKeyManager(
		awsCfg.Config, keymanager.NewAWSKeystore(awsCfg, awsRegion))
	getter := newKeysGetter(keymgr, kt)

	return getKeysAndWriteToFile(
		getter, getKeyIDsForAWS(nKey, keyGroup, kt, keyIDStartFrom), false, outputFileName)
}

func getKeysAndWriteToFile(
	getter KeyGetter,
	keyIDs []string,
	encrypted bool,
	outputFileName string,
) error {
	var wg sync.WaitGroup
	nKey := uint(len(keyIDs))
	var lock sync.Mutex
	errors := make([]error, nKey)
	certs := make([]string, nKey)
	privateKeys := make([]string, nKey)
	pubKeys := make([]string, nKey)
	addresses := make([]string, nKey)
	passwords := make([]string, nKey)

	if encrypted {
		for i, kid := range keyIDs {
			pwd, err := utils.ReadPassword(fmt.Sprintf(
				"Enter passphrase for %s: ", kid))
			if err != nil {
				return err
			}
			passwords[i] = pwd
		}
	}

	for i, kid := range keyIDs {
		wg.Add(1)
		go func(index int, keyID string) {
			defer wg.Done()

			privateKey, pubKey, addr, err := getter.getKeys(
				keyID, passwords[index])
			if err != nil {
				lock.Lock()
				defer lock.Unlock()
				errors[index] = err
				return
			}

			lock.Lock()
			defer lock.Unlock()
			privateKeys[index] = privateKey
			pubKeys[index] = pubKey
			addresses[index] = addr
		}(i, kid)
	}
	wg.Wait()

	// Check errors.
	for _, err := range errors {
		if err != nil {
			return utils.MergeErrors("ERROR: failed to get some keys.", errors)
		}
	}

	out := keymanager.KeysBlob{
		NumKey:       nKey,
		Type:         getter.getKeyType(),
		PrivateKeys:  privateKeys,
		PublicKeys:   pubKeys,
		Addresses:    addresses,
		Certificates: certs,
	}

	result, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(outputFileName, result, 0644)
}

//--------------------------------------------------------------------
// AWS-based key generators.
//--------------------------------------------------------------------

func generateAWSKeys(
	kg awsKeyGenerator, readOnlyRoleNamePrefix, readOnlyRoleSessionName, errPrefix string,
	nKeys uint, keyIDStartFrom uint, mustEncrypt bool,
) error {
	// When we want to set the policy, both arguments are required to
	// limit only the specified role can access the key.
	if (readOnlyRoleNamePrefix == "") != (readOnlyRoleSessionName == "") {
		return fmt.Errorf(
			"%saws-read-only-role-name-prefix and aws-read-only-role-session-name "+
				"should be set or unset together", errPrefix)
	}

	helper, err := kg.setUp()
	if err != nil {
		kg.failed(err)
		return fmt.Errorf("%s%s", errPrefix, err)
	}

	awsKeyIDs := kg.getKeyIDs(nKeys, keyIDStartFrom)
	if err := helper.CreateSecrets(awsKeyIDs, true); err != nil {
		kg.failed(err)
		return fmt.Errorf("%s%s", errPrefix, err)
	}

	if readOnlyRoleNamePrefix != "" {
		err = helper.SetSecretsReadOnlyForRoles(
			awsKeyIDs, readOnlyRoleNamePrefix, readOnlyRoleSessionName)
		if err != nil {
			kg.failed(err)
			return fmt.Errorf("%s%s", errPrefix, err)
		}
	}

	if kg.isGeneratingNewKeys() {
		if err = kg.genAndStoreKeys(awsKeyIDs); err != nil {
			kg.failed(err)
			return fmt.Errorf("%s%s", errPrefix, err)
		}
	} else {
		fsKeyIDs := getKeyIDsForFS(nKeys, kg.getKeyType(), keyIDStartFrom)
		blobs := make([]keyIDBlob, nKeys)
		for i := 0; i < len(blobs); i++ {
			blobs[i].fsKeyID = fsKeyIDs[i]
			blobs[i].awsKeyID = awsKeyIDs[i]
			if mustEncrypt {
				blobs[i].fsKeyIDPassword, _ = utils.ReadPassword(fmt.Sprintf(
					"Enter passphrase for %s: ", blobs[i].fsKeyID))
				if blobs[i].fsKeyIDPassword == "" {
					return fmt.Errorf("ERROR: passphrase is empty")
				}
			}
		}
		if err = kg.loadAndStoreKeys(blobs); err != nil {
			kg.failed(err)
			return fmt.Errorf("%s%s", errPrefix, err)
		}
	}

	kg.done(awsKeyIDs)
	return nil
}

//--------------------------------------------------------------------
// awsBaseKeyGenerator
//--------------------------------------------------------------------

func newBaseKeyGenerator(
	keyGroup string,
	kt keymanager.KeyType,
	cmkKeyID string,
	keysSrcDir string,
	mustEncrypt bool) awsBaseKeyGenerator {
	return awsBaseKeyGenerator{
		keyGroup, kt, cmkKeyID, keysSrcDir, mustEncrypt, nil, nil, nil}
}

func (base *awsBaseKeyGenerator) setUp() (*keymanager.AWSHelper, error) {
	if base.keyGroup == "" {
		return nil, fmt.Errorf("keyGroup is required when using AWS")
	}

	awsCfg := keymanager.AWSKeystoreConfig{
		Config: keymanager.Config{},
	}
	base.keygen = keymanager.NewKeyGenerator(
		awsCfg.Config, keymanager.NewAWSKeystore(awsCfg, awsRegion))
	helper := keymanager.NewAWSHelper(base.keygen, awsRegion, base.cmkKeyID)
	base.helper = &helper

	// Initialize keymgr if needed.
	if base.keysSrcDir != "" {
		fsCfg := keymanager.FsKeystoreConfig{
			Config: keymanager.Config{
				MustEncryptPrivateKeys: base.mustEncrypt,
			},
			DirPath: base.keysSrcDir,
		}
		base.keymgr = keymanager.NewKeyManager(
			fsCfg.Config, keymanager.NewFsKeystore(fsCfg))
	}
	return base.helper, nil
}

func (base *awsBaseKeyGenerator) getKeyType() keymanager.KeyType {
	return base.kt
}

func (base *awsBaseKeyGenerator) getKeyIDs(nKeys uint, keyIDStartFrom uint) []string {
	return getKeyIDsForAWS(nKeys, base.keyGroup, base.kt, keyIDStartFrom)
}

func (base *awsBaseKeyGenerator) isGeneratingNewKeys() bool {
	return base.keysSrcDir == ""
}

//lint:ignore U1000 to be refactored
func (base *awsBaseKeyGenerator) genAndStoreKeys(keyIDs []string) error {
	debug.Fatal("The dereived type should implement this")
	return nil
}

//lint:ignore U1000 to be refactored
func (base *awsBaseKeyGenerator) loadAndStoreKeys(keyIDBlobs []keyIDBlob) error {
	debug.Fatal("The dereived type should implement this")
	return nil
}

//lint:ignore U1000 to be refactored
func (base *awsBaseKeyGenerator) done() error {
	// Default behavior is doing nothing.
	return nil
}

func (base *awsBaseKeyGenerator) failed(err error) {
	// Default behavior is doing nothing.
}

//--------------------------------------------------------------------
// awsVoteKeyGenerator
//--------------------------------------------------------------------
func (kg *awsVoteKeyGenerator) setUp() (*keymanager.AWSHelper, error) {
	helper, err := kg.awsBaseKeyGenerator.setUp()
	if err != nil {
		return nil, err
	}

	return helper, nil
}

func (kg *awsVoteKeyGenerator) genAndStoreKeys(keyIDs []string) error {
	return kg.awsBaseKeyGenerator.keygen.GenAndStoreMultiCommVoteKey(keyIDs)
}

func (kg *awsVoteKeyGenerator) loadAndStoreKeys(keyIDBlobs []keyIDBlob) error {
	// Get private keys.
	inputs := make([]keymanager.StoreVoteKeyInput, len(keyIDBlobs))
	for i, blob := range keyIDBlobs {
		privateKey, err := kg.awsBaseKeyGenerator.keymgr.GetCommPrivateVoteKey(
			blob.fsKeyID, blob.fsKeyIDPassword)
		if err != nil {
			return err
		}
		inputs[i].KeyID = blob.awsKeyID
		inputs[i].PrivateKey = privateKey
		//inputs[i].PublicKey = (*pubKeys)[i]
	}

	// Store keys/certificates.
	if err := kg.awsBaseKeyGenerator.keygen.StoreVoteKeys(inputs); err != nil {
		return err
	}
	return nil
}

func (kg *awsVoteKeyGenerator) done(keyIDs []string) error {
	fmt.Printf("Committee voting keys are generated:\n%s\n",
		kg.awsBaseKeyGenerator.helper.GetCommVoteKeyInfo(keyIDs))
	return nil
}

//--------------------------------------------------------------------
// awsAccountKeyGenerator
//--------------------------------------------------------------------
func (kg *awsAccountKeyGenerator) genAndStoreKeys(keyIDs []string) error {
	passwords := make([]string, len(keyIDs))
	return kg.awsBaseKeyGenerator.keygen.GenAndStoreMultiAccountKeys(keyIDs, passwords)
}

func (kg *awsAccountKeyGenerator) loadAndStoreKeys(keyIDBlobs []keyIDBlob) error {
	// Get private keys.
	inputs := make([]keymanager.StoreAccountKeyInput, len(keyIDBlobs))
	for i, blob := range keyIDBlobs {
		privateKey, err := kg.awsBaseKeyGenerator.keymgr.GetAccountKey(
			blob.fsKeyID, blob.fsKeyIDPassword, "", true)
		if err != nil {
			return err
		}
		inputs[i].KeyID = blob.awsKeyID
		inputs[i].PrivateKey = privateKey
	}

	// Store keys/certificates.
	if err := kg.awsBaseKeyGenerator.keygen.StoreMultiAccountKeys(inputs); err != nil {
		return err
	}
	return nil
}

func (kg *awsAccountKeyGenerator) done(keyIDs []string) error {
	var builder strings.Builder
	builder.WriteString(
		fmt.Sprintf("Account keys (%s) are generated:\n", kg.awsBaseKeyGenerator.kt))
	builder.WriteString(fmt.Sprintf("private vote key in Secrets Manager:\n"))
	for _, keyID := range keyIDs {
		builder.WriteString(fmt.Sprintf("  %s\n", keyID))
	}
	fmt.Println(builder.String())

	return nil
}
