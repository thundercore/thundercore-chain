package keymanager

import (
	// Standard imports

	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	// Thunder imports
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/awsutil"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"
	// Vendor imports
)

// TODO: This library does debug.Fatal in many places. It's not a good idea for low level
// libraries to crash. We should change functions to return errors instead and let callers decide
// to crash or not.

// Keystore load/store keys and certificates.
// The implementation must be goroutine-safe.
type Keystore interface {
	// Single committee member operations
	getCommVoteKey(keyID string) (*SignKeyBlob, error)
	storeCommVoteKey(keyID string, key *SignKeyBlob) error

	// Account key operations
	getAccountKey(keyID string) (*SignKeyBlob, error)
	storeAccountKey(keyID string, key *SignKeyBlob) error
}

//------------------------------------------------------------------------------
// FsKeystore
//------------------------------------------------------------------------------

type FsKeystoreConfig struct {
	Config

	DirPath string
}

const fsKeyStoreFilename = "keys.json"

// fsKeystore is goroutine-safe.
// The member fields are read-only after the object is created.
type fsKeystore struct {
	utils.CheckedLock
	cfg FsKeystoreConfig
}

type keyMap map[string]*SignKeyBlob

func NewFsKeystore(cfg FsKeystoreConfig) *fsKeystore {
	return &fsKeystore{utils.CheckedLock{}, cfg}
}

func (fsK *fsKeystore) getKey(keyID string) (*SignKeyBlob, error) {
	fsK.Lock()
	defer fsK.Unlock()

	path := filepath.Join(fsK.cfg.DirPath, fsKeyStoreFilename)
	var m keyMap
	if err := readObjectFromJsonFile(&m, path); err != nil {
		return nil, err
	}
	if k, ok := m[keyID]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("key %q not found", keyID)
}

func (fsK *fsKeystore) storeKey(keyID string, key *SignKeyBlob) error {
	fsK.Lock()
	defer fsK.Unlock()

	if err := os.MkdirAll(fsK.cfg.DirPath, 0700); err != nil {
		debug.Fatal("Failed to create parent dir for %s : %s", fsK.cfg.DirPath, err)
	}

	var m keyMap
	path := filepath.Join(fsK.cfg.DirPath, fsKeyStoreFilename)
	if _, err := os.Stat(path); err != nil {
		if !os.IsNotExist(err) {
			// Stop due to an unknown error.
			return err
		}
		// The file does not exist.
		m = make(map[string]*SignKeyBlob)
	} else if err = readObjectFromJsonFile(&m, path); err != nil {
		return err
	}
	m[keyID] = key
	writeObjectToJsonFile(&m, path, 0600)
	return nil
}

func (fsK *fsKeystore) getCommVoteKey(keyID string) (*SignKeyBlob, error) {
	return fsK.getKey(keyID)
}

func (fsK *fsKeystore) storeCommVoteKey(keyID string, key *SignKeyBlob) error {
	return fsK.storeKey(keyID, key)
}

func (fsK *fsKeystore) getAccountKey(keyID string) (*SignKeyBlob, error) {
	return fsK.getKey(keyID)
}

func (fsK *fsKeystore) storeAccountKey(keyID string, key *SignKeyBlob) error {
	return fsK.storeKey(keyID, key)
}

//------------------------------------------------------------------------------
// awsKeystore
//------------------------------------------------------------------------------

// Recorded from https://docs.aws.amazon.com/general/latest/gr/rande.html
var awsRegions = map[string]bool{
	"ap-northeast-1": true,
	"ap-northeast-2": true,
	"ap-south-1":     true,
	"ap-southeast-1": true,
	"ap-southeast-2": true,
	"ca-central-1":   true,
	"eu-central-1":   true,
	"eu-west-1":      true,
	"eu-west-2":      true,
	"eu-west-3":      true,
	"sa-east-1":      true,
	"us-east-1":      true,
	"us-east-2":      true,
	"us-west-1":      true,
	"us-west-2":      true,
	"cn-north-1":     true,
	"cn-northwest-1": true,
}

// We have extra config at first, but we don't have extra config now.
// Keep it to not break existing code and provide the flexibility to add extra config.
type AWSKeystoreConfig struct {
	Config
}

// awsKeystore is goroutine-safe.
// The member fields are read-only after the object is created.
type awsKeystore struct {
	cfg AWSKeystoreConfig
	// Use the values in https://docs.aws.amazon.com/general/latest/gr/rande.html
	// Follow AWS SDK's convention to get the value if it is empty.
	// E.g., read the environment variable AWS_DEFAULT_REGION.
	region string
}

func NewAWSKeystore(cfg AWSKeystoreConfig, region string) *awsKeystore {
	if region != "" {
		if _, ok := awsRegions[region]; !ok {
			debug.Fatal("Invalid region: %s", region)
		}
	}
	return &awsKeystore{
		cfg:    cfg,
		region: region,
	}
}

func storeAWSSecret(region, keyID, typeName string, v interface{}) error {
	jsonBytes, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		debug.Fatal("Failed to marshal %s to JSON. err=%s", typeName, err)
	}
	// Update the value using the configured CMK.
	_, err = awsutil.UpdateSecret(region, keyID, "", string(jsonBytes))
	return err
}

func getAWSSecret(region, keyID, typeName string, typ reflect.Type) (interface{}, error) {
	result, err := awsutil.GetSecret(region, keyID)
	if err != nil {
		return nil, err
	}
	data := *result.SecretString

	value := reflect.New(typ)
	v := value.Interface()
	if err = json.Unmarshal([]byte(data), v); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s from JSON. err=%s", typeName, err)
	}
	return v, nil
}

// getCommVoteKey retrieves committee's private vote key from AWS Secrets Manager by keyID,
// which is unique for the same AWS account in the same region.
func (awsK *awsKeystore) getCommVoteKey(keyID string) (*SignKeyBlob, error) {
	typ := reflect.TypeOf((*SignKeyBlob)(nil)).Elem()
	v, err := getAWSSecret(awsK.region, keyID, "SignKeyBlob", typ)
	if err != nil {
		return nil, err
	}
	return v.(*SignKeyBlob), nil
}

// storeCommVoteKey stores committee's private vote key to AWS Secrets Manager by keyID,
// which is unique for the same AWS account in the same region.
func (awsK *awsKeystore) storeCommVoteKey(keyID string, key *SignKeyBlob) error {
	return storeAWSSecret(awsK.region, keyID, "SignKeyBlob", key)
}

func (awsK *awsKeystore) getAccountKey(keyID string) (*SignKeyBlob, error) {
	typ := reflect.TypeOf((*SignKeyBlob)(nil)).Elem()
	v, err := getAWSSecret(awsK.region, keyID, "SignKeyBlob", typ)
	if err != nil {
		return nil, err
	}
	return v.(*SignKeyBlob), nil
}

func (awsK *awsKeystore) storeAccountKey(keyID string, key *SignKeyBlob) error {
	return storeAWSSecret(awsK.region, keyID, "SignKeyBlob", key)
}
