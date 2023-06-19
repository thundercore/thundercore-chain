package keymanager

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/ethereum/go-ethereum/thunder/thunderella/keymanager/crypto"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/bls"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	"github.com/ethereum/go-ethereum/log"
)

type KeyType string

var (
	VotingKeyType         KeyType = "vote"
	StakeInAccountKeyType KeyType = "stakein"
	AuxNetAccountKeyType  KeyType = "auxnet"
	UnknownKeyType        KeyType = "unknown"
)

var stringToKeyType map[string]KeyType

func init() {
	stringToKeyType = make(map[string]KeyType)
	stringToKeyType[string(VotingKeyType)] = VotingKeyType
	stringToKeyType[string(StakeInAccountKeyType)] = StakeInAccountKeyType
	stringToKeyType[string(AuxNetAccountKeyType)] = AuxNetAccountKeyType
}

func ToKeyType(s string) (KeyType, error) {
	kt, ok := stringToKeyType[s]
	if !ok {
		return UnknownKeyType, fmt.Errorf("unknown key type: %s", s)
	}
	return kt, nil
}

type KeysBlob struct {
	NumKey       uint
	Type         KeyType
	PrivateKeys  []string
	PublicKeys   []string
	Addresses    []string
	Certificates []string
}

func getKeyBlobFromSigningKey(password string, signKey *bls.SigningKey, encryptKeys bool,
) (*SignKeyBlob, error) {
	signKey = bls.SigningKeyFromBytes(signKey.ToBytes())
	var keyBlob SignKeyBlob
	if encryptKeys {
		// Generate an AES key to encrypt the private proposing key.
		aesKeyBlob, err := crypto.GenAESKeyByPwd(password, []byte(nil))
		if err != nil {
			return nil, err
		}

		// Encrypt the private proposing key.
		cipherBlob, err := crypto.EncryptWithAES(signKey.ToBytes(), aesKeyBlob.KeyValue)
		if err != nil {
			return nil, err
		}
		keyBlob.EncryptedPrivateKey = cipherBlob
		keyBlob.AESKeySalt = aesKeyBlob.Salt
	} else {
		keyBlob.PrivateKey = signKey.ToBytes()
	}
	return &keyBlob, nil
}

// If encryptKeys is true, implies we know the key is encrypted and will decrypt with
// password argument (could be "").  And false means we don't know whether the key is
// encrypted and will promopt user to input password.
func getSigningKeyFromKeyBlob(password string, keyBlob *SignKeyBlob, encryptKeys bool,
) (*bls.SigningKey, error) {
	var signKey *bls.SigningKey
	if encryptKeys || keyBlob.EncryptedPrivateKey != nil {
		if keyBlob.EncryptedPrivateKey == nil {
			return nil, errEncryptedPrivateKeyIsNil
		}
		if keyBlob.EncryptedPrivateKey != nil && !encryptKeys {
			var err error
			password, err = utils.ReadPassword("Enter password for signing key: ")
			if err != nil {
				return nil, fmt.Errorf("failed to read password: %s", err)
			}
		}

		// Generate an AES key to decrypt the encrypted private proposing key.
		aesKeyBlob, err := crypto.GenAESKeyByPwd(password, keyBlob.AESKeySalt)
		if err != nil {
			return nil, err
		}

		// Decrypt the encrypted private proposing key and return it.
		decrypted, err := crypto.DecryptWithAES(
			keyBlob.EncryptedPrivateKey, aesKeyBlob.KeyValue)
		if err != nil {
			return nil, err
		}
		signKey = bls.SigningKeyFromBytes(decrypted)
	} else {
		if len(keyBlob.PrivateKey) == 0 {
			return nil, errUnencryptedPrivateKeyIsEmpty
		}

		signKey = bls.SigningKeyFromBytes(keyBlob.PrivateKey)
	}
	return signKey, nil
}

func writeObjectToJsonFile(v interface{}, filePath string, perm os.FileMode) {
	// Marshall file to JSON and write.
	jsonBytes, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		debug.Fatal("Failed to marshal to JSON. err=%s", err)
	}
	err = ioutil.WriteFile(filePath, jsonBytes, perm)
	if err != nil {
		debug.Fatal("Failed to write JSON file. err=%s", err)
	}
}

func readObjectFromJsonFile(v interface{}, filePath string) error {
	// Load the accelerator certificate from disk.
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read JSON file. err=%s", err)
	}
	if err = json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("failed to unmarshal from JSON. err=%s", err)
	}
	return nil
}

func getPemBlockFromData(data []byte, blockType string) (*pem.Block, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decoded block is nil")
	}
	if block.Type != blockType {
		return nil, fmt.Errorf("decoded block has unexpected type: %s", block.Type)
	}
	if len(rest) > 0 {
		log.Warn("multiple PEM blocks found, ignoring them")
	}
	return block, nil
}

func checkPublicAndSignKeyPair(pk *bls.PublicKey, signKey *bls.SigningKey) bool {
	data := []byte("testing data")
	return pk.VerifySignature(data, signKey.Sign(data))
}

func GetKeyIDsForFS(size uint, kt KeyType, keyIDStartFrom uint) []string {
	keyIDs := make([]string, size)
	for i := uint(0); i < size; i++ {
		keyIDs[i] = fmt.Sprintf("%s%d", kt, keyIDStartFrom+i)
	}
	return keyIDs
}

// GetKeyIDsForAWS is a helper function to generate the key IDs.
// The client of keymanager (e.g., thundertool) may use it directly
// or use their rules to generate key IDs.
func GetKeyIDsForAWS(size uint, keyGroup string, function string, keyIDStartFrom uint) []string {
	keyIDs := make([]string, size)
	for i := uint(0); i < size; i++ {
		keyIDs[i] = fmt.Sprintf("%s/%d/%s", keyGroup, keyIDStartFrom+i, function)
	}
	return keyIDs
}
