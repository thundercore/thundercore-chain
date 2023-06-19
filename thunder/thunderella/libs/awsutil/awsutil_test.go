// +build testaws

package awsutil

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/stretchr/testify/require"
)

var (
	testingRegion string // Use the default value.
)

func TestAWSUpdateSecret(t *testing.T) {
	require := require.New(t)

	// Prepare the secret.
	prefix := GetFixedUniquePrefix("at")
	secretID := prefix + "-123"

	_, err := CreateSecret(testingRegion, "", secretID)
	if err != nil {
		// The secret might exist. Check the error code.
		var errResourceExists types.ResourceExistsException
		var errInvalidRequest types.InvalidRequestException
		if errors.As(err, &errResourceExists) {
			fmt.Printf("Secret for %s exists\n", secretID)
		} else if errors.As(err, &errInvalidRequest) {
			// The secret may be deleted after running the tests.
			// Try to restore it.
			_, rerr := RestoreSecret(testingRegion, secretID)
			if rerr == nil {
				fmt.Printf("Secret for %s is restored\n", secretID)
			} else {
				require.Fail("Failed to restore %s. err=%s", secretID, rerr)
			}
		} else {
			require.Fail("Unexpected error. err=%s", err)
		}
	}
	defer DeleteSecret(testingRegion, secretID)

	// Update the KMS key ID and value.
	value := "hello"
	_, err = UpdateSecret(testingRegion, secretID, TestingKMSKeyID2, value)
	require.NoError(err)

	result, err := GetSecretDescription(testingRegion, secretID)
	require.NoError(err)
	require.NotNil(result.KmsKeyId)
	require.Equal(TestingKMSKeyID2, *result.KmsKeyId)

	// Only update KMS key ID.
	_, err = UpdateSecret(testingRegion, secretID, TestingKMSKeyID, "")
	require.NoError(err)

	result, err = GetSecretDescription(testingRegion, secretID)
	require.NoError(err)
	require.NotNil(result.KmsKeyId)
	require.Equal(TestingKMSKeyID, *result.KmsKeyId)

	result2, err := GetSecret(testingRegion, secretID)
	require.NoError(err)
	require.NotNil(result2.SecretString)
	require.Equal(value, *result2.SecretString)

	// Only update the secret value.
	value2 := "world"
	_, err = UpdateSecret(testingRegion, secretID, "", value2)
	require.NoError(err)

	result, err = GetSecretDescription(testingRegion, secretID)
	require.NoError(err)
	require.NotNil(result.KmsKeyId)
	require.Equal(TestingKMSKeyID, *result.KmsKeyId)

	result2, err = GetSecret(testingRegion, secretID)
	require.NoError(err)
	require.NotNil(result2.SecretString)
	require.Equal(value2, *result2.SecretString)
}
