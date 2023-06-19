package keymanager

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	// Thunder
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/awsutil"
	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/debug"
	"github.com/ethereum/go-ethereum/thunder/thunderella/utils"

	// Vendor

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

// AWSHelper helps prepare the environment.
// All member fields are read-only after the object is created.
type AWSHelper struct {
	keygen      *KeyGenerator
	awsRegion   string
	awsCMKKeyID string // Use the default key if the value is empty.
	aks         *awsKeystore
}

func NewAWSHelper(keygen *KeyGenerator, awsRegion string, awsCMKKeyID string) AWSHelper {
	aks, ok := keygen.keystore.(*awsKeystore)
	if !ok {
		debug.Fatal("keygen does not use awsKeystore")
	}
	if awsRegion == "" {
		// Load the default value, so we can print the correct message
		// about which region we are used.
		cfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			debug.Fatal("Cannot load default AWS config")
		}
		awsRegion = cfg.Region
	}
	return AWSHelper{keygen, awsRegion, awsCMKKeyID, aks}
}

// CreateSecrets create secrets using secretIDs. Return no error if either the secrets
// are created or restored. If tryRestore is false, creating existed secrets causes error.
func (helper AWSHelper) CreateSecrets(secretIDs []string, tryRestore bool) error {
	size := uint(len(secretIDs))

	// Create secrets in parallel.
	var wg sync.WaitGroup
	var errorsLock utils.CheckedLock // Guards errors and hasError.
	errors := make([]error, size)
	hasError := false
	for i := uint(0); i < size; i++ {
		wg.Add(1)
		go func(index uint) {
			defer wg.Done()
			secretID := secretIDs[index]
			err := helper.createSecret(secretID, tryRestore)
			if err == nil {
				return
			}
			errorsLock.Lock()
			defer errorsLock.Unlock()
			errors[index] = fmt.Errorf("ERROR: Cannot create %d's secret %s: err=%s",
				index, secretID, err)
			hasError = true
		}(i)
	}
	wg.Wait()

	// Check errors.
	if !hasError {
		return nil
	}
	// Clean up the created secrets.
	for i, err := range errors {
		if err == nil {
			continue
		}

		secretID := secretIDs[i]
		_, err = awsutil.DeleteSecret(helper.awsRegion, secretID)
		if err != nil {
			fmt.Printf("ERROR: Failed to delete the secret: %s. err=%v\n", secretID, err)
			return err
		}
	}
	return utils.MergeErrors("ERROR: failed to create all secrets.", errors)
}

func (helper AWSHelper) createSecret(secretID string, tryRestore bool) error {
	cmk := helper.awsCMKKeyID
	if cmk == "" {
		cmk = "default-key"
	}
	_, err := awsutil.CreateSecret(
		helper.awsRegion, helper.awsCMKKeyID, secretID)
	if err == nil {
		logger.Info("Secret %s is created at %s under %s",
			secretID, helper.awsRegion, cmk)
		return nil
	}

	// err != nil
	var errResourceExists *types.ResourceExistsException
	if errors.As(err, &errResourceExists) {
		logger.Info("Secret %s exists at %s under %s",
			secretID, helper.awsRegion, cmk)
		err = nil
	}

	var errInvalidRequest *types.InvalidRequestException
	if errors.As(err, &errInvalidRequest) {
		if !tryRestore {
			return err
		}
		// The secret may be deleted (e.g., deleted after running the tests).
		// Try to restore it.
		_, rerr := awsutil.RestoreSecret(helper.awsRegion, secretID)
		if rerr == nil {
			logger.Info("Secret %s is restored at %s under %s",
				secretID, helper.awsRegion, cmk)
			err = nil
		} else {
			logger.Warn("Failed to restore AWS Secret: %s. err=%v",
				secretID, rerr)
		}
	}

	if err != nil {
		return err
	}

	// Update KMS key ID if needed.
	if helper.awsCMKKeyID == "" {
		return nil
	}

	_, err = awsutil.UpdateSecret(helper.awsRegion, secretID, helper.awsCMKKeyID, "")
	if err != nil {
		logger.Info("Update Secret %s with CMK %s at %s",
			secretID, helper.awsCMKKeyID, helper.awsRegion)
	}
	return err
}

func (helper AWSHelper) SetSecretsReadOnlyForRoles(
	secretIDs []string, roleNamePrefix, sessionName string) error {
	result, err := awsutil.GetCallerIdentity()
	if err != nil {
		return err
	}
	accountID := *result.Account

	// Set policies in parallel.
	var wg sync.WaitGroup
	var errorsLock utils.CheckedLock // Guards errors and hasError.
	errors := make([]error, len(secretIDs))
	hasError := false
	for i, secretID := range secretIDs {
		wg.Add(1)
		go func(index uint, secretID string) {
			defer wg.Done()
			roleName := fmt.Sprintf("%s-%03d", roleNamePrefix, index)
			_, err := awsutil.SetSecretsReadOnlyForRole(
				helper.awsRegion, secretID, accountID, roleName, sessionName)
			if err == nil {
				logger.Info("Secret for %s at %s is set read-only to %s",
					secretID, helper.awsRegion, roleName)
				return
			}
			errorsLock.Lock()
			defer errorsLock.Unlock()
			errors[index] = fmt.Errorf(
				"ERROR: Cannot set %d's secret %s read-only to %s: err=%s",
				index, secretID, roleName, err)
			hasError = true
		}(uint(i), secretID)
	}
	wg.Wait()

	// Check errors.
	if hasError {
		return utils.MergeErrors("ERROR: failed to set all secrets read-only.", errors)
	}
	return nil
}

func (helper AWSHelper) GetCommVoteKeyInfo(secretIDs []string) string {
	builder := strings.Builder{}

	builder.WriteString(fmt.Sprintf("private vote key in Secrets Manager:\n"))
	for _, secretID := range secretIDs {
		builder.WriteString(fmt.Sprintf("  %s\n", secretID))
	}

	return builder.String()
}

func (helper AWSHelper) GetAccelKeyInfo(secretIDs []string) string {
	builder := strings.Builder{}

	builder.WriteString(fmt.Sprintf("private proposal key in Secrets Manager:\n"))
	for _, secretID := range secretIDs {
		builder.WriteString(fmt.Sprintf("  %s\n", secretID))
	}

	return builder.String()
}
