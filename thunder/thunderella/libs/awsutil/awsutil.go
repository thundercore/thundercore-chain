// Provide wrappers to use AWS functions.

package awsutil

import (
	// Standard
	"context"
	"fmt"
	"html/template"
	"io/ioutil"
	"os/user"
	"strings"

	"github.com/ethereum/go-ethereum/thunder/thunderella/libs/lgr"

	// Vendor
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

var logger = lgr.NewLgr("/AWSUtil")

// NOTE: Use a prepared testing CMK (customized master key).
// Here are some design concerns:
// * Use the same key because maintaining a CMK costs 1 USD per month.
// * Instead of using a hard-coded key ID, we may use the first/last key in the key list
//   and create a new key if there is no key. The problem is that we share the same
//   development account and somebody may just add a policy to that key and restricts
//   the access roles.
// Using a hard-coded key ID makes things simple. If you find the key is lost and want to
// create a new one. Remember to also fill the desciption:
//   "The key used to run the tests in awsutil.go"
var (
	TestingKMSKeyID  = "451b879c-e135-4922-9d73-5a73dc67e9c8"
	TestingKMSKeyID2 = "29f7dfe6-09f6-406f-9fbe-34c811b7ec56"
)

//------------------------------------------------------------------------------
// Helper functions
//------------------------------------------------------------------------------

// GetFixedUniquePrefix returns a fixed string based on the data of the user and the machine.
// ${prefix} is used as the prefix in the returned value. The goal is to provide a unique
// prefix as parts of the AWS Secret IDs, S3 bucket paths, etc. This solves two issues:
// * Everyone can run tests/programs in different machines at the same time without worrying
//   name conflicts.
// * AWS Secrets cost money and are not deleted immediately. Using the same Secret IDs saves
//   unnecessary costs. See AWS pricings to know more details.
func GetFixedUniquePrefix(prefix string) string {
	chainID := prefix
	u, err := user.Current()
	var uid string
	if err == nil {
		uid = u.Uid
		chainID += "-" + u.Username
	} else {
		uid = "123"
		logger.Warn("Cannot get the user data. err=%s", err)
	}

	// Use /etc/machine-id if possible. It's more random than UID.
	// Fallback to UID on MacOS.
	data, err := ioutil.ReadFile("/etc/machine-id")
	suffix := ""
	if err == nil {
		// Drop the tailing newline.
		suffix = string(data[:len(data)-1])
	} else {
		suffix = uid
	}
	chainID += "-" + suffix

	// AWS S3 Bucket's maximum length is 63.
	// chainID is the prefix of S3 Bucket, keep more spaces for the remaining characters.
	if len(chainID) > 25 {
		chainID = string(chainID[:25])
	}
	return chainID
}

//------------------------------------------------------------------------------
// STS
//------------------------------------------------------------------------------

// This function is goroutine-safe.
func GetCallerIdentity() (*sts.GetCallerIdentityOutput, error) {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}

	svc := sts.NewFromConfig(cfg)
	input := &sts.GetCallerIdentityInput{}

	return svc.GetCallerIdentity(context.Background(), input)
}

//------------------------------------------------------------------------------
// SecretsManager
//------------------------------------------------------------------------------
// Code reference: github.com/aws/aws-sdk-go-v2/service/secretsmanager/examples_test.go
//
// This function is goroutine-safe.
func getRegionSecretManager(region string) (*secretsmanager.Client, error) {
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
	if err != nil {
		return nil, err
	}
	return secretsmanager.NewFromConfig(cfg), nil
}

// CreateSecret creates a secret in AWS Secrets Manager. keyID is the KMS CMK key ID
// used to encrypt/decrypt the secret automatically. Use the default key if keyID is empty.
//
// This function is goroutine-safe.
func CreateSecret(region string, keyID string, name string) (*secretsmanager.CreateSecretOutput, error) {
	sm, err := getRegionSecretManager(region)
	if err != nil {
		return nil, err
	}
	input := &secretsmanager.CreateSecretInput{
		Name:     aws.String(name),
		KmsKeyId: aws.String(keyID),
	}

	result, err := sm.CreateSecret(context.Background(), input)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// UpdateSecret provides two functions:
// 1. Override the secret's value if value is not empty.
// 2. Update the CMK key ID if kmsKeyID is not empty.
// 1 & 2 can be done in one call.
//
// This function is goroutine-safe.
func UpdateSecret(
	region, secretID, kmsKeyID, value string,
) (*secretsmanager.UpdateSecretOutput, error) {
	sm, err := getRegionSecretManager(region)
	if err != nil {
		return nil, err
	}
	var kid, v *string
	if len(kmsKeyID) > 0 {
		kid = aws.String(kmsKeyID)
	}
	if len(value) > 0 {
		v = aws.String(value)
	}
	input := &secretsmanager.UpdateSecretInput{
		SecretId:     aws.String(secretID),
		SecretString: v,
		KmsKeyId:     kid,
	}

	return sm.UpdateSecret(context.Background(), input)
}

// GetSecret gets the value of secretID in AWS Secrets Manager.
//
// This function is goroutine-safe.
func GetSecret(region string, secretID string) (*secretsmanager.GetSecretValueOutput, error) {
	sm, err := getRegionSecretManager(region)
	if err != nil {
		return nil, err
	}
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretID),
		VersionStage: aws.String("AWSCURRENT"),
	}

	return sm.GetSecretValue(context.Background(), input)
}

// DeleteSecret deletes the value of secretID from AWS Secrets Manager.
//
// This function is goroutine-safe.
func DeleteSecret(region string, secretID string) (*secretsmanager.DeleteSecretOutput, error) {
	sm, err := getRegionSecretManager(region)
	if err != nil {
		return nil, err
	}
	input := &secretsmanager.DeleteSecretInput{
		RecoveryWindowInDays: 7,
		SecretId:             aws.String(secretID),
	}

	return sm.DeleteSecret(context.Background(), input)
}

// RestoreSecret restores the secret corresponding to secretID from AWS Secrets Manager.
//
// This function is goroutine-safe.
func RestoreSecret(region string, secretID string) (*secretsmanager.RestoreSecretOutput, error) {
	sm, err := getRegionSecretManager(region)
	if err != nil {
		return nil, err
	}
	input := &secretsmanager.RestoreSecretInput{
		SecretId: aws.String(secretID),
	}

	return sm.RestoreSecret(context.Background(), input)
}

// SetSecretsReadOnlyForRole add principal to only allow ${accountID}::role/${roleName}
// read the secret corresponding to ${secretID} at ${region}
//
// This function is goroutine-safe.
func SetSecretsReadOnlyForRole(
	region, secretID, accountID, roleName, sessionName string,
) (*secretsmanager.PutResourcePolicyOutput, error) {
	if region == "" {
		return nil, fmt.Errorf("region is not set")
	}
	sm, err := getRegionSecretManager(region)
	if err != nil {
		return nil, err
	}

	const policyTemplate = `{
    "Version" : "2012-10-17",
    "Statement" : [ {
        "Effect" : "Allow",
        "Principal" : {
            "AWS" : "arn:aws:iam::{{.AccountID}}:role/{{.RoleName}}"
        },
        "Action" : "secretsmanager:GetSecretValue",
        "Resource" : "arn:aws:secretsmanager:{{.Region}}:{{.AccountID}}:secret:{{.SecretID}}-*",
        "Condition" : {
            "ForAnyValue:StringEquals" : {
                "secretsmanager:VersionStage" : "AWSCURRENT"
            }
        }
    }, {
        "Effect" : "Deny",
        "NotPrincipal" : {
            "AWS" : [
                "arn:aws:sts::{{.AccountID}}:assumed-role/{{.RoleName}}/{{.SessionName}}",
                "arn:aws:iam::{{.AccountID}}:role/{{.RoleName}}",
                "arn:aws:iam::{{.AccountID}}:root"
            ]
        },
        "Action" : "secretsmanager:GetSecretValue",
        "Resource" : "arn:aws:secretsmanager:{{.Region}}:{{.AccountID}}:secret:{{.SecretID}}-*"
    } ]
}`
	type Arguments struct {
		AccountID, RoleName, SessionName, Region, SecretID string
	}
	args := Arguments{accountID, roleName, sessionName, region, secretID}
	t := template.Must(template.New(policyTemplate).Parse(policyTemplate))
	var b strings.Builder
	if err := t.Execute(&b, args); err != nil {
		return nil, err
	}
	policy := b.String()

	input := &secretsmanager.PutResourcePolicyInput{
		ResourcePolicy: aws.String(policy),
		SecretId:       aws.String(secretID),
	}

	return sm.PutResourcePolicy(context.Background(), input)
}

// GetSecretsDescriptions gets the details of of secretID in AWS Secrets Manager.
//
// This function is goroutine-safe.
func GetSecretDescription(region, secretID string,
) (*secretsmanager.DescribeSecretOutput, error) {
	sm, err := getRegionSecretManager(region)
	if err != nil {
		return nil, err
	}

	input := &secretsmanager.DescribeSecretInput{
		SecretId: aws.String(secretID),
	}

	return sm.DescribeSecret(context.Background(), input)
}
