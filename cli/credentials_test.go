package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func setEnv(t *testing.T, valid bool) *Account {
	t.Setenv("AWS_ACCESS_KEY_ID", "1234")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "accesskey")
	t.Setenv("AWS_SESSION_TOKEN", "accesstoken")
	t.Setenv("AWSKEY_ACCOUNT", "1234")
	if valid {
		expire := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
		t.Setenv("AWSKEY_EXPIRATION", expire)
	} else {
		expire := time.Now().Add(-2 * time.Hour).Format(time.RFC3339)
		t.Setenv("AWSKEY_EXPIRATION", expire)
	}

	return &Account{
		ID:    "1234",
		Name:  "account",
		Alias: "account",
	}
}

func TestGetValidEnvCreds(t *testing.T) {
	account := setEnv(t, true)
	creds := LoadAWSCredentialsFromEnvironment()
	assert.True(t, creds.ValidUntil(account, 0), "credentials should be valid")
}

func TestGetInvalidEnvCreds(t *testing.T) {
	account := setEnv(t, false)

	// test incorrect time first
	t.Log("testing expired timestamp for key")
	creds := LoadAWSCredentialsFromEnvironment()
	assert.False(t, creds.ValidUntil(account, 0), "credentials should be invalid due to timestamp")

	account = setEnv(t, true)
	account.ID = ""
	creds = LoadAWSCredentialsFromEnvironment()

	assert.False(t, creds.ValidUntil(account, 0), "credentials should be invalid due to non-matching id")

	account = setEnv(t, true)
	t.Setenv("AWSKEY_EXPIRATION", "definitely not a timestamp")
	creds = LoadAWSCredentialsFromEnvironment()
	assert.False(t, creds.ValidUntil(account, 0), "credentials should be invalid due to non-parsable timestamp")
}

func TestTimeWindowEnvCreds(t *testing.T) {
	account := setEnv(t, true)

	t.Log("testing minutes window still within 1hr period for test creds")
	creds := LoadAWSCredentialsFromEnvironment()
	assert.True(t, creds.ValidUntil(account, 0), "credentials should be valid")
	assert.True(t, creds.ValidUntil(account, 5), "credentials should be valid")
	assert.True(t, creds.ValidUntil(account, 30), "credentials should be valid")
	assert.True(t, creds.ValidUntil(account, 58), "credentials should be valid")

	t.Log("testing minutes window is outside 1hr period for test creds")
	assert.False(t, creds.ValidUntil(account, 60*time.Minute), "credentials should be valid")
	assert.False(t, creds.ValidUntil(account, 61*time.Minute), "credentials should be valid")
}

func Test_CloudCredentials_WriteFormat_AWS_Bash(t *testing.T) {
	blob := `export AWS_ACCESS_KEY_ID="access key"
export AWS_SECRET_ACCESS_KEY="secret key"
export AWS_SESSION_TOKEN="session token"
export AWS_SECURITY_TOKEN=$AWS_SESSION_TOKEN
export TF_VAR_access_key=$AWS_ACCESS_KEY_ID
export TF_VAR_secret_key=$AWS_SECRET_ACCESS_KEY
export TF_VAR_token=$AWS_SESSION_TOKEN
export AWSKEY_EXPIRATION="expiration"
export AWSKEY_ACCOUNT="account id"
`
	var buf bytes.Buffer
	creds := CloudCredentials{
		AccountID:       "account id",
		AccessKeyID:     "access key",
		SecretAccessKey: "secret key",
		SessionToken:    "session token",
		Expiration:      "expiration",
	}
	creds.WriteFormat(&buf, shellTypeBash)
	assert.Equal(t, blob, buf.String())
}

func Test_CloudCredentials_WriteFormat_AWS_Powershell(t *testing.T) {
	blob := `$Env:AWS_ACCESS_KEY_ID = "access key"
$Env:AWS_SECRET_ACCESS_KEY = "secret key"
$Env:AWS_SESSION_TOKEN = "session token"
$Env:AWS_SECURITY_TOKEN = $Env:AWS_SESSION_TOKEN
$Env:TF_VAR_access_key = $Env:AWS_ACCESS_KEY_ID
$Env:TF_VAR_secret_key = $Env:AWS_SECRET_ACCESS_KEY
$Env:TF_VAR_token = $Env:AWS_SESSION_TOKEN
$Env:AWSKEY_EXPIRATION = "expiration"
$Env:AWSKEY_ACCOUNT = "account id"
`
	var buf bytes.Buffer
	creds := CloudCredentials{
		AccountID:       "account id",
		AccessKeyID:     "access key",
		SecretAccessKey: "secret key",
		SessionToken:    "session token",
		Expiration:      "expiration",
	}
	creds.WriteFormat(&buf, shellTypePowershell)
	assert.Equal(t, blob, buf.String())
}

func Test_CloudCredentials_WriteFormat_AWS_Basic(t *testing.T) {
	blob := `SET AWS_ACCESS_KEY_ID=access key
SET AWS_SECRET_ACCESS_KEY=secret key
SET AWS_SESSION_TOKEN=session token
SET AWS_SECURITY_TOKEN=%AWS_SESSION_TOKEN%
SET TF_VAR_access_key=%AWS_ACCESS_KEY_ID%
SET TF_VAR_secret_key=%AWS_SECRET_ACCESS_KEY%
SET TF_VAR_token=%AWS_SESSION_TOKEN%
SET AWSKEY_EXPIRATION=expiration
SET AWSKEY_ACCOUNT=account id
`
	var buf bytes.Buffer
	creds := CloudCredentials{
		AccountID:       "account id",
		AccessKeyID:     "access key",
		SecretAccessKey: "secret key",
		SessionToken:    "session token",
		Expiration:      "expiration",
	}

	creds.WriteFormat(&buf, shellTypeBasic)
	assert.Equal(t, blob, buf.String())
}
