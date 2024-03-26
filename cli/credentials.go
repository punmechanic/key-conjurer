package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	ps "github.com/mitchellh/go-ps"
)

type ShellType = string

const (
	shellTypePowershell ShellType = "powershell"
	shellTypeBash       ShellType = "bash"
	shellTypeBasic      ShellType = "basic"
	shellTypeInfer      ShellType = "infer"
)

func getShellType() ShellType {
	pid := os.Getppid()
	parentProc, _ := ps.FindProcess(pid)
	name := strings.ToLower(parentProc.Executable())

	if strings.Contains(name, "bash") || strings.Contains(name, "zsh") || strings.Contains(name, "ash") {
		return shellTypeBash
	}

	if strings.Contains(name, "powershell") || strings.Contains(name, "pwsh") {
		return shellTypePowershell
	}

	if runtime.GOOS == "windows" {
		return shellTypeBasic
	}

	return shellTypeBash
}

type CloudCredentials struct {
	AccountID       string `json:"AccountId"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`

	credentialsType string
}

func LoadTencentCredentialsFromEnvironment() CloudCredentials {
	return CloudCredentials{
		AccessKeyID:     os.Getenv("TENCENTCLOUD_SECRET_ID"),
		SecretAccessKey: os.Getenv("TENCENTCLOUD_SECRET_KEY"),
		SessionToken:    os.Getenv("TENCENTCLOUD_TOKEN"),
		AccountID:       os.Getenv("TENCENTKEY_ACCOUNT"),
		Expiration:      os.Getenv("TENCENTKEY_EXPIRATION"),
		credentialsType: cloudTencent,
	}
}

func LoadAWSCredentialsFromEnvironment() CloudCredentials {
	return CloudCredentials{
		AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
		AccountID:       os.Getenv("AWSKEY_ACCOUNT"),
		Expiration:      os.Getenv("AWSKEY_EXPIRATION"),
		credentialsType: cloudAws,
	}
}

func (c *CloudCredentials) ValidUntil(account *Account, dur time.Duration) bool {
	if account == nil || c == nil {
		return false
	}

	if c.AccountID != account.ID {
		return false
	}

	expiration, err := time.Parse(time.RFC3339, c.Expiration)
	if err != nil {
		return false
	}

	return expiration.After(time.Now().Add(dur))
}

type bashWriter struct{}

func (bashWriter) WriteVariable(w io.Writer, key, value string) {
	fmt.Fprintf(w, "export %s=%q\n", key, value)
}

func (bashWriter) WriteAlias(w io.Writer, key, name string) {
	fmt.Fprintf(w, "export %s=$%s\n", key, name)
}

type powershellWriter struct{}

func (powershellWriter) WriteVariable(w io.Writer, key, value string) {
	fmt.Fprintf(w, "$Env:%s = %q\n", key, value)
}

func (powershellWriter) WriteAlias(w io.Writer, key, name string) {
	fmt.Fprintf(w, "$Env:%s = $Env:%s\n", key, name)
}

type basicWriter struct{}

func (basicWriter) WriteVariable(w io.Writer, key, value string) {
	// Do not quote values in Basic.
	fmt.Fprintf(w, "SET %s=%s\n", key, value)
}

func (basicWriter) WriteAlias(w io.Writer, key, name string) {
	fmt.Fprintf(w, "SET %s=%%%s%%\n", key, name)
}

// shellWriter describes a type that can write environment variables and aliases to a shell.
//
// Implementors of shellWriter should ensure that they generate code that can be executed in a subshell.
type shellWriter interface {
	// WriteVariable writes a new environment variable.
	WriteVariable(w io.Writer, key, value string)
	// WriteAlias writes an alias to an existing environment variable.
	WriteAlias(w io.Writer, key, name string)
}

func (c CloudCredentials) WriteFormat(w io.Writer, format ShellType) {
	var writer shellWriter
	if format == shellTypeInfer {
		format = getShellType()
	}

	switch format {
	default:
		fallthrough
	case shellTypeBash:
		writer = bashWriter{}
	case shellTypePowershell:
		writer = powershellWriter{}
	case shellTypeBasic:
		writer = basicWriter{}
	}

	switch c.credentialsType {
	default:
		fallthrough
	case cloudAws:
		writer.WriteVariable(w, "AWS_ACCESS_KEY_ID", c.AccessKeyID)
		writer.WriteVariable(w, "AWS_SECRET_ACCESS_KEY", c.SecretAccessKey)
		writer.WriteVariable(w, "AWS_SESSION_TOKEN", c.SessionToken)
		writer.WriteAlias(w, "AWS_SECURITY_TOKEN", "AWS_SESSION_TOKEN")
		writer.WriteAlias(w, "TF_VAR_access_key", "AWS_ACCESS_KEY_ID")
		writer.WriteAlias(w, "TF_VAR_secret_key", "AWS_SECRET_ACCESS_KEY")
		writer.WriteAlias(w, "TF_VAR_token", "AWS_SESSION_TOKEN")
		writer.WriteVariable(w, "AWSKEY_EXPIRATION", c.Expiration)
		writer.WriteVariable(w, "AWSKEY_ACCOUNT", c.AccountID)
	case cloudTencent:
		writer.WriteVariable(w, "TENCENTCLOUD_SECRET_ID", c.AccessKeyID)
		writer.WriteVariable(w, "TENCENTCLOUD_SECRET_KEY", c.SecretAccessKey)
		writer.WriteVariable(w, "TENCENTCLOUD_TOKEN", c.SessionToken)
		writer.WriteAlias(w, "TENCENT_SECURITY_TOKEN", "TENCENTCLOUD_TOKEN")
		writer.WriteAlias(w, "TF_VAR_access_key", "TENCENTCLOUD_SECRET_ID")
		writer.WriteAlias(w, "TF_VAR_secret_key", "TENCENTCLOUD_SECRET_KEY")
		writer.WriteAlias(w, "TF_VAR_token", "TENCENTCLOUD_TOKEN")
		writer.WriteVariable(w, "TENCENTKEY_EXPIRATION", c.Expiration)
		writer.WriteVariable(w, "TENCENTKEY_ACCOUNT", c.AccountID)
	}
}
