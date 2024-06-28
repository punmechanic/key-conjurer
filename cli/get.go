package main

import (
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/spf13/cobra"
)

var (
	FlagRegion        = "region"
	FlagRoleName      = "role"
	FlagTimeRemaining = "time-remaining"
	FlagTimeToLive    = "ttl"
	FlagBypassCache   = "bypass-cache"
	FlagLogin         = "login"
)

var (
	// outputTypeEnvironmentVariable indicates that keyconjurer will dump the credentials to stdout in Bash environment variable format
	outputTypeEnvironmentVariable = "env"
	// outputTypeAWSCredentialsFile indicates that keyconjurer will dump the credentials into the ~/.aws/credentials file.
	outputTypeAWSCredentialsFile = "awscli"
	// outputTypeTencentCredentialsFile indicates that keyconjurer will dump the credentials into the ~/.tencent/credentials file.
	outputTypeTencentCredentialsFile = "tencentcli"
	permittedOutputTypes             = []string{outputTypeAWSCredentialsFile, outputTypeEnvironmentVariable, outputTypeTencentCredentialsFile}
	permittedShellTypes              = []string{shellTypePowershell, shellTypeBash, shellTypeBasic, shellTypeInfer}
)

type GetCommand struct {
	Region          string `default:"us-west-2" env:"AWS_REGION" help:"The region to retrieve credentials in"`
	Role            string `name:"role" short:"r" help:"The name of the role to assume." required:""`
	SessionName     string `name:"session-name" help:"The name of the role session name that will show up in CloudTrail logs" default:"KeyConjurer-AssumeRole"`
	Output          string `short:"o" name:"output" enum:"awscli,tencentcli,file,env" default:"env" help:"Specifies how to output credentials. Env outputs to Environment Variables according to the cloud type; awscli, tencentcli and file all deposit to an ini-style file"`
	Shell           string `name:"shell" default:"infer" help:"If output type is env, determines which format to output credentials in - by default, the format is inferred based on the execution environment. WSL users may wish to overwrite this to bash"`
	OutputDirectory string `name:"directory" optional:"" help:"If output is set to awscli, tencentcli or file, the directory to deposit the credentials into"`
	BypassCache     bool   `name:"bypass-cache" default:"false" help:"Do not check the cache for accounts and send the application ID as-is to Okta. This is useful if you have an ID you know is an Okta application ID and it is not stored in your local account cache"`
	Login           bool   `name:"login" default:"false" help:"Login to Okta before running the command"`
	Cloud           string `enum:"aws,tencent" default:"aws" help:"The cloud you are generating credentials for"`
	TimeToLive      int    `name:"ttl" default:"1" help:"The key timeout in hours from 1 to 8"`
	TimeRemaining   int    `name:"time-remaining" default:"60" help:"Request new keys if there are no keys in the environment or the current keys expire within <time-remaining> minutes."`
}

func (g GetCommand) Run(appCtx *AppContext) error {
	return nil
}

func isMemberOfSlice(slice []string, val string) bool {
	for _, member := range slice {
		if member == val {
			return true
		}
	}

	return false
}

func resolveApplicationInfo(cfg *Config, bypassCache bool, nameOrID string) (*Account, bool) {
	if bypassCache {
		return &Account{ID: nameOrID, Name: nameOrID}, true
	}
	return cfg.FindAccount(nameOrID)
}

func (GetCommand) Help() string {
	return `A role must be specified when using this command through the --role flag. You may list the roles you can assume through the roles command.`
}

var getCmd = &cobra.Command{
	Use: "get <accountName/alias>",
	RunE: func(cmd *cobra.Command, args []string) error {
		config := ConfigFromCommand(cmd)
		ctx := cmd.Context()
		oidcDomain, _ := cmd.Flags().GetString(FlagOIDCDomain)
		clientID, _ := cmd.Flags().GetString(FlagClientID)

		if HasTokenExpired(config.Tokens) {
			if ok, _ := cmd.Flags().GetBool(FlagLogin); ok {
				// urlOnly, _ := cmd.Flags().GetBool(FlagURLOnly)
				// noBrowser, _ := cmd.Flags().GetBool(FlagNoBrowser)
				login := LoginCommand{
					OIDCDomain: oidcDomain,
					ClientID:   clientID,
					Output:     LoginOutputFriendly,
				}

				ctx := AppContext{
					Config: config,
				}

				if err := login.Run(&ctx); err != nil {
					return err
				}
			} else {
				return ErrTokensExpiredOrAbsent
			}
			return nil
		}

		ttl, _ := cmd.Flags().GetUint(FlagTimeToLive)
		timeRemaining, _ := cmd.Flags().GetUint(FlagTimeRemaining)
		outputType, _ := cmd.Flags().GetString(FlagOutputType)
		shellType, _ := cmd.Flags().GetString(FlagShellType)
		roleName, _ := cmd.Flags().GetString(FlagRoleName)
		cloudType, _ := cmd.Flags().GetString(FlagCloudType)
		awsCliPath, _ := cmd.Flags().GetString(FlagAWSCLIPath)
		tencentCliPath, _ := cmd.Flags().GetString(FlagTencentCLIPath)

		if !isMemberOfSlice(permittedOutputTypes, outputType) {
			return ValueError{Value: outputType, ValidValues: permittedOutputTypes}
		}

		if !isMemberOfSlice(permittedShellTypes, shellType) {
			return ValueError{Value: shellType, ValidValues: permittedShellTypes}
		}

		var accountID string
		if len(args) > 0 {
			accountID = args[0]
		} else if config.LastUsedAccount != nil {
			// No account specified. Can we use the most recent one?
			accountID = *config.LastUsedAccount
		} else {
			return cmd.Usage()
		}

		bypassCache, _ := cmd.Flags().GetBool(FlagBypassCache)
		account, ok := resolveApplicationInfo(config, bypassCache, accountID)
		if !ok {
			return UnknownAccountError(args[0], FlagBypassCache)
		}

		if roleName == "" {
			if account.MostRecentRole == "" {
				cmd.PrintErrln("You must specify the --role flag with this command")
				return nil
			}
			roleName = account.MostRecentRole
		}

		if config.TimeRemaining != 0 && timeRemaining == DefaultTimeRemaining {
			timeRemaining = config.TimeRemaining
		}

		var credentials CloudCredentials
		if cloudType == cloudAws {
			credentials = LoadAWSCredentialsFromEnvironment()
		} else if cloudType == cloudTencent {
			credentials = LoadTencentCredentialsFromEnvironment()
		}

		if credentials.ValidUntil(account, time.Duration(timeRemaining)*time.Minute) {
			return echoCredentials(accountID, accountID, credentials, outputType, shellType, awsCliPath, tencentCliPath)
		}

		samlResponse, assertionStr, err := DiscoverConfigAndExchangeTokenForAssertion(cmd.Context(), NewHTTPClient(), config.Tokens, oidcDomain, clientID, account.ID)
		if err != nil {
			return err
		}

		pair, ok := FindRoleInSAML(roleName, samlResponse)
		if !ok {
			return UnknownRoleError(roleName, args[0])
		}

		if ttl == 1 && config.TTL != 0 {
			ttl = config.TTL
		}

		if cloudType == cloudAws {
			region, _ := cmd.Flags().GetString(FlagRegion)
			session, _ := session.NewSession(&aws.Config{Region: aws.String(region)})
			stsClient := sts.New(session)
			timeoutInSeconds := int64(3600 * ttl)
			resp, err := stsClient.AssumeRoleWithSAMLWithContext(ctx, &sts.AssumeRoleWithSAMLInput{
				DurationSeconds: &timeoutInSeconds,
				PrincipalArn:    &pair.ProviderARN,
				RoleArn:         &pair.RoleARN,
				SAMLAssertion:   &assertionStr,
			})

			if err, ok := tryParseTimeToLiveError(err); ok {
				return err
			}

			if err != nil {
				return AWSError{
					InnerError: err,
					Message:    "failed to exchange credentials",
				}
			}

			credentials = CloudCredentials{
				AccessKeyID:     *resp.Credentials.AccessKeyId,
				Expiration:      resp.Credentials.Expiration.Format(time.RFC3339),
				SecretAccessKey: *resp.Credentials.SecretAccessKey,
				SessionToken:    *resp.Credentials.SessionToken,
				credentialsType: cloudType,
			}
		} else {
			panic("not yet implemented")
		}

		if account != nil {
			account.MostRecentRole = roleName
		}
		config.LastUsedAccount = &accountID

		return echoCredentials(accountID, accountID, credentials, outputType, shellType, awsCliPath, tencentCliPath)
	}}

func echoCredentials(id, name string, credentials CloudCredentials, outputType, shellType, awsCliPath, tencentCliPath string) error {
	switch outputType {
	case outputTypeEnvironmentVariable:
		credentials.WriteFormat(os.Stdout, shellType)
		return nil
	case outputTypeAWSCredentialsFile, outputTypeTencentCredentialsFile:
		acc := Account{ID: id, Name: name}
		newCliEntry := NewCloudCliEntry(credentials, &acc)
		cliPath := awsCliPath
		if outputType == outputTypeTencentCredentialsFile {
			cliPath = tencentCliPath
		}
		return SaveCloudCredentialInCLI(cliPath, newCliEntry)
	default:
		return fmt.Errorf("%s is an invalid output type", outputType)
	}
}
