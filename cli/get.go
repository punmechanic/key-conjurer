package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/browser"
	"github.com/riotgames/key-conjurer/internal/api"
	"github.com/spf13/cobra"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	tencentsts "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/sts/v20180813"
)

var (
	FlagRegion         = "region"
	FlagRoleName       = "role"
	FlagTimeRemaining  = "time-remaining"
	FlagTimeToLive     = "ttl"
	FlagBypassCache    = "bypass-cache"
	FlagOutputType     = "out"
	FlagShellType      = "shell"
	FlagAWSCLIPath     = "awscli"
	FlagTencentCLIPath = "tencentcli"
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

func init() {
	getCmd.Flags().String(FlagRegion, "us-west-2", "The AWS region to use")
	getCmd.Flags().Uint(FlagTimeToLive, 1, "The key timeout in hours from 1 to 8.")
	getCmd.Flags().UintP(FlagTimeRemaining, "t", DefaultTimeRemaining, "Request new keys if there are no keys in the environment or the current keys expire within <time-remaining> minutes. Defaults to 60.")
	getCmd.Flags().StringP(FlagRoleName, "r", "", "The name of the role to assume.")
	getCmd.Flags().StringP(FlagOutputType, "o", outputTypeEnvironmentVariable, "Format to save new credentials in. Supported outputs: env, awscli,tencentcli")
	getCmd.Flags().String(FlagShellType, shellTypeInfer, "If output type is env, determines which format to output credentials in - by default, the format is inferred based on the execution environment. WSL users may wish to overwrite this to `bash`")
	getCmd.Flags().String(FlagAWSCLIPath, "~/.aws/", "Path for directory used by the aws-cli tool. Default is \"~/.aws\".")
	getCmd.Flags().String(FlagTencentCLIPath, "~/.tencent/", "Path for directory used by the tencent-cli tool. Default is \"~/.tencent\".")
	getCmd.Flags().Bool(FlagBypassCache, false, "Do not check the cache for accounts and send the application ID as-is to Okta. This is useful if you have an ID you know is an Okta application ID and it is not stored in your local account cache.")
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

var getCmd = &cobra.Command{
	Use:   "get <accountName/alias>",
	Short: "Retrieves temporary cloud API credentials.",
	Long: `Retrieves temporary cloud API credentials for the specified account.  It sends a push request to the first Duo device it finds associated with your account.

A role must be specified when using this command through the --role flag. You may list the roles you can assume through the roles command.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		config := ConfigFromCommand(cmd)
		ctx := cmd.Context()
		if HasTokenExpired(config.Tokens) {
			cmd.PrintErrln("Your session has expired. Please login again.")
			return nil
		}
		client := NewHTTPClient()

		ttl, _ := cmd.Flags().GetUint(FlagTimeToLive)
		timeRemaining, _ := cmd.Flags().GetUint(FlagTimeRemaining)
		outputType, _ := cmd.Flags().GetString(FlagOutputType)
		shellType, _ := cmd.Flags().GetString(FlagShellType)
		roleName, _ := cmd.Flags().GetString(FlagRoleName)
		oidcDomain, _ := cmd.Flags().GetString(FlagOIDCDomain)
		clientID, _ := cmd.Flags().GetString(FlagClientID)
		awsCliPath, _ := cmd.Flags().GetString(FlagAWSCLIPath)
		tencentCliPath, _ := cmd.Flags().GetString(FlagTencentCLIPath)

		if !isMemberOfSlice(permittedOutputTypes, outputType) {
			return invalidValueError(outputType, permittedOutputTypes)
		}

		if !isMemberOfSlice(permittedShellTypes, shellType) {
			return invalidValueError(shellType, permittedShellTypes)
		}

		// make sure we enforce limit
		if ttl > 8 {
			ttl = 8
		}

		bypassCache, _ := cmd.Flags().GetBool(FlagBypassCache)
		account, ok := resolveApplicationInfo(config, bypassCache, args[0])
		if !ok {
			cmd.PrintErrf("%q is not a known account name in your account cache. Your cache can be refreshed by entering executing `keyconjurer accounts`. If the value provided is an Okta application ID, you may provide %s as an option to this command and try again.", args[0], FlagBypassCache)
			return nil
		}

		cloudType := cloudAws
		if account.Type == api.ApplicationTypeTencent {
			if account.Href == "" {
				cmd.PrintErrf(
					"The application %q is a Tencent application, but it does not have a URL configured. Please run %s again. If this error persists, confirm that %q is a Tencent application",
					account.Name,
					"keyconjurer login",
					account.Name,
				)

				return nil
			}

			cloudType = cloudTencent
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
			return echoCredentials(args[0], args[0], credentials, outputType, shellType, awsCliPath, tencentCliPath)
		}

		if ttl == 1 && config.TTL != 0 {
			ttl = config.TTL
		}
		region, _ := cmd.Flags().GetString(FlagRegion)
		var provider SAMLAssertionProvider
		if cloudType == cloudAws {
			provider = OktaAWSSAMLProvider{
				OIDCDomain: oidcDomain,
				ClientID:   clientID,
				Tokens:     config.Tokens,
				AccountID:  account.ID,
				Client:     client,
				Region:     region,
				TTL:        ttl,
			}
		} else if cloudType == cloudTencent {
			// Tencent applications aren't supported by the Okta API, so we can't use the same flow as AWS.
			// Instead, we can construct a URL to initiate logging into the application that has been pre-configured to support KeyConjurer.
			// This URL will redirect back to a web server known ahead of time with a SAML assertion which we can then exchange for credentials.
			//
			// Because we need to know the URL of the application, --bypass-cache can't be used.
			if bypassCache {
				cmd.PrintErrf("cannot use --%s with Tencent applications\n", FlagBypassCache)
				return nil
			}

			provider = OktaTencentCloudSAMLProvider{
				Href:   account.Href,
				Region: region,
				TTL:    ttl,
			}
		}

		assertionBytes, err := provider.FetchSAMLAssertion(cmd.Context())
		if err != nil {
			cmd.PrintErrf("could not fetch SAML assertion: %s\n", err)
			return nil
		}

		samlResponse, err := ParseBase64EncodedSAMLResponse(string(assertionBytes))
		if err != nil {
			cmd.PrintErrf("could not parse assertion: %s\n", err)
			return nil
		}

		pair, ok := FindRoleInSAML(roleName, samlResponse)
		if !ok {
			cmd.PrintErrf("you do not have access to the role %s on application %s\n", roleName, args[0])
			return nil
		}

		credentials, err = provider.ExchangeAssertionForCredentials(ctx, *samlResponse, pair)
		if err != nil {
			cmd.PrintErrf("failed to exchange SAML assertion for credentials: %s", err)
			return nil
		}

		if account != nil {
			account.MostRecentRole = roleName
		}

		return echoCredentials(args[0], args[0], credentials, outputType, shellType, awsCliPath, tencentCliPath)
	}}

type SAMLAssertionProvider interface {
	FetchSAMLAssertion(ctx context.Context) ([]byte, error)
	ExchangeAssertionForCredentials(ctx context.Context, response SAMLResponse, rp RoleProviderPair) (CloudCredentials, error)
}

type OktaAWSSAMLProvider struct {
	OIDCDomain string
	ClientID   string
	Tokens     *TokenSet
	AccountID  string
	Client     *http.Client
	TTL        uint
	Region     string
}

func (r OktaAWSSAMLProvider) ExchangeAssertionForCredentials(ctx context.Context, response SAMLResponse, rp RoleProviderPair) (CloudCredentials, error) {
	session, _ := session.NewSession(&aws.Config{Region: aws.String(r.Region)})
	stsClient := sts.New(session)
	timeoutInSeconds := int64(3600 * r.TTL)
	resp, err := stsClient.AssumeRoleWithSAMLWithContext(ctx, &sts.AssumeRoleWithSAMLInput{
		DurationSeconds: &timeoutInSeconds,
		PrincipalArn:    &rp.ProviderARN,
		RoleArn:         &rp.RoleARN,
		SAMLAssertion:   &response.original,
	})

	if err != nil {
		return CloudCredentials{}, err
	}

	return CloudCredentials{
		AccessKeyID:     *resp.Credentials.AccessKeyId,
		Expiration:      resp.Credentials.Expiration.Format(time.RFC3339),
		SecretAccessKey: *resp.Credentials.SecretAccessKey,
		SessionToken:    *resp.Credentials.SessionToken,
		credentialsType: cloudAws,
	}, nil
}

func (r OktaAWSSAMLProvider) FetchSAMLAssertion(ctx context.Context) ([]byte, error) {
	oauthCfg, err := DiscoverOAuth2Config(ctx, r.OIDCDomain, r.ClientID)
	if err != nil {
		return nil, fmt.Errorf("could not discover OAuth2 configuration: %w", err)
	}

	tok, err := ExchangeAccessTokenForWebSSOToken(ctx, r.Client, oauthCfg, r.Tokens, r.AccountID)
	if err != nil {
		return nil, fmt.Errorf("could not exchange access token for web sso token: %w", err)
	}

	assertion, err := ExchangeWebSSOTokenForSAMLAssertion(ctx, r.Client, r.OIDCDomain, tok)
	if err != nil {
		return nil, fmt.Errorf("could not exchange web sso token for saml assertion: %w", err)
	}

	return assertion, nil
}

type OktaTencentCloudSAMLProvider struct {
	Href   string
	Region string
	TTL    uint
}

func (p OktaTencentCloudSAMLProvider) FetchSAMLAssertion(ctx context.Context) ([]byte, error) {
	handler := SAMLCallbackHandler{
		AssertionChannel: make(chan []byte, 1),
	}

	// Listening and serving are done separately, so that we can confirm the port is available before launching a browser.
	// Listening attempts to reserves the port, but doesn't block.
	addr := "127.0.0.1:57468"
	sock, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	server := http.Server{Handler: &handler}
	go server.Serve(sock)
	// The socket becomes owned by the server so we don't need to close it.
	defer server.Close()

	if err := browser.OpenURL(p.Href); err != nil {
		return nil, fmt.Errorf("failed to open web browser to URL %s: %w", p.Href, err)
	}

	select {
	case assert := <-handler.AssertionChannel:
		return assert, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p OktaTencentCloudSAMLProvider) ExchangeAssertionForCredentials(ctx context.Context, response SAMLResponse, rp RoleProviderPair) (CloudCredentials, error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "sts.tencentcloudapi.com"
	client, _ := tencentsts.NewClient(&common.Credential{}, p.Region, cpf)

	timeoutInSeconds := int64(3600 * p.TTL)
	req := tencentsts.NewAssumeRoleWithSAMLRequest()
	req.RoleSessionName = common.StringPtr(fmt.Sprintf("riot-keyConjurer-%s", rp.RoleARN))
	req.DurationSeconds = common.Uint64Ptr(uint64(timeoutInSeconds))
	req.PrincipalArn = &rp.ProviderARN
	req.RoleArn = &rp.RoleARN
	req.SAMLAssertion = &response.original
	resp, err := client.AssumeRoleWithSAMLWithContext(ctx, req)
	if err != nil {
		return CloudCredentials{}, err
	}

	credentials := resp.Response.Credentials
	return CloudCredentials{
		AccessKeyID:     *credentials.TmpSecretId,
		SecretAccessKey: *credentials.TmpSecretKey,
		SessionToken:    *credentials.Token,
		Expiration:      *resp.Response.Expiration,
	}, nil
}

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
