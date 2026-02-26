// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package awsutil

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-hclog"
)

const (
	iamServerIdHeader = "X-Vault-AWS-IAM-Server-ID"
	defaultStr        = "default"
	envAwsProfile     = "AWS_PROFILE"
)

var (
	ErrReadOptsCredChain         = errors.New("error reading options in GenerateCredentialChain")
	ErrBadStaticCreds            = errors.New("static AWS client credentials haven't been properly configured (the access key or secret key were provided but not both)")
	ErrLoadConfigWithCredsFailed = errors.New("failed to load SDK's default configurations with given credential options")
)

type CredentialsConfig struct {
	// The access key if static credentials are being used
	AccessKey string

	// The secret key if static credentials are being used
	SecretKey string

	// The session token if it is being used
	SessionToken string

	// The IAM endpoint resolver to use; if not set will use the default
	IAMEndpointResolver iam.EndpointResolverV2

	// The STS endpoint resolver to use; if not set will use the default
	STSEndpointResolver sts.EndpointResolverV2

	// If specified, the region will be provided to the config of the
	// EC2RoleProvider's client. This may be useful if you want to e.g. reuse
	// the client elsewhere. If not specified, the region will be determined
	// by the environment variables "AWS_REGION" or "AWS_DEFAULT_REGION".
	// Otherwise the default value is us-east-1.
	Region string

	// The filename for the shared credentials provider, if being used
	Filename string

	// The profile for the shared credentials provider, if being used
	Profile string

	// The role arn to use when creating either a web identity role provider
	// or a ec2-instance role provider.
	RoleARN string

	// The role session name to use when creating either a web identity role provider
	// or a ec2-instance role provider.
	RoleSessionName string

	// The role external ID to use when creating a ec2-instance role provider.
	RoleExternalId string

	// The role tags to use when creating a ec2-instance role provider.
	RoleTags map[string]string

	// The web identity token file to use if using the web identity token provider
	WebIdentityTokenFile string

	// The web identity token (contents, not the file path) to use with the web
	// identity token provider
	WebIdentityToken string

	// The http.Client to use, or nil for the client to use its default
	HTTPClient *http.Client

	// The max retries to set on the client. This is a pointer because the zero
	// value has meaning. A nil pointer will use the default value.
	MaxRetries *int

	// The logger to use for credential acquisition debugging
	Logger hclog.Logger
}

// GenerateCredentialChain uses the config to generate a credential chain
// suitable for creating AWS sessions and clients.
//
// Supported options: WithAccessKey, WithSecretKey, WithLogger, WithStsEndpointResolver,
// WithIamEndpointResolver, WithMaxRetries, WithRegion, WithHttpClient, WithRoleArn,
// WithRoleSessionName, WithRoleExternalId, WithRoleTags, WithWebIdentityTokenFile,
// WithWebIdentityToken.
func NewCredentialsConfig(opt ...Option) (*CredentialsConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("error reading options in NewCredentialsConfig: %w", err)
	}

	c := &CredentialsConfig{
		AccessKey:           opts.withAccessKey,
		SecretKey:           opts.withSecretKey,
		Logger:              opts.withLogger,
		STSEndpointResolver: opts.withStsEndpointResolver,
		IAMEndpointResolver: opts.withIamEndpointResolver,
		MaxRetries:          opts.withMaxRetries,
		RoleExternalId:      opts.withRoleExternalId,
		RoleTags:            opts.withRoleTags,
	}

	c.Region = opts.withRegion
	if c.Region == "" {
		c.Region = os.Getenv("AWS_REGION")
		if c.Region == "" {
			c.Region = os.Getenv("AWS_DEFAULT_REGION")
			if c.Region == "" {
				c.Region = "us-east-1"
			}
		}
	}
	c.RoleARN = opts.withRoleArn
	if c.RoleARN == "" {
		c.RoleARN = os.Getenv("AWS_ROLE_ARN")
	}
	c.RoleSessionName = opts.withRoleSessionName
	if c.RoleSessionName == "" {
		c.RoleSessionName = os.Getenv("AWS_ROLE_SESSION_NAME")
	}
	c.WebIdentityTokenFile = opts.withWebIdentityTokenFile
	if c.WebIdentityTokenFile == "" {
		c.WebIdentityTokenFile = os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
	}
	c.WebIdentityToken = opts.withWebIdentityToken

	if c.RoleARN == "" {
		if c.RoleSessionName != "" {
			return nil, fmt.Errorf("role session name specified without role ARN")
		}
		if c.RoleExternalId != "" {
			return nil, fmt.Errorf("role external ID specified without role ARN")
		}
		if len(c.RoleTags) > 0 {
			return nil, fmt.Errorf("role tags specified without role ARN")
		}
		if c.WebIdentityTokenFile != "" {
			return nil, fmt.Errorf("web identity token file specified without role ARN")
		}
		if len(c.WebIdentityToken) > 0 {
			return nil, fmt.Errorf("web identity token specified without role ARN")
		}
	}

	c.HTTPClient = opts.withHttpClient
	if c.HTTPClient == nil {
		c.HTTPClient = cleanhttp.DefaultClient()
	}

	return c, nil
}

// Make sure the logger isn't nil before logging
func (c *CredentialsConfig) log(level hclog.Level, msg string, args ...interface{}) {
	if c.Logger != nil {
		c.Logger.Log(level, msg, args...)
	}
}

func (c *CredentialsConfig) generateAwsConfigOptions(ctx context.Context, opts options) []func(*config.LoadOptions) error {
	var cfgOpts []func(*config.LoadOptions) error

	if c.Region != "" {
		cfgOpts = append(cfgOpts, config.WithRegion(c.Region))
	}

	if c.MaxRetries != nil {
		cfgOpts = append(cfgOpts, config.WithRetryMaxAttempts(*c.MaxRetries))
	}

	if c.HTTPClient != nil {
		cfgOpts = append(cfgOpts, config.WithHTTPClient(c.HTTPClient))
	}

	// Add the shared credentials
	if opts.withSharedCredentials {
		profile := os.Getenv(envAwsProfile)
		if profile != "" {
			c.Profile = profile
		}

		// The AWS SDK will check for the 'default' shared profile and include it if it exists. If
		// WithSharedConfigProfile is set to 'default' here, and it does not exist the SDK will return an error. So
		// if profile is not set, check for a default profile and add it only if it exists.
		if c.Profile != "" {
			cfgOpts = append(cfgOpts, config.WithSharedConfigProfile(c.Profile))
		} else {
			c.Profile = defaultStr
			opts := []func(*config.LoadOptions) error{config.WithSharedConfigProfile(defaultStr)}
			if c.Filename != "" {
				opts = append(opts, config.WithSharedCredentialsFiles([]string{c.Filename}))
			}
			_, err := config.LoadDefaultConfig(ctx, opts...)
			// aws-sdk's special errors don't work with go's errors.Is
			_, ok := err.(config.SharedConfigProfileNotExistError)
			if !ok {
				cfgOpts = append(cfgOpts, config.WithSharedConfigProfile(defaultStr))
			}
		}

		cfgOpts = append(cfgOpts, config.WithSharedCredentialsFiles([]string{c.Filename}))
		c.log(hclog.Debug, "added shared profile credential provider")
	}

	// Add the static credential
	if c.AccessKey != "" && c.SecretKey != "" {
		staticCred := credentials.NewStaticCredentialsProvider(c.AccessKey, c.SecretKey, c.SessionToken)
		cfgOpts = append(cfgOpts, config.WithCredentialsProvider(staticCred))
		c.log(hclog.Debug, "added static credential provider", "AccessKey", c.AccessKey)
	}

	// Add the assume role provider
	if c.RoleARN != "" {
		if c.WebIdentityTokenFile != "" {
			// this session is only created to create the WebIdentityRoleProvider, variables used to
			// assume a role are pulled from values provided in options. If the option values are
			// not set, then the provider will default to using the environment variables.
			webIdentityRoleCred := config.WithWebIdentityRoleCredentialOptions(func(options *stscreds.WebIdentityRoleOptions) {
				options.RoleARN = c.RoleARN
				options.RoleSessionName = c.RoleSessionName
				options.TokenRetriever = stscreds.IdentityTokenFile(c.WebIdentityTokenFile)
			})
			cfgOpts = append(cfgOpts, webIdentityRoleCred)
			c.log(hclog.Debug, "added web identity provider", "roleARN", c.RoleARN)
		} else if c.WebIdentityToken != "" {
			webIdentityRoleCred := config.WithWebIdentityRoleCredentialOptions(func(options *stscreds.WebIdentityRoleOptions) {
				options.RoleARN = c.RoleARN
				options.RoleSessionName = c.RoleSessionName
				options.TokenRetriever = FetchTokenContents(c.WebIdentityToken)
			})
			cfgOpts = append(cfgOpts, webIdentityRoleCred)
			c.log(hclog.Debug, "added web identity provider with token", "roleARN", c.RoleARN)
		} else {
			// this session is only created to create the AssumeRoleProvider, variables used to
			// assume a role are pulled from values provided in options. If the option values are
			// not set, then the provider will default to using the environment variables.
			assumeRoleCred := config.WithAssumeRoleCredentialOptions(func(options *stscreds.AssumeRoleOptions) {
				options.RoleARN = c.RoleARN
				options.RoleSessionName = c.RoleSessionName
				options.ExternalID = aws.String(c.RoleExternalId)
				for k, v := range c.RoleTags {
					options.Tags = append(options.Tags, types.Tag{
						Key:   aws.String(k),
						Value: aws.String(v),
					})
				}
			})
			cfgOpts = append(cfgOpts, assumeRoleCred)
			c.log(hclog.Debug, "added ec2-instance role provider", "roleARN", c.RoleARN)
		}
	}

	return cfgOpts
}

// GenerateCredentialChain uses the config to generate a credential chain
// suitable for creating AWS clients. This will by default load configuration
// values from environment variables and append additional configuration options
// provided to the CredentialsConfig.
//
// Supported options: WithSharedCredentials, WithCredentialsProvider
func (c *CredentialsConfig) GenerateCredentialChain(ctx context.Context, opt ...Option) (*aws.Config, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadOptsCredChain, err)
	}

	// Have one or the other but not both and not neither
	if (c.AccessKey != "" && c.SecretKey == "") || (c.AccessKey == "" && c.SecretKey != "") {
		return nil, ErrBadStaticCreds
	}

	awsConfig, err := config.LoadDefaultConfig(ctx, c.generateAwsConfigOptions(ctx, opts)...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLoadConfigWithCredsFailed, err)
	}

	if opts.withCredentialsProvider != nil {
		awsConfig.Credentials = opts.withCredentialsProvider
	}

	return &awsConfig, nil
}

func RetrieveCreds(ctx context.Context, accessKey, secretKey, sessionToken string, logger hclog.Logger, opt ...Option) (*aws.Config, error) {
	credConfig := CredentialsConfig{
		AccessKey:    accessKey,
		SecretKey:    secretKey,
		SessionToken: sessionToken,
		Logger:       logger,
	}
	creds, err := credConfig.GenerateCredentialChain(ctx, opt...)
	if err != nil {
		return nil, err
	}
	if creds == nil {
		return nil, fmt.Errorf("could not compile valid credential providers from static config, environment, shared, or instance metadata")
	}
	_, err = creds.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve credentials from credential chain: %w", err)
	}
	return creds, nil
}

// FetchTokenContents allows the use of the content of a token in the
// WebIdentityProvider, instead of the path to a token. Useful with a
// serviceaccount token requested directly from the EKS/K8s API, for example.
type FetchTokenContents []byte

var _ stscreds.IdentityTokenRetriever = (*FetchTokenContents)(nil)

func (f FetchTokenContents) GetIdentityToken() ([]byte, error) {
	return f, nil
}
