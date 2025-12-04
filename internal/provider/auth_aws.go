// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithyendpoints "github.com/aws/smithy-go/endpoints"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/awsutil/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

const (
	envVarAWSAccessKeyID           = "AWS_ACCESS_KEY_ID"
	envVarAWSSecretAccessKey       = "AWS_SECRET_ACCESS_KEY"
	envVarAWSSessionToken          = "AWS_SESSION_TOKEN"
	envVarAWSProfile               = "AWS_PROFILE"
	envVarAWSSharedCredentialsFile = "AWS_SHARED_CREDENTIALS_FILE"
	envVarAWSWebIdentityTokenFile  = "AWS_WEB_IDENTITY_TOKEN_FILE"
	envVarAWSRoleARN               = "AWS_ROLE_ARN"
	envVarAWSRoleSessionName       = "AWS_ROLE_SESSION_NAME"
	envVarAWSRegion                = "AWS_REGION"
	envVarAWSDefaultRegion         = "AWS_DEFAULT_REGION"
)

func init() {
	field := consts.FieldAuthLoginAWS
	if err := globalAuthLoginRegistry.Register(field,
		func(r *schema.ResourceData) (AuthLogin, error) {
			a := &AuthLoginAWS{}
			return a.Init(r, field)
		}, GetAWSLoginSchema); err != nil {
		panic(err)
	}
}

// GetAWSLoginSchema for the AWS authentication engine.
func GetAWSLoginSchema(authField string) *schema.Schema {
	return getLoginSchema(
		authField,
		"Login to vault using the AWS method",
		GetAWSLoginSchemaResource,
	)
}

// GetAWSLoginSchemaResource for the AWS authentication engine.
func GetAWSLoginSchemaResource(authField string) *schema.Resource {
	return mustAddLoginSchema(&schema.Resource{
		Schema: map[string]*schema.Schema{
			consts.FieldRole: {
				Type:        schema.TypeString,
				Required:    true,
				Description: `The Vault role to use when logging into Vault.`,
			},
			// static credential fields
			consts.FieldAWSAccessKeyID: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: `The AWS access key ID.`,
			},
			consts.FieldAWSSecretAccessKey: {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  `The AWS secret access key.`,
				RequiredWith: []string{fmt.Sprintf("%s.0.%s", authField, consts.FieldAWSAccessKeyID)},
			},
			consts.FieldAWSSessionToken: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: `The AWS session token.`,
			},
			consts.FieldAWSProfile: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: `The name of the AWS profile.`,
			},
			consts.FieldAWSSharedCredentialsFile: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: `Path to the AWS shared credentials file.`,
			},
			consts.FieldAWSWebIdentityTokenFile: {
				Type:     schema.TypeString,
				Optional: true,
				Description: `Path to the file containing an OAuth 2.0 access token or OpenID ` +
					`Connect ID token.`,
			},
			// STS assume role fields
			consts.FieldAWSRoleARN: {
				Type:     schema.TypeString,
				Optional: true,
				Description: `The ARN of the AWS Role to assume.` +
					`Used during STS AssumeRole`,
			},
			consts.FieldAWSRoleSessionName: {
				Type:     schema.TypeString,
				Optional: true,
				Description: `Specifies the name to attach to the AWS role session. ` +
					`Used during STS AssumeRole`,
			},
			consts.FieldAWSRegion: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: `The AWS region.`,
			},
			consts.FieldAWSSTSEndpoint: {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      `The STS endpoint URL.`,
				ValidateDiagFunc: GetValidateDiagURI([]string{"https", "http"}),
			},
			consts.FieldAWSIAMEndpoint: {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      `The IAM endpoint URL.`,
				ValidateDiagFunc: GetValidateDiagURI([]string{"https", "http"}),
			},
			consts.FieldHeaderValue: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: `The Vault header value to include in the STS signing request.`,
			},
		},
	}, authField, consts.MountTypeAWS)
}

var _ AuthLogin = (*AuthLoginAWS)(nil)

// AuthLoginAWS for handling the Vault AWS authentication engine.
// Requires configuration provided by SchemaLoginAWS.
type AuthLoginAWS struct {
	AuthLoginCommon
}

func (l *AuthLoginAWS) Init(d *schema.ResourceData, authField string) (AuthLogin, error) {
	defaults := l.getDefaults()
	if err := l.AuthLoginCommon.Init(d, authField,
		func(data *schema.ResourceData, params map[string]interface{}) error {
			return l.setDefaultFields(d, defaults, params)
		},
		func(data *schema.ResourceData, params map[string]interface{}) error {
			return l.checkRequiredFields(d, params, consts.FieldRole)
		},
	); err != nil {
		return nil, err
	}

	return l, nil
}

// MountPath for the aws authentication engine.
func (l *AuthLoginAWS) MountPath() string {
	if l.mount == "" {
		return l.Method()
	}
	return l.mount
}

// LoginPath for the aws authentication engine.
func (l *AuthLoginAWS) LoginPath() string {
	return fmt.Sprintf("auth/%s/login", l.MountPath())
}

// Method name for the AWS authentication engine.
func (l *AuthLoginAWS) Method() string {
	return consts.AuthMethodAWS
}

// Login using the aws authentication engine.
func (l *AuthLoginAWS) Login(client *api.Client) (*api.Secret, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}

	params, err := l.copyParams(
		consts.FieldRole,
	)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	loginData, err := l.getLoginData(ctx, getHCLogger())
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS credentials required for Vault login, err=%w", err)
	}
	for k, v := range loginData {
		params[k] = v
	}

	return l.login(client, l.LoginPath(), params)
}

func (l *AuthLoginAWS) getDefaults() authDefaults {
	defaults := authDefaults{
		{
			field:      consts.FieldAWSAccessKeyID,
			envVars:    []string{envVarAWSAccessKeyID},
			defaultVal: "",
		},
		{
			field:      consts.FieldAWSSecretAccessKey,
			envVars:    []string{envVarAWSSecretAccessKey},
			defaultVal: "",
		},
		{
			field:      consts.FieldAWSSessionToken,
			envVars:    []string{envVarAWSSessionToken},
			defaultVal: "",
		},
		{
			field:      consts.FieldAWSProfile,
			envVars:    []string{envVarAWSProfile},
			defaultVal: "",
		},
		{
			field:      consts.FieldAWSSharedCredentialsFile,
			envVars:    []string{envVarAWSSharedCredentialsFile},
			defaultVal: "",
		},
		{
			field:      consts.FieldAWSWebIdentityTokenFile,
			envVars:    []string{envVarAWSWebIdentityTokenFile},
			defaultVal: "",
		},
		{
			field:      consts.FieldAWSRoleARN,
			envVars:    []string{envVarAWSRoleARN},
			defaultVal: "",
		},
		{
			field:      consts.FieldAWSRoleSessionName,
			envVars:    []string{envVarAWSRoleSessionName},
			defaultVal: "",
		},
		{
			field:      consts.FieldAWSRegion,
			envVars:    []string{envVarAWSRegion, envVarAWSDefaultRegion},
			defaultVal: "",
		},
	}

	return defaults
}

func (l *AuthLoginAWS) getLoginData(ctx context.Context, logger hclog.Logger) (map[string]interface{}, error) {
	// Get credentials configuration
	config, err := l.getCredentialsConfig(logger)
	if err != nil {
		return nil, err
	}

	awsConfig, err := config.GenerateCredentialChain(ctx)
	if err != nil {
		return nil, err
	}

	// Check if we need to assume a role
	var roleARN string
	if v, ok := l.params[consts.FieldAWSRoleARN].(string); ok && v != "" {
		roleARN = v

		// Create STS client with base credentials and custom endpoint if configured
		var stsOpts []func(*sts.Options)
		if v, ok := l.params[consts.FieldAWSSTSEndpoint].(string); ok && v != "" {
			stsOpts = append(stsOpts, sts.WithEndpointResolverV2(&customSTSEndpointResolver{endpointURL: v}))
		}
		stsClient := sts.NewFromConfig(*awsConfig, stsOpts...)

		// Get role session name
		roleSessionName := "vault-provider-session"
		if v, ok := l.params[consts.FieldAWSRoleSessionName].(string); ok && v != "" {
			roleSessionName = v
		}

		// Call AssumeRole
		assumeRoleOutput, err := stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
			RoleArn:         aws.String(roleARN),
			RoleSessionName: aws.String(roleSessionName),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to assume role %s: %w", roleARN, err)
		}

		// Create a new config with the assumed role credentials
		awsConfig = &aws.Config{
			Region: awsConfig.Region,
			Credentials: aws.NewCredentialsCache(
				aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
					return aws.Credentials{
						AccessKeyID:     aws.ToString(assumeRoleOutput.Credentials.AccessKeyId),
						SecretAccessKey: aws.ToString(assumeRoleOutput.Credentials.SecretAccessKey),
						SessionToken:    aws.ToString(assumeRoleOutput.Credentials.SessionToken),
						Source:          "ManualAssumeRole",
						CanExpire:       true,
						Expires:         *assumeRoleOutput.Credentials.Expiration,
					}, nil
				}),
			),
		}
	}

	var headerValue string
	if v, ok := l.params[consts.FieldHeaderValue].(string); ok {
		headerValue = v
	}

	return generateLoginData(ctx, awsConfig, headerValue, logger)
}

// customSTSEndpointResolver creates an endpoint resolver for STS with a custom endpoint URL
type customSTSEndpointResolver struct {
	endpointURL string
}

func (r *customSTSEndpointResolver) ResolveEndpoint(ctx context.Context, params sts.EndpointParameters) (smithyendpoints.Endpoint, error) {
	// Parse the custom endpoint URL
	uri, err := url.Parse(r.endpointURL)
	if err != nil {
		return smithyendpoints.Endpoint{}, fmt.Errorf("failed to parse custom STS endpoint URL: %w", err)
	}

	// Return custom endpoint
	return smithyendpoints.Endpoint{
		URI: *uri,
	}, nil
}

// customIAMEndpointResolver creates an endpoint resolver for IAM with a custom endpoint URL
type customIAMEndpointResolver struct {
	endpointURL string
}

func (r *customIAMEndpointResolver) ResolveEndpoint(ctx context.Context, params iam.EndpointParameters) (smithyendpoints.Endpoint, error) {
	// Parse the custom endpoint URL
	uri, err := url.Parse(r.endpointURL)
	if err != nil {
		return smithyendpoints.Endpoint{}, fmt.Errorf("failed to parse custom IAM endpoint URL: %w", err)
	}

	// Return custom endpoint
	return smithyendpoints.Endpoint{
		URI: *uri,
	}, nil
}

func (l *AuthLoginAWS) getCredentialsConfig(logger hclog.Logger) (*awsutil.CredentialsConfig, error) {
	// Build options for NewCredentialsConfig
	var opts []awsutil.Option

	if v, ok := l.params[consts.FieldAWSAccessKeyID].(string); ok && v != "" {
		opts = append(opts, awsutil.WithAccessKey(v))
	}
	if v, ok := l.params[consts.FieldAWSSecretAccessKey].(string); ok && v != "" {
		opts = append(opts, awsutil.WithSecretKey(v))
	}
	if v, ok := l.params[consts.FieldAWSRegion].(string); ok && v != "" {
		opts = append(opts, awsutil.WithRegion(v))
	}
	if v, ok := l.params[consts.FieldAWSRoleARN].(string); ok && v != "" {
		opts = append(opts, awsutil.WithRoleArn(v))
	}
	if v, ok := l.params[consts.FieldAWSRoleSessionName].(string); ok && v != "" {
		opts = append(opts, awsutil.WithRoleSessionName(v))
	}
	if v, ok := l.params[consts.FieldAWSWebIdentityTokenFile].(string); ok && v != "" {
		opts = append(opts, awsutil.WithWebIdentityTokenFile(v))
	}

	opts = append(opts, awsutil.WithLogger(logger))

	config, err := awsutil.NewCredentialsConfig(opts...)
	if err != nil {
		return nil, err
	}

	// Set fields that aren't available through options
	if v, ok := l.params[consts.FieldAWSProfile].(string); ok && v != "" {
		config.Profile = v
	}
	if v, ok := l.params[consts.FieldAWSSharedCredentialsFile].(string); ok && v != "" {
		config.Filename = v
	}
	if v, ok := l.params[consts.FieldAWSSessionToken].(string); ok && v != "" {
		config.SessionToken = v
	}
	if v, ok := l.params[consts.FieldAWSSTSEndpoint].(string); ok && v != "" {
		config.STSEndpointResolver = &customSTSEndpointResolver{endpointURL: v}
	}
	if v, ok := l.params[consts.FieldAWSIAMEndpoint].(string); ok && v != "" {
		config.IAMEndpointResolver = &customIAMEndpointResolver{endpointURL: v}
	}

	return config, nil
}

// generateLoginData generates the necessary login data for Vault AWS authentication
// by creating a presigned STS GetCallerIdentity request.
func generateLoginData(ctx context.Context, awsConfig *aws.Config, headerValue string, logger hclog.Logger) (map[string]interface{}, error) {
	const iamServerIdHeader = "X-Vault-AWS-IAM-Server-ID"

	loginData := make(map[string]interface{})

	// Force credential retrieval to ensure any AssumeRole calls happen before presigning
	// This is critical when role assumption is configured
	tempCreds, err := awsConfig.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve AWS credentials: %w", err)
	}

	// Check if credentials are actually populated
	if tempCreds.AccessKeyID == "" {
		return nil, fmt.Errorf("retrieved AWS credentials are empty")
	}

	// Create a NEW config using the retrieved credentials
	// This ensures we're using the assumed role credentials if role assumption occurred
	configWithCreds := awsConfig.Copy()
	configWithCreds.Credentials = aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		return tempCreds, nil
	})

	// If a header value is provided, we need to add it to the signed request
	// We'll do this by adding middleware to the config
	if headerValue != "" {
		configWithCreds.APIOptions = append(configWithCreds.APIOptions, func(stack *middleware.Stack) error {
			return stack.Build.Add(middleware.BuildMiddlewareFunc(
				"AddVaultHeader",
				func(ctx context.Context, in middleware.BuildInput, next middleware.BuildHandler) (middleware.BuildOutput, middleware.Metadata, error) {
					req, ok := in.Request.(*smithyhttp.Request)
					if ok {
						req.Header.Add(iamServerIdHeader, headerValue)
					}
					return next.HandleBuild(ctx, in)
				},
			), middleware.After)
		})
	}

	// Create STS client with the config that has the assumed role credentials
	stsClient := sts.NewFromConfig(configWithCreds)

	// Create presigner with the same STS client (which has the assumed credentials)
	presignClient := sts.NewPresignClient(stsClient)

	// Presign the GetCallerIdentity request
	presignedReq, err := presignClient.PresignGetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to presign GetCallerIdentity request: %w", err)
	}

	// Convert the signed headers map to http.Header for proper marshaling
	headers := make(http.Header)
	for k, v := range presignedReq.SignedHeader {
		headers[k] = v
	}

	// Marshal headers to JSON
	headersJson, err := json.Marshal(headers)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request headers: %w", err)
	}

	// Populate login data with base64-encoded values
	// Note: GetCallerIdentity is a POST request with an empty body
	loginData[consts.FieldIAMHttpRequestMethod] = presignedReq.Method
	loginData[consts.FieldIAMRequestURL] = base64.StdEncoding.EncodeToString([]byte(presignedReq.URL))
	loginData[consts.FieldIAMRequestHeaders] = base64.StdEncoding.EncodeToString(headersJson)
	loginData[consts.FieldIAMRequestBody] = base64.StdEncoding.EncodeToString([]byte(""))

	return loginData, nil
}

// signAWSLogin is for use by the generic auth method
func signAWSLogin(parameters map[string]interface{}, logger hclog.Logger) error {
	ctx := context.Background()

	var accessKey string
	if v, ok := parameters[consts.FieldAWSAccessKeyID].(string); ok {
		accessKey = v
	}

	var secretKey string
	if v, ok := parameters[consts.FieldAWSSecretAccessKey].(string); ok {
		secretKey = v
	}

	var sessionToken string
	if v, ok := parameters[consts.FieldAWSSessionToken].(string); ok {
		sessionToken = v
	} else if v, ok := parameters["aws_security_token"].(string); ok {
		// this is actually wrong, this should be the session token,
		// leaving this here so that it does not break any pre-existing configurations.
		sessionToken = v
	}

	var region string
	if v, ok := parameters["sts_region"].(string); ok {
		region = v
	}

	awsConfig, err := awsutil.RetrieveCreds(ctx, accessKey, secretKey, sessionToken, logger,
		awsutil.WithRegion(region))
	if err != nil {
		return fmt.Errorf("failed to retrieve AWS credentials: %s", err)
	}

	var headerValue string
	if v, ok := parameters[consts.FieldHeaderValue].(string); ok {
		headerValue = v
	}

	loginData, err := generateLoginData(ctx, awsConfig, headerValue, logger)
	if err != nil {
		return fmt.Errorf("failed to generate AWS login data: %s", err)
	}

	headerFields := []string{
		consts.FieldIAMHttpRequestMethod,
		consts.FieldIAMRequestURL,
		consts.FieldIAMRequestBody,
		consts.FieldIAMRequestHeaders,
	}

	var errs error
	for _, k := range headerFields {
		v, ok := loginData[k]
		if !ok {
			errs = multierror.Append(errs, fmt.Errorf("login data missing required header %q", k))
		}
		parameters[k] = v
	}

	if errs != nil {
		return errs
	}

	return nil
}
