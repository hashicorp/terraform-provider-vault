// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithyendpoints "github.com/aws/smithy-go/endpoints"
	"github.com/hashicorp/go-cty/cty"
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
	stsGetCallerIdentityBody       = "Action=GetCallerIdentity&Version=2011-06-15"
	stsContentType                 = "application/x-www-form-urlencoded; charset=utf-8"
	stsSigningName                 = "sts"
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
	// These fields preserve whether aws_role_arn came from explicit Terraform
	// config instead of env/default expansion in AuthLoginCommon.params.
	// The login flow uses that provenance to decide when a second manual
	// AssumeRole is intended and when it should be skipped.
	awsRoleARNExplicit   bool
	awsRoleARNFromConfig string
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
	if roleARN, ok := l.getConfigStringField(d, consts.FieldAWSRoleARN); ok {
		l.awsRoleARNExplicit = true
		l.awsRoleARNFromConfig = roleARN
	}

	return l, nil
}

// getConfigStringField reads the raw provider configuration so we can tell
// whether a value was explicitly set in Terraform rather than inherited from
// environment-based defaults in l.params.
//
// This is needed because AuthLoginCommon expands env-backed defaults into
// l.params before auth_login_aws decides whether to perform an extra manual
// STS AssumeRole call. For web identity flows such as IRSA, treating an
// env-derived AWS_ROLE_ARN the same as an explicitly configured aws_role_arn
// can trigger an unintended second AssumeRole after the AWS SDK has already
// resolved credentials through web identity.
func (l *AuthLoginAWS) getConfigStringField(d *schema.ResourceData, field string) (string, bool) {
	v, diags := d.GetRawConfigAt(cty.Path{
		cty.GetAttrStep{Name: l.authField},
		cty.IndexStep{Key: cty.NumberIntVal(0)},
		cty.GetAttrStep{Name: field},
	})
	if diags.HasError() || v.IsNull() || !v.IsKnown() {
		return "", false
	}

	if v.Type() != cty.String {
		return "", false
	}

	return v.AsString(), true
}

// configuredRoleARN returns only an explicitly configured, non-empty
// aws_role_arn. This lets the login flow distinguish Terraform config from
// env-derived defaults when deciding whether to do an extra STS AssumeRole.
func (l *AuthLoginAWS) configuredRoleARN() (string, bool) {
	// If the field was not explicitly configured, any value in l.params came from
	// env/default processing and should not be treated as a Terraform-configured ARN.
	if !l.awsRoleARNExplicit || l.awsRoleARNFromConfig == "" {
		return "", false
	}

	// A non-empty explicit value is safe to treat as a user-requested role ARN.
	return l.awsRoleARNFromConfig, true
}

// manualAssumeRoleARN decides whether the provider should perform an explicit
// STS AssumeRole after the AWS SDK credential chain has been resolved.
//
// Any web identity flow skips the extra assume to avoid the IRSA/self-assume
// regression where the SDK already resolved credentials via web identity.
func (l *AuthLoginAWS) manualAssumeRoleARN() (string, bool) {
	webIdentityTokenFile, _ := l.params[consts.FieldAWSWebIdentityTokenFile].(string)
	// Web identity flows already rely on the SDK credential chain to assume the
	// target role, so a second manual AssumeRole would create the IRSA regression.
	if webIdentityTokenFile != "" {
		return "", false
	}

	// An explicit non-empty Terraform value should still trigger manual
	// AssumeRole for non-web-identity credential sources.
	if roleARN, ok := l.configuredRoleARN(); ok {
		return roleARN, true
	}

	// If Terraform explicitly configured aws_role_arn but left it empty,
	// do not fall back to an env-derived ARN.
	if l.awsRoleARNExplicit {
		return "", false
	}

	roleARN, _ := l.params[consts.FieldAWSRoleARN].(string)
	// With no explicit config, only use the effective env/default-derived role ARN
	// when it is actually present.
	if roleARN == "" {
		return "", false
	}

	// Non-web-identity ambient credential sources can still use an env-derived
	// role ARN for the manual AssumeRole path.
	return roleARN, true
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
	if manualAssumeRoleARN, ok := l.manualAssumeRoleARN(); ok {
		// The credential chain can already resolve web identity and other ambient
		// credentials. We only do a second, explicit AssumeRole when the helper
		// above determines it is safe and intended.
		roleARN = manualAssumeRoleARN

		// Create STS client with base credentials and custom endpoint if configured
		var stsOpts []func(*sts.Options)
		if v, ok := l.params[consts.FieldAWSSTSEndpoint].(string); ok && v != "" {
			stsOpts = append(stsOpts, sts.WithEndpointResolverV2(&customSTSEndpointResolver{endpointURL: v}))
		}
		stsClient := sts.NewFromConfig(*awsConfig, stsOpts...)

		// Get role session name
		roleSessionName := "vault-provider-session"
		// Reuse the configured session name when present so the explicit manual
		// AssumeRole path behaves consistently with the rest of the provider config.
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

	var stsEndpoint string
	if v, ok := l.params[consts.FieldAWSSTSEndpoint].(string); ok {
		stsEndpoint = v
	}

	return generateLoginData(ctx, awsConfig, headerValue, stsEndpoint)
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

type stsSigningEndpoint struct {
	requestURL    string
	signingName   string
	signingRegion string
}

// generateLoginData generates the necessary login data for Vault AWS authentication
// by creating a SigV4-signed STS GetCallerIdentity request.
func generateLoginData(ctx context.Context, awsConfig *aws.Config, headerValue string, stsEndpoint string) (map[string]interface{}, error) {
	const iamServerIdHeader = "X-Vault-AWS-IAM-Server-ID"

	loginData := make(map[string]interface{})

	if awsConfig == nil || awsConfig.Credentials == nil {
		return nil, fmt.Errorf("AWS credentials are not configured")
	}

	// Validate credentials are available before building the signed request.
	// This catches configuration errors earlier with a clearer error message
	credentials, err := awsConfig.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve AWS credentials: %w", err)
	}

	region := awsConfig.Region
	if region == "" {
		region = awsutil.DefaultRegion
	}

	endpoint, err := resolveSTSSigningEndpoint(region, stsEndpoint)
	if err != nil {
		return nil, err
	}

	req, body, err := buildSignedGetCallerIdentityRequest(ctx, credentials, endpoint, region, headerValue)
	if err != nil {
		return nil, err
	}

	headers := req.Header.Clone()
	if headers.Get("Host") == "" {
		headers.Set("Host", req.URL.Host)
	}

	// Marshal headers to JSON
	headersJson, err := json.Marshal(headers)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request headers: %w", err)
	}

	// Populate login data with base64-encoded values
	loginData[consts.FieldIAMHttpRequestMethod] = req.Method
	loginData[consts.FieldIAMRequestURL] = base64.StdEncoding.EncodeToString([]byte(req.URL.String()))
	loginData[consts.FieldIAMRequestHeaders] = base64.StdEncoding.EncodeToString(headersJson)
	loginData[consts.FieldIAMRequestBody] = base64.StdEncoding.EncodeToString([]byte(body))

	return loginData, nil
}

func resolveSTSSigningEndpoint(region string, endpointURL string) (stsSigningEndpoint, error) {
	if endpointURL != "" {
		uri, err := url.Parse(endpointURL)
		if err != nil {
			return stsSigningEndpoint{}, fmt.Errorf("failed to parse custom STS endpoint URL: %w", err)
		}
		if uri.Scheme == "" || uri.Host == "" {
			return stsSigningEndpoint{}, fmt.Errorf("invalid custom STS endpoint URL %q", endpointURL)
		}

		return stsSigningEndpoint{
			requestURL:    uri.String(),
			signingName:   stsSigningName,
			signingRegion: region,
		}, nil
	}

	return stsSigningEndpoint{
		requestURL:    fmt.Sprintf("https://sts.%s.amazonaws.com", region),
		signingName:   stsSigningName,
		signingRegion: region,
	}, nil
}

func buildSignedGetCallerIdentityRequest(ctx context.Context, credentials aws.Credentials, endpoint stsSigningEndpoint, region string, headerValue string) (*http.Request, string, error) {
	body := stsGetCallerIdentityBody
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.requestURL, strings.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("failed to build GetCallerIdentity request: %w", err)
	}

	req.Header.Set("Content-Type", stsContentType)
	if headerValue != "" {
		req.Header.Set("X-Vault-AWS-IAM-Server-ID", headerValue)
	}

	payloadHash := sha256.Sum256([]byte(body))
	signingRegion := endpoint.signingRegion
	if signingRegion == "" {
		signingRegion = region
	}
	if signingRegion == "" {
		signingRegion = awsutil.DefaultRegion
	}

	signingName := endpoint.signingName
	if signingName == "" {
		signingName = stsSigningName
	}

	signer := v4.NewSigner()

	if err := signer.SignHTTP(ctx, credentials, req, hex.EncodeToString(payloadHash[:]), signingName, signingRegion, time.Now().UTC()); err != nil {
		return nil, "", fmt.Errorf("failed to sign GetCallerIdentity request: %w", err)
	}

	return req, body, nil
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

	// Resolve region from environment/IMDS before passing to NewCredentialsConfig.
	// This ensures EC2 instances use their actual region instead of
	// defaulting to us-east-1, which would cause cross-region API calls.
	if region == "" {
		var err error
		region, err = awsutil.GetRegion(ctx, region)
		if err != nil {
			logger.Warn(fmt.Sprintf("defaulting region to %q due to %s", awsutil.DefaultRegion, err.Error()))
			region = awsutil.DefaultRegion
		}
	}

	// Build credentials config using awsutil.CredentialsConfig
	var opts []awsutil.Option

	if accessKey != "" {
		opts = append(opts, awsutil.WithAccessKey(accessKey))
	}
	if secretKey != "" {
		opts = append(opts, awsutil.WithSecretKey(secretKey))
	}
	if region != "" {
		opts = append(opts, awsutil.WithRegion(region))
	}

	opts = append(opts, awsutil.WithLogger(logger))

	credConfig, err := awsutil.NewCredentialsConfig(opts...)
	if err != nil {
		return fmt.Errorf("failed to create AWS credentials config: %s", err)
	}

	// Set session token directly on the config since it's not available as an option
	if sessionToken != "" {
		credConfig.SessionToken = sessionToken
	}

	// Generate the credential chain - this properly handles region and all credential sources
	awsConfig, err := credConfig.GenerateCredentialChain(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate AWS credential chain: %s", err)
	}

	var headerValue string
	if v, ok := parameters[consts.FieldHeaderValue].(string); ok {
		headerValue = v
	}

	var stsEndpoint string
	if v, ok := parameters[consts.FieldAWSSTSEndpoint].(string); ok {
		stsEndpoint = v
	}

	loginData, err := generateLoginData(ctx, awsConfig, headerValue, stsEndpoint)
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
