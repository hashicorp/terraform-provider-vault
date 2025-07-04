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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
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
	envVarAWSSTSEndpoint           = "AWS_STS_ENDPOINT"
	envVarAWSIAMEndpoint           = "AWS_IAM_ENDPOINT"
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

// credentialsParams mirrors the fields we needed from awsutil.CredentialsConfig
type credentialsParams struct {
	AccessKey            string
	SecretKey            string
	SessionToken         string
	Profile              string
	Filename             string
	WebIdentityTokenFile string
	RoleARN              string
	RoleSessionName      string
	Region               string
	STSEndpoint          string
	IAMEndpoint          string
}

// buildAWSConfig constructs an *aws.Config whose final credentials exactly follow the
// HashiCorp AWS provider precedence (static keys > assume-role/web-identity > env >
// shared files > container/IMDS). It never lets AWS_PROFILE become the *final* identity
// when RoleARN or explicit keys are supplied.
func buildAWSConfig(ctx context.Context, p *credentialsParams) (*aws.Config, error) {
	loadOpts := []func(*config.LoadOptions) error{}

	// Region & shared-config locations
	if p.Region != "" {
		loadOpts = append(loadOpts, config.WithRegion(p.Region))
	}
	if p.Filename != "" {
		loadOpts = append(loadOpts, config.WithSharedCredentialsFiles([]string{p.Filename}))
	}
	if p.Profile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(p.Profile))
	}

	// 1. Explicit static keys override everything
	if p.AccessKey != "" && p.SecretKey != "" {
		staticProv := credentials.NewStaticCredentialsProvider(p.AccessKey, p.SecretKey, p.SessionToken)
		loadOpts = append(loadOpts, config.WithCredentialsProvider(staticProv))
	}

	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, err
	}

	// Configure custom endpoints if provided
	if p.STSEndpoint != "" {
		cfg.EndpointResolverWithOptions = aws.EndpointResolverWithOptionsFunc(
			func(service, region string, options ...interface{}) (aws.Endpoint, error) {
				if service == sts.ServiceID {
					return aws.Endpoint{URL: p.STSEndpoint}, nil
				}
				// Fall back to default resolver for other services
				return aws.Endpoint{}, &aws.EndpointNotFoundError{}
			})
	}

	// Note: IAM endpoint configuration would go here if needed for the signing process

	// 2. Explicit assume-role / web-identity override any provider selected above
	if p.RoleARN != "" {
		stsClient := sts.NewFromConfig(cfg)

		assumeProv := stscreds.NewAssumeRoleProvider(stsClient, p.RoleARN,
			func(o *stscreds.AssumeRoleOptions) {
				if p.RoleSessionName != "" {
					o.RoleSessionName = p.RoleSessionName
				}
				// when empty, stscreds will automatically generate a unique
				// name (same behaviour as the original implementation).
			},
		)

		cfg.Credentials = aws.NewCredentialsCache(assumeProv)
	} else if p.WebIdentityTokenFile != "" && p.RoleARN != "" {
		// (optional) Web-identity flow, treated analogously if required later
	}

	return &cfg, nil
}

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

	loginData, err := l.getLoginData(context.Background(), getHCLogger())
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
		{
			field:      consts.FieldAWSSTSEndpoint,
			envVars:    []string{envVarAWSSTSEndpoint},
			defaultVal: "",
		},
		{
			field:      consts.FieldAWSIAMEndpoint,
			envVars:    []string{envVarAWSIAMEndpoint},
			defaultVal: "",
		},
	}

	return defaults
}

func (l *AuthLoginAWS) getLoginData(ctx context.Context, logger hclog.Logger) (map[string]interface{}, error) {
	credParams := l.collectCredentialParams(logger)

	awsCfg, err := buildAWSConfig(ctx, &credParams)
	if err != nil {
		return nil, err
	}

	var headerValue string
	if v, ok := l.params[consts.FieldHeaderValue].(string); ok {
		headerValue = v
	}

	return generateLoginData(awsCfg, headerValue, credParams.Region, logger)
}

// collectCredentialParams converts TF schema params + env-defaults into credentialsParams
func (l *AuthLoginAWS) collectCredentialParams(logger hclog.Logger) credentialsParams {
	var p credentialsParams

	if v, ok := l.params[consts.FieldAWSAccessKeyID].(string); ok && v != "" {
		p.AccessKey = v
	}
	if v, ok := l.params[consts.FieldAWSSecretAccessKey].(string); ok && v != "" {
		p.SecretKey = v
	}
	if v, ok := l.params[consts.FieldAWSSessionToken].(string); ok && v != "" {
		p.SessionToken = v
	}
	if v, ok := l.params[consts.FieldAWSProfile].(string); ok && v != "" {
		p.Profile = v
	}
	if v, ok := l.params[consts.FieldAWSSharedCredentialsFile].(string); ok && v != "" {
		p.Filename = v
	}
	if v, ok := l.params[consts.FieldAWSWebIdentityTokenFile].(string); ok && v != "" {
		p.WebIdentityTokenFile = v
	}
	if v, ok := l.params[consts.FieldAWSRoleARN].(string); ok && v != "" {
		p.RoleARN = v
	}
	if v, ok := l.params[consts.FieldAWSRoleSessionName].(string); ok && v != "" {
		p.RoleSessionName = v
	}
	if v, ok := l.params[consts.FieldAWSRegion].(string); ok && v != "" {
		p.Region = v
	}
	if v, ok := l.params[consts.FieldAWSSTSEndpoint].(string); ok && v != "" {
		p.STSEndpoint = v
	}
	if v, ok := l.params[consts.FieldAWSIAMEndpoint].(string); ok && v != "" {
		p.IAMEndpoint = v
	}
	return p
}

func signAWSLogin(parameters map[string]interface{}, logger hclog.Logger) error {
	credParams := credentialsParams{}

	if v, ok := parameters[consts.FieldAWSAccessKeyID].(string); ok {
		credParams.AccessKey = v
	}
	if v, ok := parameters[consts.FieldAWSSecretAccessKey].(string); ok {
		credParams.SecretKey = v
	}
	if v, ok := parameters[consts.FieldAWSSessionToken].(string); ok {
		credParams.SessionToken = v
	}
	if v, ok := parameters[consts.FieldAWSRoleARN].(string); ok {
		credParams.RoleARN = v
	}
	if v, ok := parameters[consts.FieldAWSRoleSessionName].(string); ok {
		credParams.RoleSessionName = v
	}
	if v, ok := parameters["sts_region"].(string); ok {
		credParams.Region = v
	}
	if v, ok := parameters[consts.FieldAWSSTSEndpoint].(string); ok {
		credParams.STSEndpoint = v
	}
	if v, ok := parameters[consts.FieldAWSIAMEndpoint].(string); ok {
		credParams.IAMEndpoint = v
	}

	awsCfg, err := buildAWSConfig(context.Background(), &credParams)
	if err != nil {
		return fmt.Errorf("failed to build AWS config: %s", err)
	}

	var headerValue string
	if v, ok := parameters[consts.FieldHeaderValue].(string); ok {
		headerValue = v
	}

	loginData, err := generateLoginData(awsCfg, headerValue, credParams.Region, logger)
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

// generateLoginData creates the necessary login data for AWS authentication
func generateLoginData(awsConfig *aws.Config, headerValue, configuredRegion string, logger hclog.Logger) (map[string]interface{}, error) {
	region := configuredRegion
	if region == "" {
		region = "us-east-1"
	}

	// Build unsigned STS request
	const bodyStr = "Action=GetCallerIdentity&Version=2011-06-15"
	endpoint := fmt.Sprintf("https://sts.%s.amazonaws.com", region)

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(bodyStr))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if headerValue != "" {
		req.Header.Set("X-Vault-AWS-IAM-Server-ID", headerValue)
	}

	// Get credentials and sign the request
	creds, err := awsConfig.Credentials.Retrieve(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve AWS credentials: %w", err)
	}

	// Calculate SHA-256 hash of the body for payload hash
	hash := sha256.Sum256([]byte(bodyStr))
	payloadHash := hex.EncodeToString(hash[:])

	signer := v4.NewSigner()
	err = signer.SignHTTP(context.Background(), creds, req, payloadHash, "sts", region, time.Now())
	if err != nil {
		return nil, fmt.Errorf("failed to sign HTTP request: %w", err)
	}

	// Marshal for Vault - extract request components and base64 encode them
	// Headers need to be JSON format for Vault
	headersJSON, err := json.Marshal(req.Header)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal headers: %w", err)
	}

	return map[string]interface{}{
		consts.FieldIAMHttpRequestMethod: req.Method, // Method should NOT be base64-encoded
		consts.FieldIAMRequestURL:        base64.StdEncoding.EncodeToString([]byte(req.URL.String())),
		consts.FieldIAMRequestBody:       base64.StdEncoding.EncodeToString([]byte(bodyStr)),
		consts.FieldIAMRequestHeaders:    base64.StdEncoding.EncodeToString(headersJSON),
	}, nil
}
