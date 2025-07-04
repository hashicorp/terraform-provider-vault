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
	"log"
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
)

const (
	DefaultRegion   = "us-east-1"
	DefaultEndpoint = "https://sts.amazonaws.com"
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
			// aws_iam_endpoint should be deprecated, not used in aws auth
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
	}

	return defaults
}

func (l *AuthLoginAWS) getLoginData(ctx context.Context, logger hclog.Logger) (map[string]interface{}, error) {
	credParams, err := l.collectCredentialParams()
	if err != nil {
		return nil, err
	}

	awsCfg, err := buildAWSConfig(ctx, &credParams)
	if err != nil {
		return nil, err
	}

	var headerValue string
	if v, ok := l.params[consts.FieldHeaderValue].(string); ok {
		headerValue = v
	}

	return generateLoginData(awsCfg, headerValue, credParams.Region, credParams.STSEndpoint)
}

// collectCredentialParams converts TF schema params + env-defaults into credentialsParams
func (l *AuthLoginAWS) collectCredentialParams() (credentialsParams, error) {
	var credParams credentialsParams

	if v, ok := l.params[consts.FieldAWSAccessKeyID].(string); ok && v != "" {
		credParams.AccessKey = v
	}
	if v, ok := l.params[consts.FieldAWSSecretAccessKey].(string); ok && v != "" {
		credParams.SecretKey = v
	}
	if v, ok := l.params[consts.FieldAWSProfile].(string); ok && v != "" {
		credParams.Profile = v
	}
	if v, ok := l.params[consts.FieldAWSSharedCredentialsFile].(string); ok && v != "" {
		credParams.Filename = v
	}
	if v, ok := l.params[consts.FieldAWSWebIdentityTokenFile].(string); ok && v != "" {
		credParams.WebIdentityTokenFile = v
	}
	if v, ok := l.params[consts.FieldAWSRoleARN].(string); ok && v != "" {
		credParams.RoleARN = v
	}
	if v, ok := l.params[consts.FieldAWSRoleSessionName].(string); ok && v != "" {
		credParams.RoleSessionName = v
	}
	if v, ok := l.params[consts.FieldAWSRegion].(string); ok && v != "" {
		credParams.Region = v
	}
	if v, ok := l.params[consts.FieldAWSSessionToken].(string); ok && v != "" {
		credParams.SessionToken = v
	}
	if v, ok := l.params[consts.FieldAWSSTSEndpoint].(string); ok && v != "" {
		credParams.STSEndpoint = v
	}
	if v, ok := l.params[consts.FieldAWSIAMEndpoint].(string); ok && v != "" {
		credParams.IAMEndpoint = v
	}

	// TODO Remove
	if err := validateCredentialParams(&credParams); err != nil {
		return credParams, err
	}

	return credParams, nil
}

// TODO Use native schema validators and remove this function
func validateCredentialParams(p *credentialsParams) error {
	if p.AccessKey != "" && p.SecretKey == "" {
		return fmt.Errorf("static AWS client credentials haven't been properly configured (access key provided but secret key missing)")
	}
	if p.AccessKey == "" && p.SecretKey != "" {
		return fmt.Errorf("static AWS client credentials haven't been properly configured (secret key provided but access key missing)")
	}

	if p.RoleARN == "" {
		if p.RoleSessionName != "" {
			return fmt.Errorf("role session name specified without role ARN")
		}
		if p.WebIdentityTokenFile != "" {
			return fmt.Errorf("web identity token file specified without role ARN")
		}
	}

	return nil
}

// signAWSLogin is for use by the generic auth method
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
	} else if v, ok := parameters["aws_security_token"].(string); ok {
		// this is actually wrong, this should be the session token,
		// leaving this here so that it does not break any pre-existing configurations.
		credParams.SessionToken = v
	}
	// generic auth_login uses "sts_region" field name, not "aws_region"
	if v, ok := parameters["sts_region"].(string); ok {
		credParams.Region = v
	}

	if err := validateCredentialParams(&credParams); err != nil {
		return err
	}

	awsCfg, err := buildAWSConfig(context.Background(), &credParams)
	if err != nil {
		return fmt.Errorf("failed to build AWS config: %s", err)
	}

	var headerValue string
	if v, ok := parameters[consts.FieldHeaderValue].(string); ok {
		headerValue = v
	}

	loginData, err := generateLoginData(awsCfg, headerValue, credParams.Region, credParams.STSEndpoint)
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

// credentialsParams mirrors the param fields from awsutil.CredentialsConfig
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

type buildAWSConfigOption func(*buildAWSConfigOpts)

type buildAWSConfigOpts struct {
	stsClient STSAssumeRoleAPI
}

func WithSTSClient(c STSAssumeRoleAPI) buildAWSConfigOption {
	return func(o *buildAWSConfigOpts) {
		o.stsClient = c
	}
}

// buildAWSConfig constructs an *aws.Config whose final credentials exactly follow the aws tf provider identity precedence
// static keys > (web-identity > assume-role) > env > shared files > IMDS
func buildAWSConfig(ctx context.Context, p *credentialsParams, opts ...buildAWSConfigOption) (*aws.Config, error) {
	var o buildAWSConfigOpts
	for _, apply := range opts {
		apply(&o)
	}

	loadOpts := make([]func(*config.LoadOptions) error, 0)

	if p.Region != "" {
		loadOpts = append(loadOpts, config.WithRegion(p.Region))
	}
	// shared-config locations
	if p.Filename != "" {
		loadOpts = append(loadOpts, config.WithSharedCredentialsFiles([]string{p.Filename}))
	}
	if p.Profile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(p.Profile))
	}

	if p.AccessKey != "" && p.SecretKey != "" {
		staticProv := credentials.NewStaticCredentialsProvider(p.AccessKey, p.SecretKey, p.SessionToken)
		loadOpts = append(loadOpts, config.WithCredentialsProvider(staticProv))
	}

	// if previous not present, fallback to IMDS
	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, err
	}

	// explicit assume-role / web-identity override any provider selected above
	if p.RoleARN != "" {
		// create client with custom endpoint support
		roleSTSClient := o.stsClient
		if roleSTSClient == nil {
			roleSTSClient = createSTSClient(&cfg, p.STSEndpoint)
		}

		if p.WebIdentityTokenFile != "" {
			// use web identity role provider - this takes precedence over regular assume role, just as in awsutil
			webIdentityProv := stscreds.NewWebIdentityRoleProvider(roleSTSClient, p.RoleARN, stscreds.IdentityTokenFile(p.WebIdentityTokenFile),
				func(o *stscreds.WebIdentityRoleOptions) {
					if p.RoleSessionName != "" {
						o.RoleSessionName = p.RoleSessionName
					}
				},
			)

			cfg.Credentials = aws.NewCredentialsCache(webIdentityProv)
		} else {
			// use regular assume role provider
			assumeProv := stscreds.NewAssumeRoleProvider(roleSTSClient, p.RoleARN,
				func(o *stscreds.AssumeRoleOptions) {
					// bw compat: if empty, stscreds generates a unique name
					if p.RoleSessionName != "" {
						o.RoleSessionName = p.RoleSessionName
					}
				},
			)

			cfg.Credentials = aws.NewCredentialsCache(assumeProv)
		}
	}

	return &cfg, nil
}

// createSTSClient creates an client for custom endpoint
func createSTSClient(cfg *aws.Config, stsEndpoint string) *sts.Client {
	if stsEndpoint != "" {
		return sts.NewFromConfig(*cfg, func(o *sts.Options) {
			o.BaseEndpoint = aws.String(stsEndpoint)
		})
	}
	return sts.NewFromConfig(*cfg)
}

// generateLoginData constructs the sts request and signs it
// based on https://github.com/hashicorp/go-secure-stdlib/blob/awsutil/v0.2.3/awsutil/generate_credentials.go#L372
func generateLoginData(awsConfig *aws.Config, headerValue, configRegion, stsEndpoint string) (map[string]interface{}, error) {
	// exactly replicates the awsutil logic for STS signingEndpoint resolution
	// see https://github.com/hashicorp/go-secure-stdlib/blob/72fcd87cb5f9ca0a9c5a7f229c43ce3afb776bca/awsutil/generate_credentials.go#L423
	// two cases:
	// 	- if region is not provided with parameters or shared credentials, use default region and global endpoint
	//  - if region is provided, construct regional endpoint, but requires use_sts_region_from_client=true
	// see https://registry.terraform.io/providers/hashicorp/vault/latest/docs/resources/aws_auth_backend_client#use_sts_region_from_client
	signingRegion := awsConfig.Region
	if signingRegion == "" {
		signingRegion = configRegion
	}
	if signingRegion == "" {
		signingRegion = DefaultRegion
	}

	var signingEndpoint string
	if stsEndpoint != "" {
		signingEndpoint = stsEndpoint
	} else if signingRegion == DefaultRegion {
		signingEndpoint = DefaultEndpoint
	} else {
		signingEndpoint = fmt.Sprintf("https://sts.%s.amazonaws.com", signingRegion)
	}

	log.Printf("[DEBUG] generating AWS login data: configRegion=%s, awsRegion=%s, signingRegion=%s, has_header_value=%t, sts_endpoint=%s, signingEndpoint=%s", configRegion, awsConfig.Region, signingRegion, headerValue != "", stsEndpoint, signingEndpoint)

	// aws sdk v1 exposes a request object through helpers, e.g. svc.GetCallerIdentityRequest
	// v2 does not, so the request is constructed manually
	const bodyStr = "Action=GetCallerIdentity&Version=2011-06-15"
	req, err := http.NewRequest(http.MethodPost, signingEndpoint, strings.NewReader(bodyStr))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	if headerValue != "" {
		req.Header.Set("X-Vault-AWS-IAM-Server-ID", headerValue)
	}
	creds, err := awsConfig.Credentials.Retrieve(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve AWS credentials: %w", err)
	}
	hash := sha256.Sum256([]byte(bodyStr))
	payloadHash := hex.EncodeToString(hash[:])
	// sign the request
	signer := v4.NewSigner()
	err = signer.SignHTTP(context.Background(), creds, req, payloadHash, "sts", signingRegion, time.Now())
	if err != nil {
		return nil, fmt.Errorf("failed to sign HTTP request: %w", err)
	}

	headersJSON, err := json.Marshal(req.Header)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal headers: %w", err)
	}

	// b64 is not a requirement, but since previous versions used it, we have to stick to it for bw compat
	return map[string]interface{}{
		consts.FieldIAMHttpRequestMethod: req.Method,
		consts.FieldIAMRequestURL:        base64.StdEncoding.EncodeToString([]byte(req.URL.String())),
		consts.FieldIAMRequestBody:       base64.StdEncoding.EncodeToString([]byte(bodyStr)),
		consts.FieldIAMRequestHeaders:    base64.StdEncoding.EncodeToString(headersJSON),
	}, nil
}

// STSAssumeRoleAPI interface for mocking STS assume role operations in tests
type STSAssumeRoleAPI interface {
	AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
	AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}
