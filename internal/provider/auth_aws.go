// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
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
				DefaultFunc: schema.EnvDefaultFunc("AWS_ACCESS_KEY_ID", nil),
			},
			consts.FieldAWSSecretAccessKey: {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  `The AWS secret access key.`,
				DefaultFunc:  schema.EnvDefaultFunc("AWS_SECRET_ACCESS_KEY", nil),
				RequiredWith: []string{fmt.Sprintf("%s.0.%s", authField, consts.FieldAWSAccessKeyID)},
			},
			consts.FieldAWSSessionToken: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: `The AWS session token.`,
				DefaultFunc: schema.EnvDefaultFunc("AWS_SESSION_TOKEN", nil),
			},
			consts.FieldAWSProfile: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: `The name of the AWS profile.`,
				DefaultFunc: schema.EnvDefaultFunc("AWS_PROFILE", nil),
			},
			consts.FieldAWSSharedCredentialsFile: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: `Path to the AWS shared credentials file.`,
				DefaultFunc: schema.EnvDefaultFunc("AWS_SHARED_CREDENTIALS_FILE", nil),
			},
			consts.FieldAWSWebIdentityTokenFile: {
				Type:     schema.TypeString,
				Optional: true,
				Description: `Path to the file containing an OAuth 2.0 access token or OpenID ` +
					`Connect ID token.`,
				DefaultFunc: schema.EnvDefaultFunc("AWS_WEB_IDENTITY_TOKEN_FILE", nil),
			},
			// STS assume role fields
			consts.FieldAWSRoleARN: {
				Type:     schema.TypeString,
				Optional: true,
				Description: `The ARN of the AWS Role to assume.` +
					`Used during STS AssumeRole`,
				DefaultFunc: schema.EnvDefaultFunc("AWS_ROLE_ARN", nil),
			},
			consts.FieldAWSRoleSessionName: {
				Type:     schema.TypeString,
				Optional: true,
				Description: `Specifies the name to attach to the AWS role session. ` +
					`Used during STS AssumeRole`,
				DefaultFunc: schema.EnvDefaultFunc("AWS_ROLE_SESSION_NAME", nil),
			},
			consts.FieldAWSRegion: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: `The AWS region.`,
				DefaultFunc: schema.MultiEnvDefaultFunc(
					[]string{
						"AWS_REGION",
						"AWS_DEFAULT_REGION",
					},
					nil,
				),
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
	if err := l.AuthLoginCommon.Init(d, authField,
		func(data *schema.ResourceData) error {
			return l.checkRequiredFields(d, consts.FieldRole)
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

	loginData, err := l.getLoginData(getHCLogger())
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS credentials required for Vault login, err=%w", err)
	}
	for k, v := range loginData {
		params[k] = v
	}

	return l.login(client, l.LoginPath(), params)
}

func (l *AuthLoginAWS) getLoginData(logger hclog.Logger) (map[string]interface{}, error) {
	config, err := l.getCredentialsConfig(logger)
	if err != nil {
		return nil, err
	}

	creds, err := config.GenerateCredentialChain()
	if err != nil {
		return nil, err
	}

	var headerValue string
	if v, ok := l.params[consts.FieldHeaderValue].(string); ok {
		headerValue = v
	}

	return awsutil.GenerateLoginData(creds, headerValue, config.Region, logger)
}

func (l *AuthLoginAWS) getCredentialsConfig(logger hclog.Logger) (*awsutil.CredentialsConfig, error) {
	// we do not leverage awsutil.Options here since awsutil.NewCredentialsConfig
	// does not currently support all that we do.
	config, err := awsutil.NewCredentialsConfig()
	if err != nil {
		return nil, err
	}
	if v, ok := l.params[consts.FieldAWSAccessKeyID].(string); ok && v != "" {
		config.AccessKey = v
	}
	if v, ok := l.params[consts.FieldAWSSecretAccessKey].(string); ok && v != "" {
		config.SecretKey = v
	}
	if v, ok := l.params[consts.FieldAWSProfile].(string); ok && v != "" {
		config.Profile = v
	}
	if v, ok := l.params[consts.FieldAWSSharedCredentialsFile].(string); ok && v != "" {
		config.Filename = v
	}
	if v, ok := l.params[consts.FieldAWSWebIdentityTokenFile].(string); ok && v != "" {
		config.WebIdentityTokenFile = v
	}
	if v, ok := l.params[consts.FieldAWSRoleARN].(string); ok && v != "" {
		config.RoleARN = v
	}
	if v, ok := l.params[consts.FieldAWSRoleSessionName].(string); ok && v != "" {
		config.RoleSessionName = v
	}
	if v, ok := l.params[consts.FieldAWSRegion].(string); ok && v != "" {
		config.Region = v
	}
	if v, ok := l.params[consts.FieldAWSSessionToken].(string); ok && v != "" {
		config.SessionToken = v
	}
	if v, ok := l.params[consts.FieldAWSSTSEndpoint].(string); ok && v != "" {
		config.STSEndpoint = v
	}
	if v, ok := l.params[consts.FieldAWSIAMEndpoint].(string); ok && v != "" {
		config.IAMEndpoint = v
	}

	return config, nil
}

// signAWSLogin is for use by the generic auth method
func signAWSLogin(parameters map[string]interface{}, logger hclog.Logger) error {
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

	creds, err := awsutil.RetrieveCreds(accessKey, secretKey, sessionToken, logger)
	if err != nil {
		return fmt.Errorf("failed to retrieve AWS credentials: %s", err)
	}

	var headerValue string
	if v, ok := parameters[consts.FieldHeaderValue].(string); ok {
		headerValue = v
	}

	var stsRegion string
	if v, ok := parameters["sts_region"].(string); ok {
		stsRegion = v
	}

	loginData, err := awsutil.GenerateLoginData(creds, headerValue, stsRegion, logger)
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
