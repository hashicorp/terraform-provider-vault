package provider

import (
	"fmt"
	"net/http"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/logging"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

// GetAWSLoginSchema for the AWS authentication engine.
func GetAWSLoginSchema(authField string) *schema.Schema {
	return getLoginSchema(
		authField,
		"Login to vault using the AWS method",
		GetAWSLoginSchemaResource,
	)
}

// GetAWSLoginSchemaResource for the AWS authentication engine.
func GetAWSLoginSchemaResource(_ string) *schema.Resource {
	return mustAddLoginSchema(&schema.Resource{
		Schema: map[string]*schema.Schema{
			consts.FieldRole: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: `The IAM role to use when logging into Vault.`,
			},
			consts.FieldIdentity: {
				Type:        schema.TypeString,
				Description: `The base64 encoded EC2 instance identity document.`,
				Optional:    true,
			},
			consts.FieldSignature: {
				Type:        schema.TypeString,
				Description: `The base64 encoded SHA256 RSA signature of the instance identity document.`,
				Optional:    true,
			},
			consts.FieldPKCS7: {
				Type:        schema.TypeString,
				Description: `PKCS#7 signature of the identity document.`,
				Optional:    true,
			},
			consts.FieldNonce: {
				Type:        schema.TypeString,
				Description: `The nonce to be used for subsequent login requests.`,
				Optional:    true,
			},
			consts.FieldIAMHttpRequestMethod: {
				Type:        schema.TypeString,
				Description: `The HTTP method used in the signed request.`,
				Optional:    true,
				Default:     http.MethodPost,
			},
			consts.FieldIAMHttpRequestURL: {
				Type:        schema.TypeString,
				Description: `The base64 encoded HTTP URL used in the signed request.`,
				Optional:    true,
			},
			consts.FieldIAMHttpRequestBody: {
				Type:        schema.TypeString,
				Description: `The base64 encoded body of the signed request.`,
				Optional:    true,
			},
			consts.FieldIAMHttpRequestHeaders: {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: `Mapping of extra IAM specific HTTP request login headers.`,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}, consts.MountTypeAWS)
}

// AuthLoginAWS for handling the Vault AWS authentication engine.
// Requires configuration provided by SchemaLoginAWS.
type AuthLoginAWS struct {
	AuthLoginCommon
}

// LoginPath for the AWS authentication engine.
func (l *AuthLoginAWS) LoginPath() string {
	// TODO: add params validation
	return fmt.Sprintf("auth/%s/login", l.MountPath())
}

// Method name for the AWS authentication engine.
func (l *AuthLoginAWS) Method() string {
	return consts.AuthMethodAWS
}

// Login using the AWS authentication engine.
func (l *AuthLoginAWS) Login(client *api.Client) (*api.Secret, error) {
	params := l.copyParams(
		consts.FieldNamespace,
		consts.FieldMount,
		consts.FieldPasswordFile,
	)

	logger := hclog.Default()
	if logging.IsDebugOrHigher() {
		logger.SetLevel(hclog.Debug)
	} else {
		logger.SetLevel(hclog.Error)
	}
	if err := signAWSLogin(l.params, logger); err != nil {
		return nil, fmt.Errorf("error signing AWS login request: %s", err)
	}

	return l.login(client, l.LoginPath(), params)
}

func signAWSLogin(parameters map[string]interface{}, logger hclog.Logger) error {
	var accessKey, secretKey, securityToken string
	if val, ok := parameters["aws_access_key_id"].(string); ok {
		accessKey = val
	}

	if val, ok := parameters["aws_secret_access_key"].(string); ok {
		secretKey = val
	}

	if val, ok := parameters["aws_security_token"].(string); ok {
		securityToken = val
	}

	creds, err := awsutil.RetrieveCreds(accessKey, secretKey, securityToken, logger)
	if err != nil {
		return fmt.Errorf("failed to retrieve AWS credentials: %s", err)
	}

	var headerValue, stsRegion string
	if val, ok := parameters["header_value"].(string); ok {
		headerValue = val
	}

	if val, ok := parameters["sts_region"].(string); ok {
		stsRegion = val
	}

	loginData, err := awsutil.GenerateLoginData(creds, headerValue, stsRegion, logger)
	if err != nil {
		return fmt.Errorf("failed to generate AWS login data: %s", err)
	}

	parameters["iam_http_request_method"] = loginData["iam_http_request_method"]
	parameters["iam_request_url"] = loginData["iam_request_url"]
	parameters["iam_request_headers"] = loginData["iam_request_headers"]
	parameters["iam_request_body"] = loginData["iam_request_body"]

	return nil
}
