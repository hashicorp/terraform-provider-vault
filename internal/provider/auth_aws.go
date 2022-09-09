package provider

import (
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/logging"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func GetAWSLoginSchema(authField string) *schema.Schema {
	return getLoginSchema(
		authField,
		"Login to vault using the AWS method",
		GetAWSLoginSchemaResource,
	)
}

func GetAWSLoginSchemaResource(_ string) *schema.Resource {
	return mustAddLoginSchema(&schema.Resource{
		Schema: map[string]*schema.Schema{
			consts.FieldRole: {
				Type:     schema.TypeString,
				Optional: true,
				Description: `name of the role against which the login is being attempted. 
If role is not specified, then the login endpoint looks for a 
role bearing the name of the AMI ID of the EC2 instance that is trying 
to login if using the ec2 auth method, 
or the "friendly name" (i.e., role name or username) 
of the IAM principal authenticated. If a matching role is not found, login fails.`,
			},
			consts.FieldIdentity: {
				Type: schema.TypeString,
				Description: `base64 encoded EC2 instance identity document, which can usually be obtained from 
the http://169.254.169.254/latest/dynamic/instance-identity/document endpoint. 
When using curl for fetching the identity document, consider using the option -w 0 while piping the 
output to base64 binary. Either both of this and signature must be set OR pkcs7 must be set when using the 
ec2 auth method.`,
				Optional: true,
			},
			consts.FieldSignature: {
				Type: schema.TypeString,
				Description: `base64-encoded SHA256 RSA signature of the instance identity document, 
which can usually be obtained from the http://169.254.169.254/latest/dynamic/instance-identity/document endpoint. 
Either both this AND identity must be set OR pkcs7 must be set when using the ec2 auth method.`,
				Optional: true,
			},
			consts.FieldPKCS7: {
				Type: schema.TypeString,
				Description: `PKCS#7 signature of the identity document with all \n characters removed. 
This supports signatures from the AWS http://169.254.169.254/latest/dynamic/instance-identity/rsa2048 
or http://169.254.169.254/latest/dynamic/instance-identity/pkcs7 endpoints.
Either this needs to be set OR both identity and signature need to be set when using the ec2 auth method.`,
				Optional: true,
			},
			consts.FieldNonce: {
				Type: schema.TypeString,
				Description: `The nonce to be used for subsequent login requests. If this parameter is not 
specified at all and if reauthentication is allowed, then the method will generate a random nonce, 
attaches it to the instance's identity-accesslist entry and returns the nonce back as part of auth metadata.
This value should be used with further login requests, to establish client authenticity.
Clients can choose to set a custom nonce if preferred, in which case, 
it is recommended that clients provide a strong nonce.
If a nonce is provided but with an empty value, 
it indicates intent to disable reauthentication. 
Note that, when disallow_reauthentication option is enabled on either the role or the role tag, 
the nonce holds no significance. This is ignored unless using the ec2 auth method.`,
				Optional: true,
			},
			consts.FieldIAMHttpRequestMethod: {
				Type: schema.TypeString,
				Description: `HTTP method used in the signed request.
Currently only POST is supported, but other methods may be supported in the future.
This is required when using the iam auth method.`,
				Optional: true,
			},
			consts.FieldIAMHttpRequestURL: {
				Type: schema.TypeString,
				Description: `base64-encoded HTTP URL used in the signed request. 
Most likely just aHR0cHM6Ly9zdHMuYW1hem9uYXdzLmNvbS8= (base64-encoding of https://sts.amazonaws.
com/) as most requests will probably use POST with an empty URI. 
This is required when using the iam auth method.`,
				Optional: true,
			},
			consts.FieldIAMHttpRequestBody: {
				Type: schema.TypeString,
				Description: `base64-encoded body of the signed request. 
Most likely QWN0aW9uPUdldENhbGxlcklkZW50aXR5JlZlcnNpb249MjAxMS0wNi0xNQ==, 
which is the base64 encoding of Action=GetCallerIdentity&Version=2011-06-15.
This is required when using the iam auth method.`,
				Optional: true,
			},
			consts.FieldIAMHttpRequestHeaders: {
				Type:     schema.TypeMap,
				Optional: true,
				Description: `key/value pairs of headers for use in the sts:GetCallerIdentity HTTP requests headers. 
Can be either a Base64-encoded, JSON-serialized string, or a JSON object of key/value pairs. 
The JSON serialization assumes that each header key maps to either a string value or an array of string values 
(though the length of that array will probably only be one). 
If the iam_server_id_header_value is configured in Vault for the aws auth mount, 
then the headers must include the X-Vault-AWS-IAM-Server-ID header, 
its value must match the value configured, and the header must be included in the signed headers. 
This is required when using the iam auth method.`,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	})
}

// AuthLoginAWS for handling the Vault AWS authentication engine.
// Requires configuration provided by SchemaLoginAWS.
type AuthLoginAWS struct {
	AuthLoginCommon
}

func (l *AuthLoginAWS) LoginPath() string {
	// TODO: add params validation
	return fmt.Sprintf("auth/%s/login", l.MountPath())
}

func (l *AuthLoginAWS) Method() string {
	return consts.AuthMethodAWS
}

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
