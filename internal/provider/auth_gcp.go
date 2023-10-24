// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	credentials "cloud.google.com/go/iam/credentials/apiv1"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/useragent"
	"github.com/mitchellh/go-homedir"
	googleoauth "golang.org/x/oauth2/google"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	credentialspb "google.golang.org/genproto/googleapis/iam/credentials/v1"

	"cloud.google.com/go/compute/metadata"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func init() {
	field := consts.FieldAuthLoginGCP
	if err := globalAuthLoginRegistry.Register(field,
		func(r *schema.ResourceData) (AuthLogin, error) {
			a := &AuthLoginGCP{}
			return a.Init(r, field)
		}, GetGCPLoginSchema); err != nil {
		panic(err)
	}
}

// GetGCPLoginSchema for the gcp authentication engine.
func GetGCPLoginSchema(authField string) *schema.Schema {
	return getLoginSchema(
		authField,
		"Login to vault using the gcp method",
		GetGCPLoginSchemaResource,
	)
}

// GetGCPLoginSchemaResource for the gcp authentication engine.
func GetGCPLoginSchemaResource(authField string) *schema.Resource {
	return mustAddLoginSchema(&schema.Resource{
		Schema: map[string]*schema.Schema{
			consts.FieldRole: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the login role.",
			},
			consts.FieldJWT: {
				Type:          schema.TypeString,
				Optional:      true,
				Description:   "A signed JSON Web Token.",
				DefaultFunc:   schema.EnvDefaultFunc(consts.EnvVarGCPAuthJWT, nil),
				ConflictsWith: []string{fmt.Sprintf("%s.0.%s", authField, consts.FieldCredentials)},
			},
			consts.FieldCredentials: {
				Type:          schema.TypeString,
				Optional:      true,
				ValidateFunc:  validateCredentials,
				Description:   "Path to the Google Cloud credentials file.",
				DefaultFunc:   schema.EnvDefaultFunc(consts.EnvVarGoogleApplicationCreds, nil),
				ConflictsWith: []string{fmt.Sprintf("%s.0.%s", authField, consts.FieldJWT)},
			},
			consts.FieldServiceAccount: {
				Type:          schema.TypeString,
				Optional:      true,
				Description:   "IAM service account.",
				ConflictsWith: []string{fmt.Sprintf("%s.0.%s", authField, consts.FieldJWT)},
			},
		},
	}, consts.MountTypeGCP)
}

var _ AuthLogin = (*AuthLoginGCP)(nil)

// AuthLoginGCP provides an interface for authenticating to the
// gcp authentication engine.
// Requires configuration provided by SchemaLoginGCP.
type AuthLoginGCP struct {
	AuthLoginCommon
}

func (l *AuthLoginGCP) Init(d *schema.ResourceData, authField string) (AuthLogin, error) {
	if err := l.AuthLoginCommon.Init(d, authField); err != nil {
		return nil, err
	}
	return l, nil
}

// MountPath for the cert authentication engine.
func (l *AuthLoginGCP) MountPath() string {
	if l.mount == "" {
		return l.Method()
	}
	return l.mount
}

// LoginPath for the gcp authentication engine.
func (l *AuthLoginGCP) LoginPath() string {
	return fmt.Sprintf("auth/%s/login", l.MountPath())
}

// Method name for the gcp authentication engine.
func (l *AuthLoginGCP) Method() string {
	return consts.AuthMethodGCP
}

// Login using the gcp authentication engine.
func (l *AuthLoginGCP) Login(client *api.Client) (*api.Secret, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}

	params, err := l.copyParamsExcluding(
		consts.FieldIsRootNamespace,
		consts.FieldNamespace,
		consts.FieldMount,
		consts.FieldJWT,
		consts.FieldCredentials,
		consts.FieldServiceAccount,
	)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	jwt, err := l.getJWT(ctx)
	if err != nil {
		return nil, err
	}

	params[consts.FieldJWT] = jwt

	return l.login(client, l.LoginPath(), params)
}

func (l *AuthLoginGCP) getJWT(ctx context.Context) (string, error) {
	// get the token from the params
	if v, ok := l.params[consts.FieldJWT]; ok && v.(string) != "" {
		return v.(string), nil
	}

	if v, ok := l.params[consts.FieldCredentials]; ok && v.(string) != "" {
		// get the token from IAM
		creds, err := getGCPOauthCredentials(ctx, v.(string), iam.CloudPlatformScope)
		if err != nil {
			return "", fmt.Errorf(
				"JSON credentials are not valid, err=%w", err)
		}

		c, err := credentials.NewIamCredentialsClient(ctx,
			option.WithCredentials(creds),
			// TODO: set the Vault user-agent for now, until we have a build time value for the provider.
			option.WithUserAgent(useragent.String()),
		)
		if err != nil {
			return "", fmt.Errorf(
				"failed to instantiate the IAMCredentialsClient, err=%w", err)
		}
		defer c.Close()

		var m map[string]interface{}
		if err := json.Unmarshal(creds.JSON, &m); err != nil {
			return "", err
		}

		var serviceAccount string
		if v, ok := l.params[consts.FieldServiceAccount]; ok {
			serviceAccount = v.(string)
		} else if v, ok := m[consts.FieldClientEmail]; ok {
			serviceAccount = v.(string)
		} else {
			return "", fmt.Errorf("no serviceAccount could be found")
		}

		b, err := json.Marshal(
			map[string]interface{}{
				"sub": serviceAccount,
				"aud": fmt.Sprintf("https://vault/%s", l.params[consts.FieldRole]),
				// TODO: consider making this value a tunable
				"exp": time.Now().Add(time.Minute * 30).Unix(),
			},
		)
		if err != nil {
			// should never get here
			return "", err
		}

		// requires: https://cloud.google.com/iam/docs/service-accounts#token-creator-role
		resourceName := fmt.Sprintf("projects/-/serviceAccounts/%s", serviceAccount)
		req := &credentialspb.SignJwtRequest{
			Name:    resourceName,
			Payload: string(b),
		}
		resp, err := c.SignJwt(ctx, req)
		if err != nil {
			return "", fmt.Errorf("failed to sign JWT, err=%w", err)
		}

		return resp.SignedJwt, nil
	}

	if metadata.OnGCE() {
		// If we are running on GCE instance we can get the JWT token
		// from the meta-data service.
		audience := fmt.Sprintf("%s/vault", l.params[consts.FieldRole])
		c := metadata.NewClient(nil)
		resp, err := c.Get(
			fmt.Sprintf("instance/service-accounts/default/identity?audience=%s&format=full", audience),
		)
		if err != nil {
			return "", err
		}
		return resp, nil
	}

	return "", fmt.Errorf(
		"no JWT token specified and all methods of generating one have failed")
}

func validateCredentials(v interface{}, k string) ([]string, []error) {
	if v == nil || v.(string) == "" {
		return nil, nil
	}

	if _, err := getGCPOauthCredentials(context.Background(), v.(string)); err != nil {
		return nil, []error{fmt.Errorf("failed to validate JSON credentials, err=%w", err)}
	}

	return nil, nil
}

func getGCPOauthCredentials(ctx context.Context, filename string, scopes ...string) (*googleoauth.Credentials, error) {
	var err error
	filename, err = homedir.Expand(filename)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("could not read credentials from %q, err=%w", filename, err)
	}

	return googleoauth.CredentialsFromJSON(ctx, data, scopes...)
}
