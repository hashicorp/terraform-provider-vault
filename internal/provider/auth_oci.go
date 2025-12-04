// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	ociauth "github.com/hashicorp/vault-plugin-auth-oci"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func init() {
	field := consts.FieldAuthLoginOCI
	if err := globalAuthLoginRegistry.Register(field,
		func(r *schema.ResourceData) (AuthLogin, error) {
			a := &AuthLoginOCI{}
			return a.Init(r, field)
		}, GetOCILoginSchema); err != nil {
		panic(err)
	}
}

const (
	ociAuthTypeInstance = "instance"
	ociAuthTypeAPIKeys  = "apikey"
)

type signHeadersFunc func(string, string) (http.Header, error)

// GetOCILoginSchema for the OCI authentication engine.
func GetOCILoginSchema(authField string) *schema.Schema {
	return getLoginSchema(
		authField,
		"Login to vault using the OCI method",
		GetOCILoginSchemaResource,
	)
}

// GetOCILoginSchemaResource for the OCI authentication engine.
func GetOCILoginSchemaResource(authField string) *schema.Resource {
	return mustAddLoginSchema(&schema.Resource{
		Schema: map[string]*schema.Schema{
			consts.FieldRole: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the login role.",
			},
			consts.FieldAuthType: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Authentication type to use when getting OCI credentials.",
				ValidateDiagFunc: GetValidateDiagChoices(
					[]string{ociAuthTypeInstance, ociAuthTypeAPIKeys},
				),
			},
		},
	}, authField, consts.MountTypeOCI)
}

var _ AuthLogin = (*AuthLoginOCI)(nil)

// AuthLoginOCI handler for authenticating to OCI auth engine.
type AuthLoginOCI struct {
	AuthLoginCommon
}

// MountPath for the OCI authentication engine.
func (l *AuthLoginOCI) MountPath() string {
	if l.mount == "" {
		return l.Method()
	}
	return l.mount
}

// LoginPath for the OCI authentication engine.
func (l *AuthLoginOCI) LoginPath() string {
	return fmt.Sprintf("auth/%s/login/%s", l.MountPath(), l.params[consts.FieldRole])
}

func (l *AuthLoginOCI) Init(d *schema.ResourceData, authField string) (AuthLogin, error) {
	if err := l.AuthLoginCommon.Init(d, authField,
		func(data *schema.ResourceData, params map[string]interface{}) error {
			return l.checkRequiredFields(d, params, consts.FieldRole, consts.FieldAuthType)
		},
	); err != nil {
		return nil, err
	}

	return l, nil
}

// Method name for the OCI authentication engine.
func (l *AuthLoginOCI) Method() string {
	return consts.AuthMethodOCI
}

// Login using the OCI authentication engine.
func (l *AuthLoginOCI) Login(client *api.Client) (*api.Secret, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}

	v := l.params[consts.FieldAuthType]
	f, err := l.getSignedHeadersFunc(v.(string))
	if err != nil {
		return nil, err
	}

	signPath := strings.Join([]string{consts.VaultAPIV1Root, l.LoginPath()}, consts.PathDelim)
	headers, err := f(client.Address(), signPath)
	if err != nil {
		return nil, err
	}

	params := map[string]interface{}{
		consts.FieldRequestHeaders: headers,
	}

	return l.login(client, l.LoginPath(), params)
}

func (l *AuthLoginOCI) getSignedHeadersFunc(authType string) (signHeadersFunc, error) {
	var headerFunc signHeadersFunc
	switch authType {
	case ociAuthTypeInstance:
		headerFunc = ociauth.GetSignedInstanceRequestHeaders
	case ociAuthTypeAPIKeys:
		headerFunc = ociauth.GetSignedAPIRequestHeaders
	default:
		return nil, fmt.Errorf("unsupported auth type %q", authType)
	}

	return headerFunc, nil
}
