// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	krbauth "github.com/hashicorp/vault-plugin-auth-kerberos"
	"github.com/hashicorp/vault/api"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/mitchellh/go-homedir"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

// GetKerberosLoginSchema for the kerberos authentication engine.
func GetKerberosLoginSchema(authField string) *schema.Schema {
	return getLoginSchema(
		authField,
		"Login to vault using the kerberos method",
		GetKerberosLoginSchemaResource,
	)
}

// GetKerberosLoginSchemaResource for the kerberos authentication engine.
func GetKerberosLoginSchemaResource(authField string) *schema.Resource {
	conflicts := []string{fmt.Sprintf("%s.0.%s", authField, consts.FieldToken)}
	s := mustAddLoginSchema(&schema.Resource{
		Schema: map[string]*schema.Schema{
			consts.FieldToken: {
				Type:         schema.TypeString,
				Optional:     true,
				DefaultFunc:  schema.EnvDefaultFunc(consts.EnvVarKrbSPNEGOToken, nil),
				Description:  "Simple and Protected GSSAPI Negotiation Mechanism (SPNEGO) token",
				ValidateFunc: validateKRBNegToken,
			},
			consts.FieldUsername: {
				Type:          schema.TypeString,
				Optional:      true,
				Description:   "The username to login into Kerberos with.",
				ConflictsWith: conflicts,
			},
			consts.FieldService: {
				Type:          schema.TypeString,
				Optional:      true,
				Description:   "The service principle name.",
				ConflictsWith: conflicts,
			},
			consts.FieldRealm: {
				Type:          schema.TypeString,
				Optional:      true,
				Description:   "The Kerberos server's authoritative authentication domain",
				ConflictsWith: conflicts,
			},
			consts.FieldKRB5ConfPath: {
				Type:          schema.TypeString,
				Optional:      true,
				Description:   "A valid Kerberos configuration file e.g. /etc/krb5.conf.",
				DefaultFunc:   schema.EnvDefaultFunc(consts.EnvVarKRB5Conf, nil),
				ValidateFunc:  validateFileExists,
				ConflictsWith: conflicts,
			},
			consts.FieldKeytabPath: {
				Type:          schema.TypeString,
				Optional:      true,
				Description:   "The Kerberos keytab file containing the entry of the login entity.",
				DefaultFunc:   schema.EnvDefaultFunc(consts.EnvVarKRBKeytab, nil),
				ValidateFunc:  validateFileExists,
				ConflictsWith: conflicts,
			},
			consts.FieldDisableFastNegotiation: {
				Type:          schema.TypeBool,
				Optional:      true,
				Default:       false,
				ConflictsWith: conflicts,
				Description:   "Disable the Kerberos FAST negotiation.",
			},
			consts.FieldRemoveInstanceName: {
				Type:          schema.TypeBool,
				Optional:      true,
				Default:       false,
				ConflictsWith: conflicts,
				Description:   "Strip the host from the username found in the keytab.",
			},
		},
	}, consts.MountTypeKerberos)

	return s
}

type AuthLoginKerberos struct {
	AuthLoginCommon
	// useful for unit testing
	authHeaderFunc func(*krbauth.LoginCfg) (string, error)
}

// MountPath for the kerberos authentication engine.
func (l *AuthLoginKerberos) MountPath() string {
	if l.mount == "" {
		return l.Method()
	}
	return l.mount
}

// LoginPath for the kerberos authentication engine.
func (l *AuthLoginKerberos) LoginPath() string {
	return fmt.Sprintf("auth/%s/login", l.MountPath())
}

func (l *AuthLoginKerberos) Init(d *schema.ResourceData, authField string) error {
	if err := l.AuthLoginCommon.Init(d, authField); err != nil {
		return err
	}

	if _, ok := l.getOk(d, consts.FieldToken); !ok {
		required := []string{
			consts.FieldUsername,
			consts.FieldService,
			consts.FieldRealm,
			consts.FieldKeytabPath,
			consts.FieldKRB5ConfPath,
		}
		var missing []string
		for _, f := range required {
			if _, ok := l.getOk(d, f); !ok {
				missing = append(missing, f)
			}
		}

		if len(missing) > 0 {
			return fmt.Errorf("required fields are unset: %v", missing)
		}
	}

	return nil
}

// Method name for the kerberos authentication engine.
func (l *AuthLoginKerberos) Method() string {
	return consts.AuthMethodKerberos
}

// Login using the kerberos authentication engine.
func (l *AuthLoginKerberos) Login(client *api.Client) (*api.Secret, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}

	negInitToken, err := l.getNegInitToken()
	if err != nil {
		return nil, err
	}

	return l.login(client, l.LoginPath(),
		map[string]interface{}{
			consts.FieldAuthorization: negInitToken,
		},
	)
}

func (l *AuthLoginKerberos) getNegInitToken() (string, error) {
	if v, ok := l.params[consts.FieldToken]; ok && v.(string) != "" {
		return fmt.Sprintf("Negotiate %s", v), nil
	}

	f := l.authHeaderFunc
	if f == nil {
		f = krbauth.GetAuthHeaderVal
	}

	config := &krbauth.LoginCfg{
		Username:               l.params[consts.FieldUsername].(string),
		Service:                l.params[consts.FieldService].(string),
		Realm:                  l.params[consts.FieldRealm].(string),
		KeytabPath:             l.params[consts.FieldKeytabPath].(string),
		Krb5ConfPath:           l.params[consts.FieldKRB5ConfPath].(string),
		DisableFASTNegotiation: l.params[consts.FieldDisableFastNegotiation].(bool),
		RemoveInstanceName:     l.params[consts.FieldRemoveInstanceName].(bool),
	}
	token, err := f(config)
	if err != nil {
		return "", err
	}

	return token, nil
}

func validateKRBNegToken(v interface{}, _ string) ([]string, []error) {
	if v == nil || v.(string) == "" {
		return nil, nil
	}

	var errors []error
	b, err := base64.StdEncoding.DecodeString(v.(string))
	if err != nil {
		return nil, append(errors, fmt.Errorf("failed to decode token, err=%w", err))
	}

	isNeg, _, err := spnego.UnmarshalNegToken(b)
	if err != nil {
		return nil, append(errors, fmt.Errorf("failed to unmarshal token, err=%w", err))
	}

	if !isNeg {
		return nil, append(errors, fmt.Errorf("not an initialization token"))
	}

	return nil, nil
}

func validateFileExists(v interface{}, _ string) ([]string, []error) {
	if v == nil || v.(string) == "" {
		return nil, nil
	}

	var errors []error
	filename, err := homedir.Expand(v.(string))
	if err != nil {
		return nil, append(errors, err)
	}

	st, err := os.Stat(filename)
	if err != nil {
		return nil, append(errors, fmt.Errorf("failed to stat path %q, err=%w", filename, err))
	}

	if st.IsDir() {
		return nil, append(errors, fmt.Errorf("path %q is not a file", filename))
	}

	return nil, errors
}
