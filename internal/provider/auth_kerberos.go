package provider

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	kerberos "github.com/hashicorp/vault-plugin-auth-kerberos"
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
	conflicts := []string{consts.FieldToken}
	s := mustAddLoginSchema(&schema.Resource{
		Schema: map[string]*schema.Schema{
			consts.FieldToken: {
				Type:         schema.TypeString,
				Required:     true,
				DefaultFunc:  schema.EnvDefaultFunc(consts.EnvVarKrbSPENGOToken, nil),
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
				Description:   "",
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
				Description:   "Disable the Kerberos FAST negotiation",
			},
			consts.FieldRemoveInstanceName: {
				Type:          schema.TypeBool,
				Optional:      true,
				Default:       false,
				ConflictsWith: conflicts,
				Description:   "Strip the host from the any username found in the keytab.",
			},
		},
	}, consts.MountTypeKerberos)

	return s
}

type AuthLoginKerberos struct {
	AuthLoginCommon
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

	return nil
}

// Method name for the kerberos authentication engine.
func (l *AuthLoginKerberos) Method() string {
	return consts.AuthMethodKerberos
}

// Login using the kerberos authentication engine.
func (l *AuthLoginKerberos) Login(client *api.Client) (*api.Secret, error) {
	token, err := l.getToken()
	if err != nil {
		return nil, err
	}

	return l.login(client, l.LoginPath(),
		map[string]interface{}{
			consts.FieldAuthorization: fmt.Sprintf("Negotiate %s", token),
		},
	)
}

func (l *AuthLoginKerberos) getToken() (string, error) {
	if v, ok := l.params[consts.FieldToken]; ok && v.(string) != "" {
		return fmt.Sprintf("Negotiate %s", v), nil
	}

	config := &kerberos.LoginCfg{
		Username:               l.params[consts.FieldUsername].(string),
		Service:                l.params[consts.FieldService].(string),
		Realm:                  l.params[consts.FieldRealm].(string),
		KeytabPath:             l.params[consts.FieldKeytabPath].(string),
		Krb5ConfPath:           l.params[consts.FieldKRB5ConfPath].(string),
		DisableFASTNegotiation: l.params[consts.FieldDisableFastNegotiation].(bool),
		RemoveInstanceName:     l.params[consts.FieldRemoveInstanceName].(bool),
	}

	token, err := kerberos.GetAuthHeaderVal(config)
	if err != nil {
		return "", err
	}

	return token, nil
}

func validateKRBNegToken(v interface{}, s string) ([]string, []error) {
	if v == nil || v.(string) == "" {
		return nil, nil
	}

	b, err := base64.StdEncoding.DecodeString(v.(string))
	if err != nil {
		return nil, []error{err}
	}

	isNeg, _, err := spnego.UnmarshalNegToken(b)
	if err != nil {
		return nil, []error{err}
	}

	if !isNeg {
		return nil, []error{fmt.Errorf("token is not a valid SPNEGO negotiation token")}
	}

	return nil, nil
}

func validateFileExists(v interface{}, s string) ([]string, []error) {
	if v == nil || v.(string) == "" {
		return nil, nil
	}

	var errors []error
	filename, err := homedir.Expand(v.(string))
	if err != nil {
		errors = append(errors, err)
	} else {
		if _, err := os.Stat(filename); err != nil {
			errors = append(errors, err)
		}
	}

	return nil, errors
}
