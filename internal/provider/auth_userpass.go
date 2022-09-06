package provider

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

var SchemaLoginUserpass = mustAddLoginSchema(&schema.Resource{
	Schema: map[string]*schema.Schema{
		consts.FieldUsername: {
			Type:        schema.TypeString,
			Required:    true,
			DefaultFunc: schema.EnvDefaultFunc(consts.EnvVarUsername, ""),
		},
		consts.FieldPassword: {
			Type:        schema.TypeString,
			Optional:    true,
			DefaultFunc: schema.EnvDefaultFunc(consts.EnvVarPassword, ""),
		},
		consts.FieldPasswordFile: {
			Type:        schema.TypeString,
			Optional:    true,
			DefaultFunc: schema.EnvDefaultFunc(consts.EnvVarPasswordFile, ""),
			// ConflictsWith: []string{consts.FieldPassword},
		},
	},
})

// AuthLoginUserpass provides an interface for authenticating to the
// userpass authentication engine.
type AuthLoginUserpass struct {
	AuthLoginCommon
}

func (l *AuthLoginUserpass) Schema() *schema.Resource {
	return SchemaLoginUserpass
}

func (l *AuthLoginUserpass) Login(client *api.Client) (*api.Secret, error) {
	params := l.copyParams()
	if err := setupUserpassAuthParams(params, nil); err != nil {
		return nil, err
	}

	return l.login(client, l.LoginPath(), params)
}

func (l *AuthLoginUserpass) MountPath() string {
	if l.mount == "" {
		return consts.AuthMethodUserpass
	}
	return l.mount
}

func (l *AuthLoginUserpass) LoginPath() string {
	return fmt.Sprintf("auth/%s/login/%s", l.MountPath(), l.params[consts.FieldUsername])
}

func (l *AuthLoginUserpass) Method() string {
	return consts.AuthMethodUserpass
}

func setupUserpassAuthParams(params map[string]interface{}, env map[string]string) error {
	method := consts.AuthMethodUserpass

	// largely here for tests
	getEnv := func(k string) string {
		if env != nil {
			return env[k]
		}
		return os.Getenv(k)
	}

	username := getEnv(consts.EnvVarUsername)
	if username == "" {
		if v, ok := params["username"]; ok {
			username = v.(string)
		}
	}

	if username == "" {
		return fmt.Errorf("auth method %q, %q not set in %q",
			method,
			consts.FieldUsername,
			consts.FieldParameters,
		)
	}

	// the password can be had from various sources
	p := getEnv(consts.EnvVarPassword)
	if p == "" {
		var passwordFile string
		if v := getEnv(consts.EnvVarPasswordFile); v != "" {
			passwordFile = v
		} else if v, ok := params[consts.FieldPasswordFile]; ok && v != nil {
			passwordFile = v.(string)
			delete(params, consts.FieldPasswordFile)
		}

		if v := getEnv(consts.EnvVarPassword); v != "" {
			p = v
		} else if v, ok := params[consts.FieldPassword]; ok && v != nil {
			p = v.(string)
		}

		if passwordFile != "" && p != "" {
			return fmt.Errorf("auth method %q, mutually exclusive auth params provided: %s",
				method,
				strings.Join([]string{consts.FieldPassword, consts.FieldPasswordFile}, ", "))
		}

		if passwordFile != "" {
			f, err := os.Open(passwordFile)
			if err != nil {
				return err
			}

			v, err := ioutil.ReadAll(f)
			if err != nil {
				return err
			}
			p = string(v)
		}
	}

	params[consts.FieldPassword] = p
	params[consts.FieldUsername] = username

	return nil
}
