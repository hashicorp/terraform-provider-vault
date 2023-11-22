// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func init() {
	field := consts.FieldAuthLoginTokenFile
	if err := globalAuthLoginRegistry.Register(field,
		func(r *schema.ResourceData) (AuthLogin, error) {
			a := &AuthLoginTokenFile{}
			return a.Init(r, field)
		}, GetTokenFileSchema); err != nil {
		panic(err)
	}
}

// GetTokenFileSchema for the token file.
func GetTokenFileSchema(authField string) *schema.Schema {
	return getLoginSchema(
		authField,
		//  TODO: come up with a meaningful description
		"Login to vault using ",
		GetTokenFileSchemaResource,
	)
}

// GetTokenFileSchemaResource for pre-authenticated token-from-file.
func GetTokenFileSchemaResource(authField string) *schema.Resource {
	return mustAddLoginSchema(&schema.Resource{
		Schema: map[string]*schema.Schema{
			consts.FieldFilename: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The name of a file containing a single " +
					"line that is a valid Vault token",
			},
		},
	}, authField, consts.MountTypeNone)
}

var _ AuthLogin = (*AuthLoginTokenFile)(nil)

type AuthLoginTokenFile struct {
	AuthLoginCommon
}

// MountPath is unused
func (l *AuthLoginTokenFile) MountPath() string {
	return ""
}

// LoginPath is unused
func (l *AuthLoginTokenFile) LoginPath() string {
	return ""
}

func (l *AuthLoginTokenFile) Init(d *schema.ResourceData,
	authField string,
) (AuthLogin, error) {
	l.mount = consts.MountTypeNone

	defaults := authDefaults{
		{
			field:      consts.FieldFilename,
			envVars:    []string{consts.EnvVarTokenFilename},
			defaultVal: "",
		},
	}
	if err := l.AuthLoginCommon.Init(d, authField,
		func(data *schema.ResourceData, params map[string]interface{}) error {
			return l.setDefaultFields(d, defaults, params)
		},
		func(data *schema.ResourceData, params map[string]interface{}) error {
			return l.checkRequiredFields(d, params, consts.FieldFilename)
		},
	); err != nil {
		return nil, err
	}

	return l, nil
}

// Method is unused.
func (l *AuthLoginTokenFile) Method() string {
	return ""
}

// Login provides a pseudo mechanism fetching a Vault token from a local file.
func (l *AuthLoginTokenFile) Login(c *api.Client) (*api.Secret, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}

	token, err := l.readTokenFile()
	if err != nil {
		return nil, err
	}

	clone, err := c.Clone()
	if err != nil {
		return nil, err
	}

	clone.SetToken(token)
	resp, err := clone.Auth().Token().LookupSelf()
	if err != nil {
		return nil, err
	}

	if resp == nil {
		return nil, fmt.Errorf("empty token lookup response")
	}

	resp.Auth = &api.SecretAuth{
		ClientToken: token,
	}

	return resp, nil
}

func (l *AuthLoginTokenFile) readTokenFile() (string, error) {
	filename := l.params[consts.FieldFilename].(string)
	fh, err := os.Open(filename)
	if err != nil {
		return "", err
	}

	st, err := fh.Stat()
	if err != nil {
		return "", err
	}

	mode := st.Mode()
	if !mode.IsRegular() {
		return "", fmt.Errorf("token path %q is not regular file", filename)
	}

	// require only user access
	v := mode.Perm() & 0o077
	if v != 0 {
		return "", fmt.Errorf("token path %q has an invalid mode %v", filename, mode.Perm())
	}

	var lines [][]byte
	s := bufio.NewScanner(fh)
	for s.Scan() {
		lines = append(lines, s.Bytes())
		if len(lines) > 1 {
			return "", fmt.Errorf("token path %q contains more than one line", filename)
		}
	}

	var token string
	if len(lines) == 1 {
		token = strings.TrimSuffix(string(lines[0]), "\n")
	}

	if token == "" {
		return "", fmt.Errorf("no token found in %q", filename)
	}

	return token, nil
}
