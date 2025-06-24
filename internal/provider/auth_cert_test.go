// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAuthLoginCert_Init(t *testing.T) {
	s := map[string]*schema.Schema{
		consts.FieldCACertFile: {
			Type:     schema.TypeString,
			Optional: true,
		},
		consts.FieldCACertDir: {
			Type:     schema.TypeString,
			Optional: true,
		},
		consts.FieldSkipTLSVerify: {
			Type:     schema.TypeBool,
			Optional: true,
		},
		consts.FieldTLSServerName: {
			Type:     schema.TypeString,
			Optional: true,
		},
	}

	tests := []authLoginInitTest{
		{
			name: "without-role-name",
			raw: map[string]interface{}{
				consts.FieldCACertFile: "ca.crt",
				consts.FieldAuthLoginCert: []interface{}{
					map[string]interface{}{
						consts.FieldCertFile: "cert.crt",
						consts.FieldKeyFile:  "cert.key",
					},
				},
			},
			authField: consts.FieldAuthLoginCert,
			expectParams: map[string]interface{}{
				consts.FieldNamespace:        "",
				consts.FieldUseRootNamespace: false,
				consts.FieldMount:            consts.MountTypeCert,
				consts.FieldName:             "",
				consts.FieldCACertFile:       "ca.crt",
				consts.FieldCertFile:         "cert.crt",
				consts.FieldKeyFile:          "cert.key",
			},
			wantErr: false,
		},
		{
			name: "with-role-name",
			raw: map[string]interface{}{
				consts.FieldAuthLoginCert: []interface{}{
					map[string]interface{}{
						consts.FieldName:     "bob",
						consts.FieldCertFile: "cert.crt",
						consts.FieldKeyFile:  "cert.key",
					},
				},
			},
			authField: consts.FieldAuthLoginCert,
			expectParams: map[string]interface{}{
				consts.FieldNamespace:        "",
				consts.FieldUseRootNamespace: false,
				consts.FieldMount:            consts.MountTypeCert,
				consts.FieldName:             "bob",
				consts.FieldCertFile:         "cert.crt",
				consts.FieldKeyFile:          "cert.key",
			},
			wantErr: false,
		},
		{
			name: "with-namespace",
			raw: map[string]interface{}{
				consts.FieldCACertFile: "ca.crt",
				consts.FieldAuthLoginCert: []interface{}{
					map[string]interface{}{
						consts.FieldNamespace: "ns1",
						consts.FieldCertFile:  "cert.crt",
						consts.FieldKeyFile:   "cert.key",
					},
				},
			},
			authField: consts.FieldAuthLoginCert,
			expectParams: map[string]interface{}{
				consts.FieldNamespace:        "ns1",
				consts.FieldUseRootNamespace: false,
				consts.FieldMount:            consts.MountTypeCert,
				consts.FieldName:             "",
				consts.FieldCACertFile:       "ca.crt",
				consts.FieldCertFile:         "cert.crt",
				consts.FieldKeyFile:          "cert.key",
			},
			wantErr: false,
		},
		{
			name: "all-params",
			raw: map[string]interface{}{
				consts.FieldCACertDir:     "/foo/baz",
				consts.FieldCACertFile:    "ca.crt",
				consts.FieldSkipTLSVerify: true,
				consts.FieldTLSServerName: "baz.biff",
				consts.FieldAuthLoginCert: []interface{}{
					map[string]interface{}{
						consts.FieldNamespace: "ns1",
						consts.FieldName:      "bob",
						consts.FieldCertFile:  "cert.crt",
						consts.FieldKeyFile:   "cert.key",
						consts.FieldMount:     "cert1",
					},
				},
			},
			authField: consts.FieldAuthLoginCert,
			expectParams: map[string]interface{}{
				consts.FieldNamespace:        "ns1",
				consts.FieldUseRootNamespace: false,
				consts.FieldCACertDir:        "/foo/baz",
				consts.FieldSkipTLSVerify:    true,
				consts.FieldTLSServerName:    "baz.biff",
				consts.FieldMount:            "cert1",
				consts.FieldName:             "bob",
				consts.FieldCACertFile:       "ca.crt",
				consts.FieldCertFile:         "cert.crt",
				consts.FieldKeyFile:          "cert.key",
			},
			wantErr: false,
		},
		{
			name:         "error-missing-resource",
			authField:    consts.FieldAuthLoginCert,
			expectParams: nil,
			wantErr:      true,
			expectErr:    fmt.Errorf("resource data missing field %q", consts.FieldAuthLoginCert),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s[tt.authField] = GetCertLoginSchema(tt.authField)
			t.Cleanup(func() {
				delete(s, tt.authField)
			})
			assertAuthLoginInit(t, tt, s, &AuthLoginCert{})
		})
	}
}

func TestAuthLoginCert_LoginPath(t *testing.T) {
	type fields struct {
		AuthLoginCommon AuthLoginCommon
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "default",
			fields: fields{
				AuthLoginCommon: AuthLoginCommon{},
			},
			want: "auth/cert/login",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginCert{
				AuthLoginCommon: tt.fields.AuthLoginCommon,
			}
			if got := l.LoginPath(); got != tt.want {
				t.Errorf("LoginPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthLoginCert_Login(t *testing.T) {
	// Since Auth Cert login clones the Vault client,
	// this test will fail if VAULT_TOKEN environment variable is set

	env := "VAULT_TOKEN"
	originalValue, exists := os.LookupEnv(env)

	t.Setenv(env, "") // Unset the environment variable

	t.Cleanup(func() {
		if exists {
			t.Setenv(env, originalValue) // Restore original value
		} else {
			os.Unsetenv(env) // Unset if it didn't exist initially
		}
	})

	handlerFunc := func(t *testLoginHandler, w http.ResponseWriter, req *http.Request) {
		role := "default"
		if t.params != nil {
			if v, ok := t.params[len(t.params)-1][consts.FieldName]; ok {
				role = v.(string)
			}
		}
		m, err := json.Marshal(
			&api.Secret{
				Auth: &api.SecretAuth{
					Metadata: map[string]string{
						"role": role,
					},
				},
			},
		)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(m)
	}

	tempDir := t.TempDir()

	b, k, err := testutil.GenerateCA()
	if err != nil {
		t.Fatal(err)
	}

	certFile := path.Join(tempDir, "cert.crt")
	if err := os.WriteFile(certFile, b, 0o400); err != nil {
		t.Fatal(err)
	}

	keyFile := path.Join(tempDir, "cert.key")
	if err := os.WriteFile(keyFile, k, 0o400); err != nil {
		t.Fatal(err)
	}

	tests := []authLoginTest{
		{
			name: "default",
			authLogin: &AuthLoginCert{
				AuthLoginCommon{
					authField: "baz",
					params: map[string]interface{}{
						consts.FieldCertFile:      certFile,
						consts.FieldKeyFile:       keyFile,
						consts.FieldSkipTLSVerify: true,
					},
					initialized: true,
				},
			},
			handler: &testLoginHandler{
				handlerFunc: handlerFunc,
			},
			expectReqCount: 1,
			expectReqPaths: []string{
				"/v1/auth/cert/login",
			},
			expectReqParams: nil,
			want: &api.Secret{
				Auth: &api.SecretAuth{
					Metadata: map[string]string{
						"role": "default",
					},
				},
			},
			tls:        true,
			wantErr:    false,
			cloneToken: true,
		},
		{
			name: "named-role",
			authLogin: &AuthLoginCert{
				AuthLoginCommon{
					authField: "baz",
					mount:     "qux",
					params: map[string]interface{}{
						consts.FieldName:          "bob",
						consts.FieldCertFile:      certFile,
						consts.FieldKeyFile:       keyFile,
						consts.FieldSkipTLSVerify: true,
					},
					initialized: true,
				},
			},
			handler: &testLoginHandler{
				handlerFunc: handlerFunc,
			},
			expectReqCount: 1,
			expectReqPaths: []string{
				"/v1/auth/qux/login",
			},
			expectReqParams: []map[string]interface{}{{
				consts.FieldName: "bob",
			}},
			want: &api.Secret{
				Auth: &api.SecretAuth{
					Metadata: map[string]string{
						"role": "bob",
					},
				},
			},
			tls:        true,
			wantErr:    false,
			cloneToken: true,
		},
		{
			name: "error-vault-token-set",
			authLogin: &AuthLoginCert{
				AuthLoginCommon{
					authField: "baz",
					mount:     "qux",
					params: map[string]interface{}{
						consts.FieldName:          "bob",
						consts.FieldCertFile:      certFile,
						consts.FieldKeyFile:       keyFile,
						consts.FieldSkipTLSVerify: true,
					},
					initialized: true,
				},
			},
			handler: &testLoginHandler{
				handlerFunc: handlerFunc,
			},
			token:      "foo",
			cloneToken: true,
			wantErr:    true,
			expectErr:  errors.New("vault login client has a token set"),
		},
		{
			name: "error-uninitialized",
			authLogin: &AuthLoginCert{
				AuthLoginCommon{
					initialized: false,
				},
			},
			handler: &testLoginHandler{
				handlerFunc: handlerFunc,
			},
			want:      nil,
			wantErr:   true,
			tls:       true,
			expectErr: authLoginInitCheckError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			testAuthLogin(t, tt)
		})
	}
}
