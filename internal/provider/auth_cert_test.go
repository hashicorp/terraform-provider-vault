// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func TestAuthLoginCert_Init(t *testing.T) {
	type fields struct {
		AuthLoginCommon AuthLoginCommon
	}

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

	tests := []struct {
		name         string
		authField    string
		raw          map[string]interface{}
		wantErr      bool
		expectMount  string
		expectParams map[string]interface{}
		expectErr    error
	}{
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
				consts.FieldNamespace:  "",
				consts.FieldMount:      consts.MountTypeCert,
				consts.FieldName:       "",
				consts.FieldCACertFile: "ca.crt",
				consts.FieldCertFile:   "cert.crt",
				consts.FieldKeyFile:    "cert.key",
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
				consts.FieldNamespace: "",
				consts.FieldMount:     consts.MountTypeCert,
				consts.FieldName:      "bob",
				consts.FieldCertFile:  "cert.crt",
				consts.FieldKeyFile:   "cert.key",
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
				consts.FieldNamespace:  "ns1",
				consts.FieldMount:      consts.MountTypeCert,
				consts.FieldName:       "",
				consts.FieldCACertFile: "ca.crt",
				consts.FieldCertFile:   "cert.crt",
				consts.FieldKeyFile:    "cert.key",
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
				consts.FieldCACertDir:     "/foo/baz",
				consts.FieldSkipTLSVerify: true,
				consts.FieldTLSServerName: "baz.biff",
				consts.FieldNamespace:     "ns1",
				consts.FieldMount:         "cert1",
				consts.FieldName:          "bob",
				consts.FieldCACertFile:    "ca.crt",
				consts.FieldCertFile:      "cert.crt",
				consts.FieldKeyFile:       "cert.key",
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

			d := schema.TestResourceDataRaw(t, s, tt.raw)
			l := &AuthLoginCert{}

			err := l.Init(d, tt.authField)
			if (err != nil) != tt.wantErr {
				t.Errorf("Init() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !reflect.DeepEqual(tt.expectErr, err) {
				t.Errorf("Init() expected error %#v, actual %#v", tt.expectErr, err)
			}

			if !reflect.DeepEqual(tt.expectParams, l.params) {
				t.Errorf("Init() expected params %#v, actual %#v", tt.expectParams, l.params)
			}
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
	handlerFunc := func(t *testLoginHandler, w http.ResponseWriter, req *http.Request) {
		role := "default"
		if v, ok := t.params[len(t.params)-1][consts.FieldName]; ok {
			role = v.(string)
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

	tests := []authLoginTest{
		{
			name: "default",
			authLogin: &AuthLoginCert{
				AuthLoginCommon{
					authField:   "baz",
					params:      map[string]interface{}{},
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
			expectReqParams: []map[string]interface{}{{}},
			want: &api.Secret{
				Auth: &api.SecretAuth{
					Metadata: map[string]string{
						"role": "default",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "named-role",
			authLogin: &AuthLoginCert{
				AuthLoginCommon{
					authField: "baz",
					mount:     "qux",
					params: map[string]interface{}{
						consts.FieldName: "bob",
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
			wantErr: false,
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
			expectErr: authLoginInitCheckError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testAuthLogin(t, tt)
		})
	}
}
