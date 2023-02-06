// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const envVarGCPServiceAccount = "TF_ACC_GOOGLE_SERVICE_ACCOUNT"

func TestAuthLoginGCP_Init(t *testing.T) {
	type fields struct {
		AuthLoginCommon AuthLoginCommon
	}

	s := map[string]*schema.Schema{}

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
			name:         "error-missing-resource",
			authField:    consts.FieldAuthLoginGCP,
			expectParams: nil,
			wantErr:      true,
			expectErr:    fmt.Errorf("resource data missing field %q", consts.FieldAuthLoginGCP),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s[tt.authField] = GetGCPLoginSchema(tt.authField)
			t.Cleanup(func() {
				delete(s, tt.authField)
			})

			d := schema.TestResourceDataRaw(t, s, tt.raw)
			l := &AuthLoginGCP{}

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

func TestAuthLoginGCP_LoginPath(t *testing.T) {
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
			want: "auth/gcp/login",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginGCP{
				AuthLoginCommon: tt.fields.AuthLoginCommon,
			}
			if got := l.LoginPath(); got != tt.want {
				t.Errorf("LoginPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthLoginGCP_Login(t *testing.T) {
	handlerFunc := func(t *testLoginHandler, w http.ResponseWriter, req *http.Request) {
		role := "default"
		params := t.params[len(t.params)-1]
		if v, ok := params[consts.FieldRole]; ok {
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
			name: "role-jwt",
			authLogin: &AuthLoginGCP{
				AuthLoginCommon{
					authField: "baz",
					mount:     "qux",
					params: map[string]interface{}{
						consts.FieldJWT:  "jwt",
						consts.FieldRole: "bob",
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
				consts.FieldJWT:  "jwt",
				consts.FieldRole: "bob",
			}},
			want: &api.Secret{
				Auth: &api.SecretAuth{
					Metadata: map[string]string{
						consts.FieldRole: "bob",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "role-credentials",
			authLogin: &AuthLoginGCP{
				AuthLoginCommon{
					authField: "baz",
					mount:     "qux",
					params: map[string]interface{}{
						consts.FieldRole:           "bob",
						consts.FieldCredentials:    os.Getenv(consts.EnvVarGoogleApplicationCreds),
						consts.FieldServiceAccount: os.Getenv(envVarGCPServiceAccount),
					},
					initialized: true,
				},
			},
			handler: &testLoginHandler{
				excludeParams: []string{consts.FieldJWT},
				handlerFunc:   handlerFunc,
			},
			expectReqCount: 1,
			expectReqPaths: []string{
				"/v1/auth/qux/login",
			},
			expectReqParams: []map[string]interface{}{{
				consts.FieldRole: "bob",
			}},
			want: &api.Secret{
				Auth: &api.SecretAuth{
					Metadata: map[string]string{
						consts.FieldRole: "bob",
					},
				},
			},
			wantErr: false,
			skipFunc: func(t *testing.T) {
				testutil.SkipTestEnvUnset(t, consts.EnvVarGoogleApplicationCreds, envVarGCPServiceAccount)
			},
		},
		{
			name: "no-jwt",
			authLogin: &AuthLoginGCP{
				AuthLoginCommon{
					authField: "baz",
					params:    map[string]interface{}{},
				},
			},
			handler: &testLoginHandler{
				handlerFunc: handlerFunc,
			},
			expectReqCount:  0,
			expectReqParams: nil,
			want:            nil,
			wantErr:         true,
		},
		{
			name: "error-uninitialized",
			authLogin: &AuthLoginGCP{
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
