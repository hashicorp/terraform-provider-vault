// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	jwtauth "github.com/hashicorp/vault-plugin-auth-jwt"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func TestAuthLoginOIDC_Init(t *testing.T) {
	tests := []authLoginInitTest{
		{
			name:      "basic",
			authField: consts.FieldAuthLoginOIDC,
			raw: map[string]interface{}{
				consts.FieldAuthLoginOIDC: []interface{}{
					map[string]interface{}{
						consts.FieldNamespace: "ns1",
						consts.FieldRole:      "alice",
					},
				},
			},
			expectParams: map[string]interface{}{
				consts.FieldNamespace:               "ns1",
				consts.FieldUseRootNamespace:        false,
				consts.FieldMount:                   consts.MountTypeOIDC,
				consts.FieldRole:                    "alice",
				consts.FieldCallbackListenerAddress: "",
				consts.FieldCallbackAddress:         "",
			},
			wantErr: false,
		},
		{
			name:         "error-missing-resource",
			authField:    consts.FieldAuthLoginOIDC,
			expectParams: nil,
			wantErr:      true,
			expectErr:    fmt.Errorf("resource data missing field %q", consts.FieldAuthLoginOIDC),
		},
		{
			name:      "error-missing-required",
			authField: consts.FieldAuthLoginOIDC,
			raw: map[string]interface{}{
				consts.FieldAuthLoginOIDC: []interface{}{
					map[string]interface{}{},
				},
			},
			expectParams: nil,
			wantErr:      true,
			expectErr: fmt.Errorf("required fields are unset: %v", []string{
				consts.FieldRole,
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := map[string]*schema.Schema{
				tt.authField: GetOIDCLoginSchema(tt.authField),
			}
			assertAuthLoginInit(t, tt, s, &AuthLoginOIDC{})
		})
	}
}

func TestAuthLoginOIDC_LoginPath(t *testing.T) {
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
				AuthLoginCommon: AuthLoginCommon{
					params: map[string]interface{}{
						consts.FieldRole: "alice",
					},
				},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginOIDC{
				AuthLoginCommon: tt.fields.AuthLoginCommon,
			}
			if got := l.LoginPath(); got != tt.want {
				t.Errorf("LoginPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthLoginOIDC_getAuthParams(t *testing.T) {
	tests := []struct {
		name      string
		params    map[string]interface{}
		want      map[string]string
		expectErr error
		wantErr   bool
	}{
		{
			name: "listener-addr-only",
			params: map[string]interface{}{
				consts.FieldRole:                    "alice",
				consts.FieldCallbackListenerAddress: "tcp://localhost:55000",
				consts.FieldCallbackAddress:         "",
			},
			want: map[string]string{
				consts.FieldMount:          consts.MountTypeOIDC,
				consts.FieldRole:           "alice",
				jwtauth.FieldSkipBrowser:   "false",
				jwtauth.FieldListenAddress: "localhost",
				jwtauth.FieldPort:          "55000",
				jwtauth.FieldAbortOnError:  "true",
			},
			wantErr: false,
		},
		{
			name: "callback-addr-only",
			params: map[string]interface{}{
				consts.FieldRole:            "alice",
				consts.FieldCallbackAddress: "http://127.0.0.1:55001",
			},
			want: map[string]string{
				consts.FieldMount:           consts.MountTypeOIDC,
				consts.FieldRole:            "alice",
				jwtauth.FieldSkipBrowser:    "false",
				jwtauth.FieldCallbackHost:   "127.0.0.1",
				jwtauth.FieldCallbackPort:   "55001",
				jwtauth.FieldCallbackMethod: "http",
				jwtauth.FieldAbortOnError:   "true",
			},
			wantErr: false,
		},
		{
			name: "both-addrs",
			params: map[string]interface{}{
				consts.FieldRole:                    "alice",
				consts.FieldCallbackListenerAddress: "tcp://localhost:55000",
				consts.FieldCallbackAddress:         "http://127.0.0.1:55001",
			},
			want: map[string]string{
				consts.FieldMount:           consts.MountTypeOIDC,
				consts.FieldRole:            "alice",
				jwtauth.FieldSkipBrowser:    "false",
				jwtauth.FieldAbortOnError:   "true",
				jwtauth.FieldListenAddress:  "localhost",
				jwtauth.FieldPort:           "55000",
				jwtauth.FieldCallbackHost:   "127.0.0.1",
				jwtauth.FieldCallbackPort:   "55001",
				jwtauth.FieldCallbackMethod: "http",
			},
			wantErr: false,
		},
		{
			name: "error-no-role",
			params: map[string]interface{}{
				consts.FieldCallbackListenerAddress: "tcp://localhost:55000",
				consts.FieldCallbackAddress:         "http://127.0.0.1:55001",
			},
			want:      nil,
			wantErr:   true,
			expectErr: fmt.Errorf("%q is not set", consts.FieldRole),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginOIDC{
				AuthLoginCommon: AuthLoginCommon{
					params:      tt.params,
					initialized: true,
				},
			}
			got, err := l.getAuthParams()
			if (err != nil) != tt.wantErr {
				t.Errorf("getAuthParams() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(err, tt.expectErr) {
				t.Errorf("getAuthParams() gotErr = %v, wantErr %v", err, tt.expectErr)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getAuthParams() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthLoginOIDC_Login(t *testing.T) {
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
			name: "error-vault-token-set",
			authLogin: &AuthLoginOIDC{
				AuthLoginCommon{
					authField: "baz",
					mount:     "foo",
					params: map[string]interface{}{
						consts.FieldRole: "bob",
					},
					initialized: true,
				},
			},
			handler: &testLoginHandler{
				handlerFunc: handlerFunc,
			},
			token:     "foo",
			wantErr:   true,
			expectErr: errors.New("vault login client has a token set"),
		},
		{
			name: "error-uninitialized",
			authLogin: &AuthLoginOIDC{
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
			t.Parallel()
			testAuthLogin(t, tt)
		})
	}
}
