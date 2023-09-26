// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func TestAuthLoginJWT_Init(t *testing.T) {
	tests := []authLoginInitTest{
		{
			name:      "basic",
			authField: consts.FieldAuthLoginJWT,
			raw: map[string]interface{}{
				consts.FieldAuthLoginJWT: []interface{}{
					map[string]interface{}{
						consts.FieldNamespace: "ns1",
						consts.FieldRole:      "alice",
						consts.FieldJWT:       "jwt1",
					},
				},
			},
			expectParams: map[string]interface{}{
				consts.FieldNamespace: "ns1",
				consts.FieldMount:     consts.MountTypeJWT,
				consts.FieldRole:      "alice",
				consts.FieldJWT:       "jwt1",
			},
			wantErr: false,
		},
		{
			name:         "error-missing-resource",
			authField:    consts.FieldAuthLoginJWT,
			expectParams: nil,
			wantErr:      true,
			expectErr:    fmt.Errorf("resource data missing field %q", consts.FieldAuthLoginJWT),
		},
		{
			name:      "error-missing-required",
			authField: consts.FieldAuthLoginJWT,
			raw: map[string]interface{}{
				consts.FieldAuthLoginJWT: []interface{}{
					map[string]interface{}{
						consts.FieldRole: "alice",
					},
				},
			},
			expectParams: nil,
			wantErr:      true,
			expectErr: fmt.Errorf("required fields are unset: %v", []string{
				consts.FieldJWT,
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := map[string]*schema.Schema{
				tt.authField: GetJWTLoginSchema(tt.authField),
			}
			assertAuthLoginInit(t, tt, s, &AuthLoginJWT{})
		})
	}
}

func TestAuthLoginJWT_LoginPath(t *testing.T) {
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
						consts.FieldJWT:  "jwt1",
					},
				},
			},
			want: "auth/jwt/login",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginJWT{
				AuthLoginCommon: tt.fields.AuthLoginCommon,
			}
			if got := l.LoginPath(); got != tt.want {
				t.Errorf("LoginPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthLoginJWT_Login(t *testing.T) {
	handlerFunc := func(t *testLoginHandler, w http.ResponseWriter, req *http.Request) {
		m, err := json.Marshal(
			&api.Secret{
				Data: map[string]interface{}{
					"auth_login": "jwt",
				},
			},
		)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(m); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	tests := []authLoginTest{
		{
			name: "basic",
			authLogin: &AuthLoginJWT{
				AuthLoginCommon: AuthLoginCommon{
					authField: consts.FieldAuthLoginJWT,
					params: map[string]interface{}{
						consts.FieldRole: "alice",
						consts.FieldJWT:  "jwt1",
					},
					initialized: true,
				},
			},
			handler: &testLoginHandler{
				handlerFunc: handlerFunc,
			},
			expectReqCount: 1,
			expectReqPaths: []string{"/v1/auth/jwt/login"},
			expectReqParams: []map[string]interface{}{
				{
					consts.FieldRole: "alice",
					consts.FieldJWT:  "jwt1",
				},
			},
			want: &api.Secret{
				Data: map[string]interface{}{
					"auth_login": "jwt",
				},
			},
			wantErr: false,
		},
		{
			name: "error-vault-token-set",
			authLogin: &AuthLoginJWT{
				AuthLoginCommon: AuthLoginCommon{
					authField: consts.FieldAuthLoginJWT,
					params: map[string]interface{}{
						consts.FieldRole: "alice",
						consts.FieldJWT:  "jwt1",
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
			authLogin: &AuthLoginJWT{
				AuthLoginCommon: AuthLoginCommon{
					initialized: false,
				},
			},
			handler: &testLoginHandler{
				handlerFunc: handlerFunc,
			},
			expectReqCount: 0,
			want:           nil,
			wantErr:        true,
			expectErr:      authLoginInitCheckError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			testAuthLogin(t, tt)
		})
	}
}
