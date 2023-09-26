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
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const envVarTFAccOCIAuth = "TF_ACC_OCI_AUTH"

func TestAuthLoginOCI_Init(t *testing.T) {
	tests := []authLoginInitTest{
		{
			name:      "basic",
			authField: consts.FieldAuthLoginOCI,
			raw: map[string]interface{}{
				consts.FieldAuthLoginOCI: []interface{}{
					map[string]interface{}{
						consts.FieldNamespace: "ns1",
						consts.FieldRole:      "alice",
						consts.FieldAuthType:  ociAuthTypeAPIKeys,
					},
				},
			},
			expectParams: map[string]interface{}{
				consts.FieldNamespace: "ns1",
				consts.FieldMount:     consts.MountTypeOCI,
				consts.FieldRole:      "alice",
				consts.FieldAuthType:  ociAuthTypeAPIKeys,
			},
			wantErr: false,
		},
		{
			name:         "error-missing-resource",
			authField:    consts.FieldAuthLoginOCI,
			expectParams: nil,
			wantErr:      true,
			expectErr:    fmt.Errorf("resource data missing field %q", consts.FieldAuthLoginOCI),
		},
		{
			name:      "error-missing-required",
			authField: consts.FieldAuthLoginOCI,
			raw: map[string]interface{}{
				consts.FieldAuthLoginOCI: []interface{}{
					map[string]interface{}{
						consts.FieldRole: "alice",
					},
				},
			},
			expectParams: nil,
			wantErr:      true,
			expectErr: fmt.Errorf("required fields are unset: %v", []string{
				consts.FieldAuthType,
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := map[string]*schema.Schema{
				tt.authField: GetOCILoginSchema(tt.authField),
			}
			assertAuthLoginInit(t, tt, s, &AuthLoginOCI{})
		})
	}
}

func TestAuthLoginOCI_LoginPath(t *testing.T) {
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
			want: "auth/oci/login/alice",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginOCI{
				AuthLoginCommon: tt.fields.AuthLoginCommon,
			}
			if got := l.LoginPath(); got != tt.want {
				t.Errorf("LoginPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthLoginOCI_Login(t *testing.T) {
	handlerFunc := func(t *testLoginHandler, w http.ResponseWriter, req *http.Request) {
		params := t.params[len(t.params)-1]
		v, ok := params[consts.FieldRequestHeaders]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		reqHeaders, ok := v.(map[string]interface{})
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		metaData := make(map[string]string, len(reqHeaders))
		for k, v := range reqHeaders {
			metaData[k] = fmt.Sprintf("%d", len(v.([]interface{})))
		}
		m, err := json.Marshal(
			&api.Secret{
				Auth: &api.SecretAuth{
					Metadata: metaData,
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
			name: "api-keys",
			authLogin: &AuthLoginOCI{
				AuthLoginCommon: AuthLoginCommon{
					authField: consts.FieldAuthLoginOCI,
					params: map[string]interface{}{
						consts.FieldRole:     "alice",
						consts.FieldAuthType: ociAuthTypeAPIKeys,
					},
					initialized: true,
				},
			},
			handler: &testLoginHandler{
				handlerFunc: handlerFunc,
			},
			expectReqCount: 1,
			// validation is done in the request handler
			skipCheckReqParams: true,
			expectReqPaths:     []string{"/v1/auth/oci/login/alice"},
			skipFunc: func(t *testing.T) {
				testutil.SkipTestEnvUnset(t, envVarTFAccOCIAuth)
			},
			want: &api.Secret{
				Auth: &api.SecretAuth{
					// these are used to ensure that we received all the
					// required request headers they are not part of the real API.
					Metadata: map[string]string{
						"Accept":           "1",
						"Authorization":    "1",
						"Content-Length":   "1",
						"Content-Type":     "1",
						"Date":             "1",
						"Host":             "1",
						"Opc-Client-Info":  "1",
						"User-Agent":       "1",
						"(request-target)": "1",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "error-vault-token-set",
			authLogin: &AuthLoginOCI{
				AuthLoginCommon: AuthLoginCommon{
					authField: consts.FieldAuthLoginOCI,
					params: map[string]interface{}{
						consts.FieldRole:     "alice",
						consts.FieldAuthType: ociAuthTypeAPIKeys,
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
			authLogin: &AuthLoginOCI{
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
