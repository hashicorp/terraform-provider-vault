// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func TestAuthLoginUserPass_Init(t *testing.T) {
	tests := []authLoginInitTest{
		{
			name:      "basic",
			authField: consts.FieldAuthLoginUserpass,
			raw: map[string]interface{}{
				consts.FieldAuthLoginUserpass: []interface{}{
					map[string]interface{}{
						consts.FieldNamespace: "ns1",
						consts.FieldUsername:  "alice",
						consts.FieldPassword:  "password1",
					},
				},
			},
			expectParams: map[string]interface{}{
				consts.FieldNamespace:    "ns1",
				consts.FieldMount:        consts.MountTypeUserpass,
				consts.FieldUsername:     "alice",
				consts.FieldPassword:     "password1",
				consts.FieldPasswordFile: "",
			},
			wantErr: false,
		},
		{
			name:         "error-missing-resource",
			authField:    consts.FieldAuthLoginUserpass,
			expectParams: nil,
			wantErr:      true,
			expectErr:    fmt.Errorf("resource data missing field %q", consts.FieldAuthLoginUserpass),
		},
		{
			name:      "error-missing-required",
			authField: consts.FieldAuthLoginUserpass,
			raw: map[string]interface{}{
				consts.FieldAuthLoginUserpass: []interface{}{
					map[string]interface{}{},
				},
			},
			expectParams: nil,
			wantErr:      true,
			expectErr: fmt.Errorf("required fields are unset: %v", []string{
				consts.FieldUsername,
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := map[string]*schema.Schema{
				tt.authField: GetUserpassLoginSchema(tt.authField),
			}
			assertAuthLoginInit(t, tt, s, &AuthLoginUserpass{})
		})
	}
}

func Test_setupUserpassAuthParams(t *testing.T) {
	tests := []struct {
		name    string
		params  map[string]interface{}
		env     map[string]string
		wantErr bool
		want    map[string]interface{}
	}{
		{
			name: "password-file",
			params: map[string]interface{}{
				consts.FieldUsername:     "bob",
				consts.FieldPasswordFile: "",
			},
			want: map[string]interface{}{
				consts.FieldUsername: "bob",
				consts.FieldPassword: "foobar",
			},
			wantErr: false,
		},
		{
			name: "error-no-username",
			params: map[string]interface{}{
				"canary": "baz",
			},
			want: map[string]interface{}{
				"canary": "baz",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var filename string
			if _, ok := tt.params[consts.FieldPasswordFile]; ok {
				filename = path.Join(t.TempDir(), "password")
				tt.params[consts.FieldPasswordFile] = filename
			}

			if filename != "" {
				if err := ioutil.WriteFile(
					filename, []byte(tt.want[consts.FieldPassword].(string)), 0o440); err != nil {
					t.Fatal(err)
				}
			}

			if err := setupUserpassAuthParams(tt.params); (err != nil) != tt.wantErr {
				t.Errorf("setupUserpassAuthParams() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !reflect.DeepEqual(tt.want, tt.params) {
				t.Errorf("setupUserpassAuthParams() want = %v, actual %v", tt.want, tt.params)
			}
		})
	}
}

func TestAuthLoginUserpass_LoginPath(t *testing.T) {
	type fields struct {
		AuthLoginCommon AuthLoginCommon
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "basic",
			fields: fields{
				AuthLoginCommon{
					authField: "",
					mount:     "foo",
					params: map[string]interface{}{
						consts.FieldUsername: "bob",
					},
				},
			},
			want: "auth/foo/login/bob",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginUserpass{
				AuthLoginCommon: tt.fields.AuthLoginCommon,
			}
			if got := l.LoginPath(); got != tt.want {
				t.Errorf("LoginPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthLoginUserpass_Login(t *testing.T) {
	handlerFunc := func(t *testLoginHandler, w http.ResponseWriter, req *http.Request) {
		parts := strings.Split(req.URL.Path, "/")
		m, err := json.Marshal(
			&api.Secret{
				Auth: &api.SecretAuth{
					Metadata: map[string]string{
						"username": parts[len(parts)-1],
					},
				},
			},
		)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if _, err := w.Write(m); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	tests := []authLoginTest{
		{
			name: "basic",
			authLogin: &AuthLoginUserpass{
				AuthLoginCommon{
					authField: "baz",
					mount:     "foo",
					params: map[string]interface{}{
						consts.FieldUsername: "bob",
						consts.FieldPassword: "baz",
					},
					initialized: true,
				},
			},
			handler: &testLoginHandler{
				handlerFunc: handlerFunc,
			},
			expectReqCount: 1,
			expectReqPaths: []string{
				"/v1/auth/foo/login/bob",
			},
			expectReqParams: []map[string]interface{}{
				{
					consts.FieldUsername: "bob",
					consts.FieldPassword: "baz",
				},
			},
			want: &api.Secret{
				Auth: &api.SecretAuth{
					Metadata: map[string]string{
						"username": "bob",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "error-vault-token-set",
			authLogin: &AuthLoginUserpass{
				AuthLoginCommon{
					authField: "baz",
					mount:     "foo",
					params: map[string]interface{}{
						consts.FieldUsername: "bob",
						consts.FieldPassword: "baz",
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
			name: "error-no-username",
			authLogin: &AuthLoginUserpass{
				AuthLoginCommon{
					authField: "baz",
					mount:     "foo",
					params: map[string]interface{}{
						consts.FieldPassword: "baz",
					},
					initialized: true,
				},
			},
			handler: &testLoginHandler{
				handlerFunc: handlerFunc,
			},
			expectReqCount:  0,
			expectReqPaths:  nil,
			expectReqParams: nil,
			want:            nil,
			wantErr:         true,
		},
		{
			name: "error-uninitialized",
			authLogin: &AuthLoginUserpass{
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
