// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	krbauth "github.com/hashicorp/vault-plugin-auth-kerberos"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

const (
	// base64 encoded SPNEGO request token
	testNegTokenInit = "oIICqjCCAqagJzAlBgkqhkiG9xIBAgIGBSsFAQUCBgkqhkiC9xIBAgIGBisGAQUCBaKCAnkEggJ1YIICcQYJKoZIhvcSAQICAQBuggJgMIICXKADAgEFoQMCAQ6iBwMFAAAAAACjggFwYYIBbDCCAWigAwIBBaENGwtURVNULkdPS1JCNaIjMCGgAwIBA6EaMBgbBEhUVFAbEGhvc3QudGVzdC5nb2tyYjWjggErMIIBJ6ADAgESoQMCAQKiggEZBIIBFdS9iQq8RW9E4uei6BEb1nZ6vwMmbfzal8Ypry7ORQpa4fFF5KTRvCyEjmamxrMdl0CyawPNvSVwv88SbpCt9fXrzp4oP/UIbaR7EpsU/Aqr1NHfnB88crgMxhTfwoeDRQsse3dJZR9DK0eqov8VjABmt1fz+wDde09j1oJ2x2Nz7N0/GcZuvEOoHld/PCY7h4NW9X6NbE7M1Ye4FTjnA5LPfnP8Eqb3xTeolKe7VWbIOsTWl1eqMgpR2NaQAXrr+VKt0Yia38Mwew5s2Mm1fPhYn75SgArLZGHCVHPUn6ob3OuLzj9h2yP5zWoJ1a3OtBHhxFRrMLMzMeVw/WvFCqQDVX519IjnWXUOoDiqtkVGZ9m2T0GkgdIwgc+gAwIBEqKBxwSBxNZ7oq5M9dkXyqsdhjYFJJMg6QSCVjZi7ZJAilQ7atXt64+TdekGCiBUkd8IL9Kl/sk9+3b0EBK7YMriDwetu3ehqlbwUh824eoQ3J+3YpArJU3XZk0LzG91HyAD5BmQrxtDMNEEd7+tY4ufC3BKyAzEdzH47I2AF2K62IhLjekK2x2+f8ew/6/Tj7Xri2VHzuMNiYcygc5jrXAEKhNHixp8K93g8iOs5i27hOLQbxBw9CZfZuBUREkzXi/MTQruW/gcWZk="
	// base64 encoded response token
	testNegTokenResp = "oRQwEqADCgEAoQsGCSqGSIb3EgECAg=="
)

func TestAuthLoginKerberos_Init(t *testing.T) {
	tests := []authLoginInitTest{
		{
			name: "with-token",
			raw: map[string]interface{}{
				consts.FieldAuthLoginKerberos: []interface{}{
					map[string]interface{}{
						consts.FieldToken: testNegTokenInit,
					},
				},
			},
			authField: consts.FieldAuthLoginKerberos,
			expectParams: map[string]interface{}{
				consts.FieldToken:                  testNegTokenInit,
				consts.FieldNamespace:              "",
				consts.FieldMount:                  consts.MountTypeKerberos,
				consts.FieldUsername:               "",
				consts.FieldService:                "",
				consts.FieldRealm:                  "",
				consts.FieldKeytabPath:             "",
				consts.FieldKRB5ConfPath:           "",
				consts.FieldRemoveInstanceName:     false,
				consts.FieldDisableFastNegotiation: false,
			},
			wantErr: false,
		},
		{
			name:         "error-missing-resource",
			authField:    consts.FieldAuthLoginKerberos,
			expectParams: nil,
			wantErr:      true,
			expectErr:    fmt.Errorf("resource data missing field %q", consts.FieldAuthLoginKerberos),
		},
		{
			name: "error-missing-required",
			raw: map[string]interface{}{
				consts.FieldAuthLoginKerberos: []interface{}{
					map[string]interface{}{
						consts.FieldUsername: "alice",
					},
				},
			},
			authField:    consts.FieldAuthLoginKerberos,
			expectParams: nil,
			wantErr:      true,
			expectErr: fmt.Errorf("required fields are unset: %v", []string{
				consts.FieldService,
				consts.FieldRealm,
				consts.FieldKeytabPath,
				consts.FieldKRB5ConfPath,
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := map[string]*schema.Schema{
				tt.authField: GetKerberosLoginSchema(tt.authField),
			}
			assertAuthLoginInit(t, tt, s, &AuthLoginKerberos{})
		})
	}
}

func TestAuthLoginKerberos_LoginPath(t *testing.T) {
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
			want: "auth/kerberos/login",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginKerberos{
				AuthLoginCommon: tt.fields.AuthLoginCommon,
			}
			if got := l.LoginPath(); got != tt.want {
				t.Errorf("LoginPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthLoginKerberos_Login(t *testing.T) {
	handlerFunc := func(t *testLoginHandler, w http.ResponseWriter, req *http.Request) {
		m, err := json.Marshal(
			&api.Secret{
				Data: map[string]interface{}{
					"auth_login": "kerberos",
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

	getTestAuthHeaderFunc := func(expectConfig *krbauth.LoginCfg) func(c *krbauth.LoginCfg) (string, error) {
		return func(c *krbauth.LoginCfg) (string, error) {
			if expectConfig != nil {
				if !reflect.DeepEqual(expectConfig, c) {
					return "", fmt.Errorf("validateKRBNegToken() got = %v, want %v", c, expectConfig)
				}
			}
			return fmt.Sprintf("Negotiate %s", testNegTokenInit), nil
		}
	}

	tests := []authLoginTest{
		{
			name: "with-token",
			authLogin: &AuthLoginKerberos{
				AuthLoginCommon: AuthLoginCommon{
					authField: consts.FieldAuthLoginKerberos,
					params: map[string]interface{}{
						consts.FieldToken: testNegTokenInit,
					},
					initialized: true,
				},
			},
			handler: &testLoginHandler{
				handlerFunc: handlerFunc,
			},
			expectReqCount: 1,
			expectReqPaths: []string{"/v1/auth/kerberos/login"},
			expectReqParams: []map[string]interface{}{
				{
					consts.FieldAuthorization: fmt.Sprintf("Negotiate %s", testNegTokenInit),
				},
			},
			want: &api.Secret{
				Data: map[string]interface{}{
					"auth_login": "kerberos",
				},
			},
			wantErr: false,
		},
		{
			name: "no-token",
			authLogin: &AuthLoginKerberos{
				authHeaderFunc: getTestAuthHeaderFunc(&krbauth.LoginCfg{
					Username:               "alice",
					Service:                "service1",
					Realm:                  "realm1",
					KeytabPath:             "/etc/kerberos/keytab",
					Krb5ConfPath:           "/etc/kerberos/krb5.conf",
					DisableFASTNegotiation: true,
					RemoveInstanceName:     false,
				}),
				AuthLoginCommon: AuthLoginCommon{
					authField: consts.FieldAuthLoginKerberos,
					params: map[string]interface{}{
						consts.FieldUsername:               "alice",
						consts.FieldService:                "service1",
						consts.FieldRealm:                  "realm1",
						consts.FieldKeytabPath:             "/etc/kerberos/keytab",
						consts.FieldKRB5ConfPath:           "/etc/kerberos/krb5.conf",
						consts.FieldDisableFastNegotiation: true,
						consts.FieldRemoveInstanceName:     false,
					},
					initialized: true,
				},
			},
			handler: &testLoginHandler{
				handlerFunc: handlerFunc,
			},
			expectReqCount: 1,
			expectReqPaths: []string{"/v1/auth/kerberos/login"},
			expectReqParams: []map[string]interface{}{
				{
					consts.FieldAuthorization: fmt.Sprintf("Negotiate %s", testNegTokenInit),
				},
			},
			want: &api.Secret{
				Data: map[string]interface{}{
					"auth_login": "kerberos",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testAuthLogin(t, tt)
		})
	}
}

func Test_validateKRBNegToken(t *testing.T) {
	tests := []struct {
		name       string
		v          interface{}
		s          string
		want       []string
		wantErrors []error
	}{
		{
			name:       "basic",
			v:          testNegTokenInit,
			want:       nil,
			wantErrors: nil,
		},
		{
			name: "error-b64-decoding",
			v:    "Negotiation foo",
			want: nil,
			wantErrors: []error{
				fmt.Errorf(
					"failed to decode token, err=%w", base64.CorruptInputError(11)),
			},
		},
		{
			name: "error-unmarshal",
			v:    base64.StdEncoding.EncodeToString([]byte(testNegTokenInit)),
			want: nil,
			wantErrors: []error{
				fmt.Errorf(
					"failed to unmarshal token, err=%w",
					fmt.Errorf("unknown choice type for NegotiationToken")),
			},
		},
		{
			name:       "error-not-init-token",
			v:          testNegTokenResp,
			want:       nil,
			wantErrors: []error{fmt.Errorf("not an initialization token")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := validateKRBNegToken(tt.v, tt.s)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("validateKRBNegToken() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.wantErrors) {
				t.Errorf("validateKRBNegToken() got1 = %v, want %v", got1, tt.wantErrors)
			}
		})
	}
}
