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

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func TestAuthLoginAWS_Init(t *testing.T) {
	tests := []authLoginInitTest{
		{
			name:      "basic",
			authField: consts.FieldAuthLoginAWS,
			raw: map[string]interface{}{
				consts.FieldAuthLoginAWS: []interface{}{
					map[string]interface{}{
						consts.FieldNamespace:                "ns1",
						consts.FieldRole:                     "alice",
						consts.FieldAWSAccessKeyID:           "key-id",
						consts.FieldAWSSecretAccessKey:       "sa-key",
						consts.FieldAWSSessionToken:          "session-token",
						consts.FieldAWSIAMEndpoint:           "iam.us-east-2.amazonaws.com",
						consts.FieldAWSSTSEndpoint:           "sts.us-east-2.amazonaws.com",
						consts.FieldAWSRegion:                "us-east-2",
						consts.FieldAWSSharedCredentialsFile: "credentials",
						consts.FieldAWSProfile:               "profile1",
						consts.FieldAWSRoleARN:               "role-arn",
						consts.FieldAWSRoleSessionName:       "session1",
						consts.FieldAWSWebIdentityTokenFile:  "web-token",
						consts.FieldHeaderValue:              "header1",
					},
				},
			},
			expectParams: map[string]interface{}{
				consts.FieldNamespace:                "ns1",
				consts.FieldUseRootNamespace:         false,
				consts.FieldRole:                     "alice",
				consts.FieldMount:                    consts.MountTypeAWS,
				consts.FieldAWSAccessKeyID:           "key-id",
				consts.FieldAWSSecretAccessKey:       "sa-key",
				consts.FieldAWSSessionToken:          "session-token",
				consts.FieldAWSIAMEndpoint:           "iam.us-east-2.amazonaws.com",
				consts.FieldAWSSTSEndpoint:           "sts.us-east-2.amazonaws.com",
				consts.FieldAWSRegion:                "us-east-2",
				consts.FieldAWSSharedCredentialsFile: "credentials",
				consts.FieldAWSProfile:               "profile1",
				consts.FieldAWSRoleARN:               "role-arn",
				consts.FieldAWSRoleSessionName:       "session1",
				consts.FieldAWSWebIdentityTokenFile:  "web-token",
				consts.FieldHeaderValue:              "header1",
			},
			wantErr: false,
		},
		{
			name:         "error-missing-resource",
			authField:    consts.FieldAuthLoginAWS,
			expectParams: nil,
			wantErr:      true,
			expectErr:    fmt.Errorf("resource data missing field %q", consts.FieldAuthLoginAWS),
		},
		{
			name:      "error-missing-required",
			authField: consts.FieldAuthLoginAWS,
			raw: map[string]interface{}{
				consts.FieldAuthLoginAWS: []interface{}{
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
				tt.authField: GetAWSLoginSchema(tt.authField),
			}
			assertAuthLoginInit(t, tt, s, &AuthLoginAWS{})
		})
	}
}

func TestAuthLoginAWS_LoginPath(t *testing.T) {
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
			want: "auth/aws/login",
		},
		{
			name: "other",
			fields: fields{
				AuthLoginCommon: AuthLoginCommon{
					mount: "other",
					params: map[string]interface{}{
						consts.FieldRole: "alice",
					},
				},
			},
			want: "auth/other/login",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginAWS{
				AuthLoginCommon: tt.fields.AuthLoginCommon,
			}
			if got := l.LoginPath(); got != tt.want {
				t.Errorf("LoginPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthLoginAWS_getCredentialsConfig(t *testing.T) {
	type fields struct {
		AuthLoginCommon AuthLoginCommon
	}
	tests := []struct {
		name    string
		fields  fields
		logger  hclog.Logger
		want    *awsutil.CredentialsConfig
		wantErr bool
	}{
		{
			name: "static-creds",
			fields: fields{
				AuthLoginCommon: AuthLoginCommon{
					params: map[string]interface{}{
						consts.FieldAWSAccessKeyID:     "key-id",
						consts.FieldAWSSecretAccessKey: "sa-key",
					},
				},
			},
			logger: hclog.NewNullLogger(),
			want: &awsutil.CredentialsConfig{
				Region:    "us-east-1",
				AccessKey: "key-id",
				SecretKey: "sa-key",
			},
			wantErr: false,
		},
		{
			name: "static-creds-with-profile",
			fields: fields{
				AuthLoginCommon: AuthLoginCommon{
					params: map[string]interface{}{
						consts.FieldAWSSharedCredentialsFile: "credentials",
						consts.FieldAWSProfile:               "profile1",
					},
				},
			},
			logger: hclog.NewNullLogger(),
			want: &awsutil.CredentialsConfig{
				Region:   "us-east-1",
				Filename: "credentials",
				Profile:  "profile1",
			},
			wantErr: false,
		},
		{
			name: "all",
			fields: fields{
				AuthLoginCommon: AuthLoginCommon{
					params: map[string]interface{}{
						consts.FieldAWSAccessKeyID:           "key-id",
						consts.FieldAWSSecretAccessKey:       "sa-key",
						consts.FieldAWSSessionToken:          "session-token",
						consts.FieldAWSIAMEndpoint:           "iam.us-east-2.amazonaws.com",
						consts.FieldAWSSTSEndpoint:           "sts.us-east-2.amazonaws.com",
						consts.FieldAWSRegion:                "us-east-2",
						consts.FieldAWSSharedCredentialsFile: "credentials",
						consts.FieldAWSProfile:               "profile1",
						consts.FieldAWSRoleARN:               "role-arn",
						consts.FieldAWSRoleSessionName:       "session1",
						consts.FieldAWSWebIdentityTokenFile:  "web-token",
					},
				},
			},
			logger: hclog.NewNullLogger(),
			want: &awsutil.CredentialsConfig{
				AccessKey:            "key-id",
				SecretKey:            "sa-key",
				SessionToken:         "session-token",
				IAMEndpoint:          "iam.us-east-2.amazonaws.com",
				STSEndpoint:          "sts.us-east-2.amazonaws.com",
				Region:               "us-east-2",
				Filename:             "credentials",
				Profile:              "profile1",
				RoleARN:              "role-arn",
				RoleSessionName:      "session1",
				WebIdentityTokenFile: "web-token",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginAWS{
				AuthLoginCommon: tt.fields.AuthLoginCommon,
			}
			got, err := l.getCredentialsConfig(tt.logger)
			if (err != nil) != tt.wantErr {
				t.Errorf("getCredentialsConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got.HTTPClient == nil {
				t.Errorf("getCredentialsConfig() HTTPClient not initialized")
			}
			// set HTTPClient to nil
			got.HTTPClient = nil
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getCredentialsConfig() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthLoginAWS_Login(t *testing.T) {
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
			name: "error-uninitialized",
			authLogin: &AuthLoginAWS{
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
		{
			name: "error-vault-token-set",
			authLogin: &AuthLoginAWS{
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			testAuthLogin(t, tt)
		})
	}
}
