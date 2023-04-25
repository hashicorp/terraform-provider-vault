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
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const envVarTFAccAzureAuth = "TF_ACC_AZURE_AUTH"

func TestAuthLoginAzure_Init(t *testing.T) {
	tests := []struct {
		name         string
		authField    string
		raw          map[string]interface{}
		wantErr      bool
		expectParams map[string]interface{}
		expectErr    error
	}{
		{
			name:      "basic",
			authField: consts.FieldAuthLoginAzure,
			raw: map[string]interface{}{
				consts.FieldAuthLoginAzure: []interface{}{
					map[string]interface{}{
						consts.FieldNamespace:         "ns1",
						consts.FieldRole:              "alice",
						consts.FieldJWT:               "jwt1",
						consts.FieldSubscriptionID:    "sub1",
						consts.FieldResourceGroupName: "res1",
						consts.FieldVMName:            "vm1",
					},
				},
			},
			expectParams: map[string]interface{}{
				consts.FieldNamespace:         "ns1",
				consts.FieldMount:             consts.MountTypeAzure,
				consts.FieldRole:              "alice",
				consts.FieldJWT:               "jwt1",
				consts.FieldSubscriptionID:    "sub1",
				consts.FieldResourceGroupName: "res1",
				consts.FieldVMName:            "vm1",
				consts.FieldVMSSName:          "",
				consts.FieldTenantID:          "",
				consts.FieldClientID:          "",
				consts.FieldScope:             defaultAzureScope,
			},
			wantErr: false,
		},
		{
			name:         "error-missing-resource",
			authField:    consts.FieldAuthLoginAzure,
			expectParams: nil,
			wantErr:      true,
			expectErr:    fmt.Errorf("resource data missing field %q", consts.FieldAuthLoginAzure),
		},
		{
			name:      "error-missing-required",
			authField: consts.FieldAuthLoginAzure,
			raw: map[string]interface{}{
				consts.FieldAuthLoginAzure: []interface{}{
					map[string]interface{}{
						consts.FieldRole: "alice",
					},
				},
			},
			expectParams: nil,
			wantErr:      true,
			expectErr: fmt.Errorf("required fields are unset: %v", []string{
				consts.FieldSubscriptionID,
				consts.FieldResourceGroupName,
			}),
		},
		{
			name:      "error-missing-one-of",
			authField: consts.FieldAuthLoginAzure,
			raw: map[string]interface{}{
				consts.FieldAuthLoginAzure: []interface{}{
					map[string]interface{}{
						consts.FieldRole:              "alice",
						consts.FieldSubscriptionID:    "sub1",
						consts.FieldResourceGroupName: "res1",
					},
				},
			},
			expectParams: nil,
			wantErr:      true,
			expectErr: fmt.Errorf("at least one field must be set: %v", []string{
				consts.FieldVMName,
				consts.FieldVMSSName,
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := map[string]*schema.Schema{
				tt.authField: GetAzureLoginSchema(tt.authField),
			}

			d := schema.TestResourceDataRaw(t, s, tt.raw)
			l := &AuthLoginAzure{}
			err := l.Init(d, tt.authField)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Init() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil {
				if tt.expectErr != nil {
					if !reflect.DeepEqual(tt.expectErr, err) {
						t.Errorf("Init() expected error %#v, actual %#v", tt.expectErr, err)
					}
				}
			} else {
				if !reflect.DeepEqual(tt.expectParams, l.params) {
					t.Errorf("Init() expected params %#v, actual %#v", tt.expectParams, l.params)
				}
			}
		})
	}
}

func TestAuthLoginAzure_LoginPath(t *testing.T) {
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
			want: "auth/azure/login",
		},
		{
			name: "other",
			fields: fields{
				AuthLoginCommon: AuthLoginCommon{
					mount: "other",
					params: map[string]interface{}{
						consts.FieldRole: "alice",
						consts.FieldJWT:  "jwt1",
					},
				},
			},
			want: "auth/other/login",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginAzure{
				AuthLoginCommon: tt.fields.AuthLoginCommon,
			}
			if got := l.LoginPath(); got != tt.want {
				t.Errorf("LoginPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthLoginAzure_Login(t *testing.T) {
	handlerFunc := func(t *testLoginHandler, w http.ResponseWriter, req *http.Request) {
		m, err := json.Marshal(
			&api.Secret{},
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
			name: "auth-with-jwt",
			authLogin: &AuthLoginAzure{
				AuthLoginCommon: AuthLoginCommon{
					authField: consts.FieldAuthLoginAzure,
					params: map[string]interface{}{
						consts.FieldRole:              "alice",
						consts.FieldJWT:               "jwt1",
						consts.FieldSubscriptionID:    "sub1",
						consts.FieldResourceGroupName: "res1",
						consts.FieldVMSSName:          "vmss1",
					},
					initialized: true,
				},
			},
			handler: &testLoginHandler{
				handlerFunc: handlerFunc,
			},
			expectReqCount:     1,
			expectReqPaths:     []string{"/v1/auth/azure/login"},
			skipCheckReqParams: true,
			expectReqParams: []map[string]interface{}{
				{
					consts.FieldRole:              "alice",
					consts.FieldJWT:               "jwt1",
					consts.FieldSubscriptionID:    "sub1",
					consts.FieldResourceGroupName: "res1",
				},
			},
			want:    &api.Secret{},
			wantErr: false,
		},
		{
			// TODO: extend this test once we are running in Azure.
			name: "auth-with-az-identity",
			authLogin: &AuthLoginAzure{
				AuthLoginCommon: AuthLoginCommon{
					authField: consts.FieldAuthLoginAzure,
					params: map[string]interface{}{
						consts.FieldRole:              "alice",
						consts.FieldSubscriptionID:    "sub1",
						consts.FieldResourceGroupName: "res1",
						consts.FieldVMSSName:          "vmss1",
					},
					initialized: true,
				},
			},
			handler: &testLoginHandler{
				handlerFunc: handlerFunc,
			},
			expectReqCount:     1,
			expectReqPaths:     []string{"/v1/auth/azure/login"},
			skipCheckReqParams: true,
			skipFunc: func(t *testing.T) {
				testutil.SkipTestEnvUnset(t, envVarTFAccAzureAuth)
			},
			want:    &api.Secret{},
			wantErr: false,
		},
		{
			name: "error-uninitialized",
			authLogin: &AuthLoginAzure{
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
			testAuthLogin(t, tt)
		})
	}
}
