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

func TestAuthLoginRadius_Init(t *testing.T) {
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
			authField: consts.FieldAuthLoginRadius,
			raw: map[string]interface{}{
				consts.FieldAuthLoginRadius: []interface{}{
					map[string]interface{}{
						consts.FieldNamespace: "ns1",
						consts.FieldUsername:  "alice",
						consts.FieldPassword:  "password1",
					},
				},
			},
			expectParams: map[string]interface{}{
				consts.FieldNamespace: "ns1",
				consts.FieldMount:     consts.MountTypeRadius,
				consts.FieldUsername:  "alice",
				consts.FieldPassword:  "password1",
			},
			wantErr: false,
		},
		{
			name:         "error-missing-resource",
			authField:    consts.FieldAuthLoginRadius,
			expectParams: nil,
			wantErr:      true,
			expectErr:    fmt.Errorf("resource data missing field %q", consts.FieldAuthLoginRadius),
		},
		{
			name:      "error-missing-required",
			authField: consts.FieldAuthLoginRadius,
			raw: map[string]interface{}{
				consts.FieldAuthLoginRadius: []interface{}{
					map[string]interface{}{
						consts.FieldUsername: "alice",
					},
				},
			},
			expectParams: nil,
			wantErr:      true,
			expectErr: fmt.Errorf("required fields are unset: %v", []string{
				consts.FieldPassword,
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := map[string]*schema.Schema{
				tt.authField: GetRadiusLoginSchema(tt.authField),
			}

			d := schema.TestResourceDataRaw(t, s, tt.raw)
			l := &AuthLoginRadius{}
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

func TestAuthLoginRadius_LoginPath(t *testing.T) {
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
						consts.FieldUsername: "alice",
						consts.FieldPassword: "password1",
					},
				},
			},
			want: "auth/radius/login",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginRadius{
				AuthLoginCommon: tt.fields.AuthLoginCommon,
			}
			if got := l.LoginPath(); got != tt.want {
				t.Errorf("LoginPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthLoginRadius_Login(t *testing.T) {
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
			name: "basic",
			authLogin: &AuthLoginRadius{
				AuthLoginCommon: AuthLoginCommon{
					authField: consts.FieldAuthLoginRadius,
					params: map[string]interface{}{
						consts.FieldUsername: "alice",
						consts.FieldPassword: "password1",
					},
					initialized: true,
				},
			},
			handler: &testLoginHandler{
				handlerFunc: handlerFunc,
			},
			expectReqCount: 1,
			expectReqPaths: []string{"/v1/auth/radius/login"},
			expectReqParams: []map[string]interface{}{
				{
					consts.FieldUsername: "alice",
					consts.FieldPassword: "password1",
				},
			},
			want:    &api.Secret{},
			wantErr: false,
		},
		{
			name: "error-uninitialized",
			authLogin: &AuthLoginRadius{
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
