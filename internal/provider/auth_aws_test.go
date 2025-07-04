// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

// AWS auth initialization with various parameter combinations
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

// auth login path generation
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

// AWS config building from credential parameters
func TestAuthLoginAWS_buildAWSConfig(t *testing.T) {
	type fields struct {
		AuthLoginCommon AuthLoginCommon
	}
	tests := []struct {
		name           string
		fields         fields
		wantErr        bool
		validateConfig func(t *testing.T, cfg *aws.Config, credParams credentialsParams)
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
			wantErr: false,
			validateConfig: func(t *testing.T, cfg *aws.Config, credParams credentialsParams) {
				if credParams.AccessKey != "key-id" {
					t.Errorf("expected AccessKey = key-id, got %s", credParams.AccessKey)
				}
				if credParams.SecretKey != "sa-key" {
					t.Errorf("expected SecretKey = sa-key, got %s", credParams.SecretKey)
				}
				// When no region is specified, SDK may leave it empty - this is acceptable
				// The actual region resolution happens when making AWS calls
			},
		},
		{
			name: "region-specified",
			fields: fields{
				AuthLoginCommon: AuthLoginCommon{
					params: map[string]interface{}{
						consts.FieldAWSAccessKeyID:     "key-id",
						consts.FieldAWSSecretAccessKey: "sa-key",
						consts.FieldAWSRegion:          "us-west-2",
					},
				},
			},
			wantErr: false,
			validateConfig: func(t *testing.T, cfg *aws.Config, credParams credentialsParams) {
				if credParams.AccessKey != "key-id" {
					t.Errorf("expected AccessKey = key-id, got %s", credParams.AccessKey)
				}
				if credParams.SecretKey != "sa-key" {
					t.Errorf("expected SecretKey = sa-key, got %s", credParams.SecretKey)
				}
				if credParams.Region != "us-west-2" {
					t.Errorf("expected Region = us-west-2, got %s", credParams.Region)
				}
				if cfg.Region != "us-west-2" {
					t.Errorf("expected AWS config region us-west-2, got %s", cfg.Region)
				}
			},
		},
		{
			name: "with-endpoints-and-role",
			fields: fields{
				AuthLoginCommon: AuthLoginCommon{
					params: map[string]interface{}{
						consts.FieldAWSAccessKeyID:          "key-id",
						consts.FieldAWSSecretAccessKey:      "sa-key",
						consts.FieldAWSSessionToken:         "session-token",
						consts.FieldAWSIAMEndpoint:          "iam.us-east-2.amazonaws.com",
						consts.FieldAWSSTSEndpoint:          "sts.us-east-2.amazonaws.com",
						consts.FieldAWSRegion:               "us-east-2",
						consts.FieldAWSRoleARN:              "arn:aws:iam::123456789012:role/MyRole",
						consts.FieldAWSRoleSessionName:      "session1",
						consts.FieldAWSWebIdentityTokenFile: "web-token",
					},
				},
			},
			wantErr: false,
			validateConfig: func(t *testing.T, cfg *aws.Config, credParams credentialsParams) {
				if credParams.AccessKey != "key-id" {
					t.Errorf("expected AccessKey = key-id, got %s", credParams.AccessKey)
				}
				if credParams.SecretKey != "sa-key" {
					t.Errorf("expected SecretKey = sa-key, got %s", credParams.SecretKey)
				}
				if credParams.SessionToken != "session-token" {
					t.Errorf("expected SessionToken = session-token, got %s", credParams.SessionToken)
				}
				if credParams.STSEndpoint != "sts.us-east-2.amazonaws.com" {
					t.Errorf("expected STSEndpoint = sts.us-east-2.amazonaws.com, got %s", credParams.STSEndpoint)
				}
				if credParams.IAMEndpoint != "iam.us-east-2.amazonaws.com" {
					t.Errorf("expected IAMEndpoint = iam.us-east-2.amazonaws.com, got %s", credParams.IAMEndpoint)
				}
				if credParams.Region != "us-east-2" {
					t.Errorf("expected Region = us-east-2, got %s", credParams.Region)
				}
				if credParams.RoleARN != "arn:aws:iam::123456789012:role/MyRole" {
					t.Errorf("expected RoleARN = arn:aws:iam::123456789012:role/MyRole, got %s", credParams.RoleARN)
				}
				if credParams.RoleSessionName != "session1" {
					t.Errorf("expected RoleSessionName = session1, got %s", credParams.RoleSessionName)
				}
				if credParams.WebIdentityTokenFile != "web-token" {
					t.Errorf("expected WebIdentityTokenFile = web-token, got %s", credParams.WebIdentityTokenFile)
				}
				if cfg.Region != "us-east-2" {
					t.Errorf("expected AWS config region us-east-2, got %s", cfg.Region)
				}
			},
		},
		{
			name: "validation-error-incomplete-static-creds",
			fields: fields{
				AuthLoginCommon: AuthLoginCommon{
					params: map[string]interface{}{
						consts.FieldAWSAccessKeyID: "key-id",
						// missing secret key
					},
				},
			},
			wantErr: true,
		},
		{
			name: "validation-error-role-session-without-arn",
			fields: fields{
				AuthLoginCommon: AuthLoginCommon{
					params: map[string]interface{}{
						consts.FieldAWSRoleSessionName: "session1",
						// missing role ARN
					},
				},
			},
			wantErr: true,
		},
		{
			name: "validation-error-web-identity-without-arn",
			fields: fields{
				AuthLoginCommon: AuthLoginCommon{
					params: map[string]interface{}{
						consts.FieldAWSWebIdentityTokenFile: "web-token",
						// missing role ARN
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginAWS{
				AuthLoginCommon: tt.fields.AuthLoginCommon,
			}

			// Test the complete flow: collectCredentialParams -> buildAWSConfig
			credParams, err := l.collectCredentialParams()
			if (err != nil) != tt.wantErr {
				t.Errorf("collectCredentialParams() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				// If we expect an error, we should have gotten it from collectCredentialParams
				return
			}

			// Build AWS config from the collected parameters
			ctx := context.Background()
			cfg, err := buildAWSConfig(ctx, &credParams)
			if err != nil {
				t.Errorf("buildAWSConfig() unexpected error = %v", err)
				return
			}

			if cfg == nil {
				t.Errorf("buildAWSConfig() returned nil config")
				return
			}

			// Run validation function if provided
			if tt.validateConfig != nil {
				tt.validateConfig(t, cfg, credParams)
			}
		})
	}
}

// validate chain parameter extraction
func TestAuthLoginAWS_CredentialProviderChain(t *testing.T) {
	tests := []struct {
		name           string
		params         map[string]interface{}
		expectedStatic bool
		expectedRole   bool
		expectedRegion string
	}{
		{
			name: "static-credentials-only",
			params: map[string]interface{}{
				consts.FieldAWSAccessKeyID:     "test-key",
				consts.FieldAWSSecretAccessKey: "test-secret",
				consts.FieldAWSRegion:          "us-west-2",
			},
			expectedStatic: true,
			expectedRole:   false,
			expectedRegion: "us-west-2",
		},
		{
			name: "static-credentials-with-role",
			params: map[string]interface{}{
				consts.FieldAWSAccessKeyID:     "test-key",
				consts.FieldAWSSecretAccessKey: "test-secret",
				consts.FieldAWSRoleARN:         "arn:aws:iam::123456789012:role/TestRole",
				consts.FieldAWSRoleSessionName: "test-session",
				consts.FieldAWSRegion:          "us-east-1",
			},
			expectedStatic: true,
			expectedRole:   true,
			expectedRegion: "us-east-1",
		},
		{
			name: "profile-credentials-with-role",
			params: map[string]interface{}{
				consts.FieldAWSProfile:         "test-profile",
				consts.FieldAWSRoleARN:         "arn:aws:iam::123456789012:role/TestRole",
				consts.FieldAWSRoleSessionName: "test-session",
			},
			expectedStatic: false,
			expectedRole:   true,
			expectedRegion: "", // no region specified, SDK will use default resolution
		},
		{
			name: "web-identity-with-role",
			params: map[string]interface{}{
				consts.FieldAWSRoleARN:              "arn:aws:iam::123456789012:role/TestRole",
				consts.FieldAWSWebIdentityTokenFile: "/tmp/token",
				consts.FieldAWSRoleSessionName:      "web-session",
			},
			expectedStatic: false,
			expectedRole:   true,
			expectedRegion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginAWS{
				AuthLoginCommon: AuthLoginCommon{
					params: tt.params,
				},
			}

			credParams, err := l.collectCredentialParams()
			if err != nil {
				t.Fatalf("collectCredentialParams() failed: %v", err)
			}

			// Test that credential parameters are correctly extracted
			if tt.expectedStatic {
				if credParams.AccessKey != "test-key" {
					t.Errorf("expected AccessKey = test-key, got %s", credParams.AccessKey)
				}
				if credParams.SecretKey != "test-secret" {
					t.Errorf("expected SecretKey = test-secret, got %s", credParams.SecretKey)
				}
			}

			if tt.expectedRole {
				if !strings.HasPrefix(credParams.RoleARN, "arn:aws:iam::") {
					t.Errorf("expected valid role ARN, got %s", credParams.RoleARN)
				}
			}

			if tt.expectedRegion != "" {
				if credParams.Region != tt.expectedRegion {
					t.Errorf("expected region %s, got %s", tt.expectedRegion, credParams.Region)
				}
			}

			// Test that AWS config can be built from these parameters
			ctx := context.Background()
			cfg, err := buildAWSConfig(ctx, &credParams)
			if err != nil {
				// For tests that require actual files (profile, web identity),
				// we expect errors but want to verify the parameters were processed correctly
				if !tt.expectedStatic && (strings.Contains(err.Error(), "profile") || strings.Contains(err.Error(), "token")) {
					// This is expected for profile/web identity tests without real files
					return
				}
				t.Fatalf("buildAWSConfig() failed: %v", err)
			}

			if cfg == nil {
				t.Fatal("buildAWSConfig() returned nil config")
			}

			// Verify region configuration
			if tt.expectedRegion != "" && cfg.Region != tt.expectedRegion {
				t.Errorf("expected config region %s, got %s", tt.expectedRegion, cfg.Region)
			}
		})
	}
}

// Test credential parameter validation
func TestAuthLoginAWS_ValidationErrors(t *testing.T) {
	tests := []struct {
		name      string
		params    map[string]interface{}
		wantErr   bool
		errString string
	}{
		{
			name: "validation-error-incomplete-static-creds",
			params: map[string]interface{}{
				consts.FieldAWSAccessKeyID: "only-key",
				// missing secret key
			},
			wantErr:   true,
			errString: "static AWS client credentials haven't been properly configured",
		},
		{
			name: "validation-error-role-session-without-arn",
			params: map[string]interface{}{
				consts.FieldAWSRoleSessionName: "session-name",
				// missing role ARN
			},
			wantErr:   true,
			errString: "role session name specified without role ARN",
		},
		{
			name: "validation-error-web-identity-without-arn",
			params: map[string]interface{}{
				consts.FieldAWSWebIdentityTokenFile: "/tmp/token",
				// missing role ARN
			},
			wantErr:   true,
			errString: "web identity token file specified without role ARN",
		},
		{
			name: "valid-static-credentials",
			params: map[string]interface{}{
				consts.FieldAWSAccessKeyID:     "test-key",
				consts.FieldAWSSecretAccessKey: "test-secret",
			},
			wantErr: false,
		},
		{
			name: "valid-role-assumption",
			params: map[string]interface{}{
				consts.FieldAWSAccessKeyID:     "test-key",
				consts.FieldAWSSecretAccessKey: "test-secret",
				consts.FieldAWSRoleARN:         "arn:aws:iam::123456789012:role/TestRole",
				consts.FieldAWSRoleSessionName: "test-session",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginAWS{
				AuthLoginCommon: AuthLoginCommon{
					params: tt.params,
				},
			}

			credParams, err := l.collectCredentialParams()
			if (err != nil) != tt.wantErr {
				t.Errorf("collectCredentialParams() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if tt.errString != "" && !strings.Contains(err.Error(), tt.errString) {
					t.Errorf("expected error containing %q, got %q", tt.errString, err.Error())
				}
				return
			}

			// If no error expected, verify basic parameter extraction worked
			if tt.params[consts.FieldAWSAccessKeyID] != nil {
				expectedKey := tt.params[consts.FieldAWSAccessKeyID].(string)
				if credParams.AccessKey != expectedKey {
					t.Errorf("expected AccessKey = %s, got %s", expectedKey, credParams.AccessKey)
				}
			}
		})
	}
}

// Test legacy field mapping in signAWSLogin function
func TestSignAWSLogin_ParameterMapping(t *testing.T) {
	tests := []struct {
		name       string
		parameters map[string]interface{}
		wantErr    bool
		errString  string
	}{
		{
			name: "legacy-aws-security-token-field-mapping",
			parameters: map[string]interface{}{
				"aws_security_token": "legacy-token", // legacy field name
			},
			wantErr: false,
		},
		{
			name: "standard-session-token-field-mapping",
			parameters: map[string]interface{}{
				consts.FieldAWSSessionToken: "standard-token", // standard field name
			},
			wantErr: false,
		},
		{
			name: "sts-region-field-mapping",
			parameters: map[string]interface{}{
				"sts_region": "us-west-2", // generic auth uses sts_region instead of aws_region
			},
			wantErr: false,
		},
		{
			name: "validation-error-incomplete-credentials",
			parameters: map[string]interface{}{
				consts.FieldAWSAccessKeyID: "only-key",
				// missing secret key
			},
			wantErr:   true,
			errString: "static AWS client credentials haven't been properly configured",
		},
		{
			name: "validation-error-role-session-without-arn",
			parameters: map[string]interface{}{
				consts.FieldAWSRoleSessionName: "session-name",
				// missing role ARN
			},
			wantErr:   true,
			errString: "role session name specified without role ARN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the parameter processing part of signAWSLogin without actually calling AWS
			credParams := credentialsParams{}

			// Simulate the parameter mapping logic from signAWSLogin
			if v, ok := tt.parameters[consts.FieldAWSAccessKeyID].(string); ok {
				credParams.AccessKey = v
			}
			if v, ok := tt.parameters[consts.FieldAWSSecretAccessKey].(string); ok {
				credParams.SecretKey = v
			}
			if v, ok := tt.parameters[consts.FieldAWSSessionToken].(string); ok {
				credParams.SessionToken = v
			} else if v, ok := tt.parameters["aws_security_token"].(string); ok {
				credParams.SessionToken = v // legacy field mapping
			}
			if v, ok := tt.parameters["sts_region"].(string); ok {
				credParams.Region = v // generic auth field mapping
			}
			if v, ok := tt.parameters[consts.FieldAWSRoleARN].(string); ok {
				credParams.RoleARN = v
			}
			if v, ok := tt.parameters[consts.FieldAWSRoleSessionName].(string); ok {
				credParams.RoleSessionName = v
			}

			// Test validation
			err := validateCredentialParams(&credParams)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCredentialParams() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if tt.errString != "" && !strings.Contains(err.Error(), tt.errString) {
					t.Errorf("expected error containing %q, got %q", tt.errString, err.Error())
				}
				return
			}

			// Verify field mappings worked correctly
			if tt.parameters["aws_security_token"] != nil {
				expected := tt.parameters["aws_security_token"].(string)
				if credParams.SessionToken != expected {
					t.Errorf("expected legacy aws_security_token mapping to work, got %s", credParams.SessionToken)
				}
			}
			if tt.parameters[consts.FieldAWSSessionToken] != nil {
				expected := tt.parameters[consts.FieldAWSSessionToken].(string)
				if credParams.SessionToken != expected {
					t.Errorf("expected standard session token mapping to work, got %s", credParams.SessionToken)
				}
			}
			if tt.parameters["sts_region"] != nil {
				expected := tt.parameters["sts_region"].(string)
				if credParams.Region != expected {
					t.Errorf("expected sts_region mapping to work, got %s", credParams.Region)
				}
			}
		})
	}
}

// Test AWS login error conditions
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
		_, _ = w.Write(m)
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

// test credential provider precedence order (static > role > shared creds > env)
func TestAuthLoginAWS_CredentialProviderPrecedence(t *testing.T) {
	tests := []struct {
		name                    string
		params                  map[string]interface{}
		expectStaticCredentials bool
		expectAssumeRole        bool
		expectSharedCredentials bool
		skipIfNoProfile         bool
		expectRegion            string
	}{
		{
			name: "static-credentials-only",
			params: map[string]interface{}{
				consts.FieldAWSAccessKeyID:     "test-key",
				consts.FieldAWSSecretAccessKey: "test-secret",
				consts.FieldAWSRegion:          "us-west-2",
			},
			expectStaticCredentials: true,
			expectAssumeRole:        false,
			expectSharedCredentials: false,
			expectRegion:            "us-west-2",
		},
		{
			name: "static-credentials-with-role",
			params: map[string]interface{}{
				consts.FieldAWSAccessKeyID:     "test-key",
				consts.FieldAWSSecretAccessKey: "test-secret",
				consts.FieldAWSRoleARN:         "arn:aws:iam::123456789012:role/TestRole",
				consts.FieldAWSRoleSessionName: "test-session",
				consts.FieldAWSRegion:          "us-east-1",
			},
			expectStaticCredentials: false, // Role assumption should wrap static credentials
			expectAssumeRole:        true,
			expectSharedCredentials: false,
			expectRegion:            "us-east-1",
		},
		{
			name: "profile-with-role",
			params: map[string]interface{}{
				consts.FieldAWSProfile:         "test-profile",
				consts.FieldAWSRoleARN:         "arn:aws:iam::123456789012:role/TestRole",
				consts.FieldAWSRoleSessionName: "test-session",
			},
			expectStaticCredentials: false,
			expectAssumeRole:        true,
			expectSharedCredentials: false,
			skipIfNoProfile:         true, // profiles might not be present in the testing environment, ok to fail
		},
		{
			name: "profile-only",
			params: map[string]interface{}{
				consts.FieldAWSProfile: "test-profile",
			},
			expectStaticCredentials: false,
			expectAssumeRole:        false,
			expectSharedCredentials: true,
			skipIfNoProfile:         true, // profiles might not be present in the testing environment, ok to fail
		},
		{
			name: "environment-credentials-fallback",
			params: map[string]interface{}{
				// no explicit credential fields, hence should fallback to env vars
				consts.FieldAWSRegion: "us-west-1",
			},
			expectStaticCredentials: false,
			expectAssumeRole:        false,
			expectSharedCredentials: false,
			expectRegion:            "us-west-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginAWS{
				AuthLoginCommon: AuthLoginCommon{
					params: tt.params,
				},
			}

			// 1. verify credential parameters are collected correctly
			credParams, err := l.collectCredentialParams()
			if err != nil {
				t.Fatalf("collectCredentialParams() failed: %v", err)
			}

			// verify static credentials were set properly
			if tt.expectStaticCredentials {
				if credParams.AccessKey != "test-key" {
					t.Errorf("Expected AccessKey = test-key, got %s", credParams.AccessKey)
				}
				if credParams.SecretKey != "test-secret" {
					t.Errorf("Expected SecretKey = test-secret, got %s", credParams.SecretKey)
				}
			}

			// verify role assumption parameters
			if tt.expectAssumeRole {
				if credParams.RoleARN == "" {
					t.Error("Expected RoleARN to be set for role assumption")
				}
				if credParams.RoleSessionName == "" && credParams.WebIdentityTokenFile == "" {
					t.Error("Expected RoleSessionName or WebIdentityTokenFile to be set for role assumption")
				}
			}

			// verify profile config
			if tt.expectSharedCredentials {
				if credParams.Profile == "" {
					t.Error("Expected Profile to be set for shared credentials")
				}
			}

			// verify region
			if tt.expectRegion != "" {
				if credParams.Region != tt.expectRegion {
					t.Errorf("Expected region %s, got %s", tt.expectRegion, credParams.Region)
				}
			}

			// 2. build AWS config
			ctx := context.Background()
			cfg, err := buildAWSConfig(ctx, &credParams)

			if tt.skipIfNoProfile && err != nil {
				// in automations we can expect errors when profile doesn't exist
				if strings.Contains(err.Error(), "profile") || strings.Contains(err.Error(), "config") {
					t.Skipf("Skipping test that requires AWS profile: %v", err)
				}
			}

			if err != nil {
				t.Fatalf("buildAWSConfig() failed: %v", err)
			}

			if cfg == nil {
				t.Fatal("buildAWSConfig() returned nil config")
			}

			// 3. static property verification
			// credentials are set
			if cfg.Credentials == nil {
				t.Fatal("AWS config has nil Credentials")
			}

			// verify region
			if tt.expectRegion != "" && cfg.Region != tt.expectRegion {
				t.Errorf("Expected config region %s, got %s", tt.expectRegion, cfg.Region)
			}

			// for static-credentials-with-role skip cred retrieval, since test role doesn't exist
			// unexported field CredentialsCache.provider stores the real provider, but not accessible without reflection
			if tt.name == "static-credentials-with-role" {
				t.Log("Skipping credential retrieval for static-credentials-with-role to avoid AWS API calls")
				return
			}

			// retrieve creds for non-role tests
			if !tt.expectAssumeRole {
				creds, err := cfg.Credentials.Retrieve(ctx)
				if err != nil && tt.skipIfNoProfile {
					if strings.Contains(err.Error(), "profile") || strings.Contains(err.Error(), "credentials") {
						t.Skipf("Skipping credential retrieval test due to missing profile: %v", err)
					}
				}

				if err != nil {
					t.Fatalf("Failed to retrieve credentials: %v", err)
				}

				// verify the credential source for non-role cases
				if tt.expectStaticCredentials {
					if credParams.AccessKey != "" && creds.AccessKeyID != credParams.AccessKey {
						t.Errorf("Expected static credentials with AccessKey %s, got %s", credParams.AccessKey, creds.AccessKeyID)
					}
				}
			}

			t.Logf("Successfully built AWS config for scenario: %s", tt.name)
			if tt.expectStaticCredentials {
				t.Log("  - Static credentials configured")
			}
			if tt.expectAssumeRole {
				t.Log("  - Role assumption configured")
			}
			if tt.expectSharedCredentials {
				t.Log("  - Shared credentials configured")
			}
		})
	}
}

// Test IAM request generation with deterministic output
func TestGenerateLoginData_DeterministicOutput(t *testing.T) {
	tests := []struct {
		name              string
		awsConfig         *aws.Config
		headerValue       string
		configuredRegion  string
		expectMethod      string
		expectURLContains string
		expectHeaderID    bool
	}{
		{
			name: "basic-request-without-header",
			awsConfig: &aws.Config{
				Region: "us-east-1",
				Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(
					"test-access-key",
					"test-secret-key",
					"",
				)),
			},
			headerValue:       "",
			configuredRegion:  "us-east-1",
			expectMethod:      "POST",
			expectURLContains: "sts.us-east-1.amazonaws.com",
			expectHeaderID:    false,
		},
		{
			name: "request-with-header-value",
			awsConfig: &aws.Config{
				Region: "us-west-2",
				Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(
					"test-access-key",
					"test-secret-key",
					"test-session-token",
				)),
			},
			headerValue:       "vault-server-id",
			configuredRegion:  "us-west-2",
			expectMethod:      "POST",
			expectURLContains: "sts.us-west-2.amazonaws.com",
			expectHeaderID:    true,
		},
		{
			name: "default-region-fallback",
			awsConfig: &aws.Config{
				Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(
					"test-access-key",
					"test-secret-key",
					"",
				)),
			},
			headerValue:       "",
			configuredRegion:  "",
			expectMethod:      "POST",
			expectURLContains: "sts.us-east-1.amazonaws.com", // default fallback
			expectHeaderID:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := getHCLogger()

			loginData, err := generateLoginData(tt.awsConfig, tt.headerValue, tt.configuredRegion, logger)
			if err != nil {
				t.Fatalf("generateLoginData() failed: %v", err)
			}

			requiredFields := []string{
				consts.FieldIAMHttpRequestMethod,
				consts.FieldIAMRequestURL,
				consts.FieldIAMRequestBody,
				consts.FieldIAMRequestHeaders,
			}

			for _, field := range requiredFields {
				if _, ok := loginData[field]; !ok {
					t.Errorf("Missing required field: %s", field)
				}
			}

			// check if url/body/headers are base64 encoded - bw compat
			urlB64, ok := loginData[consts.FieldIAMRequestURL].(string)
			if !ok {
				t.Fatalf("iam_request_url is not a string")
			}
			urlBytes, err := base64.StdEncoding.DecodeString(urlB64)
			if err != nil {
				t.Fatalf("Failed to decode iam_request_url: %v", err)
			}
			url := string(urlBytes)
			if !strings.Contains(url, tt.expectURLContains) {
				t.Errorf("Expected URL to contain %s, got %s", tt.expectURLContains, url)
			}

			bodyB64, ok := loginData[consts.FieldIAMRequestBody].(string)
			if !ok {
				t.Fatalf("iam_request_body is not a string")
			}
			bodyBytes, err := base64.StdEncoding.DecodeString(bodyB64)
			if err != nil {
				t.Fatalf("Failed to decode iam_request_body: %v", err)
			}
			body := string(bodyBytes)
			if !strings.Contains(body, "Action=GetCallerIdentity") {
				t.Errorf("Expected body to contain GetCallerIdentity action, got %s", body)
			}

			headersB64, ok := loginData[consts.FieldIAMRequestHeaders].(string)
			if !ok {
				t.Fatalf("iam_request_headers is not a string")
			}
			headersBytes, err := base64.StdEncoding.DecodeString(headersB64)
			if err != nil {
				t.Fatalf("Failed to decode iam_request_headers: %v", err)
			}

			var headers map[string][]string
			if err := json.Unmarshal(headersBytes, &headers); err != nil {
				t.Fatalf("Failed to unmarshal headers: %v", err)
			}

			// verify vault header presence (case-insensitive per RFC 2616)
			var vaultHeader []string
			var hasVaultHeader bool
			expectedHeaderName := "X-Vault-AWS-IAM-Server-ID"

			for headerName, headerValue := range headers {
				if strings.EqualFold(headerName, expectedHeaderName) {
					vaultHeader = headerValue
					hasVaultHeader = true
					break
				}
			}

			if tt.expectHeaderID {
				if !hasVaultHeader {
					t.Errorf("Expected %s header to be present. Available headers: %v", expectedHeaderName, headers)
				} else if len(vaultHeader) == 0 || vaultHeader[0] != tt.headerValue {
					t.Errorf("Expected header value %s, got %v", tt.headerValue, vaultHeader)
				}
			} else {
				if hasVaultHeader {
					t.Errorf("Expected %s header to be absent", expectedHeaderName)
				}
			}

			// x-amz-date generated by sdk when signing
			expectedSigHeaders := []string{"Authorization", "X-Amz-Date"}
			for _, headerName := range expectedSigHeaders {
				if _, ok := headers[headerName]; !ok {
					t.Errorf("Missing expected AWS signature header: %s", headerName)
				}
			}
		})
	}
}

// Test complete signAWSLogin flow from parameters to signed request
func TestSignAWSLogin_EndToEnd(t *testing.T) {
	tests := []struct {
		name       string
		parameters map[string]interface{}
		wantErr    bool
		errString  string
	}{
		{
			name: "static-credentials-complete-flow",
			parameters: map[string]interface{}{
				consts.FieldAWSAccessKeyID:     "test-access-key",
				consts.FieldAWSSecretAccessKey: "test-secret-key",
				consts.FieldAWSSessionToken:    "test-session-token",
				"sts_region":                   "us-west-2",
			},
			wantErr: false,
		},
		{
			name: "legacy-aws-security-token-field",
			parameters: map[string]interface{}{
				consts.FieldAWSAccessKeyID:     "test-access-key",
				consts.FieldAWSSecretAccessKey: "test-secret-key",
				"aws_security_token":           "legacy-token",
				"sts_region":                   "us-east-1",
			},
			wantErr: false,
		},
		{
			name: "with-header-value",
			parameters: map[string]interface{}{
				consts.FieldAWSAccessKeyID:     "test-access-key",
				consts.FieldAWSSecretAccessKey: "test-secret-key",
				"sts_region":                   "us-east-1",
				consts.FieldHeaderValue:        "vault-server-id",
			},
			wantErr: false,
		},
		{
			name: "validation-error-incomplete-credentials",
			parameters: map[string]interface{}{
				consts.FieldAWSAccessKeyID: "only-access-key",
				// missing secret key
			},
			wantErr:   true,
			errString: "static AWS client credentials haven't been properly configured",
		},
		{
			name: "validation-error-role-session-without-arn",
			parameters: map[string]interface{}{
				consts.FieldAWSRoleSessionName: "session-name",
				// missing role ARN
			},
			wantErr:   true,
			errString: "role session name specified without role ARN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := getHCLogger()

			// Make a copy of parameters to avoid modifying the test case
			params := make(map[string]interface{})
			for k, v := range tt.parameters {
				params[k] = v
			}

			err := signAWSLogin(params, logger)
			if (err != nil) != tt.wantErr {
				t.Errorf("signAWSLogin() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if tt.errString != "" && !strings.Contains(err.Error(), tt.errString) {
					t.Errorf("Expected error containing %q, got %q", tt.errString, err.Error())
				}
				return
			}

			// For successful cases, verify all IAM fields are populated
			requiredIAMFields := []string{
				consts.FieldIAMHttpRequestMethod,
				consts.FieldIAMRequestURL,
				consts.FieldIAMRequestBody,
				consts.FieldIAMRequestHeaders,
			}

			for _, field := range requiredIAMFields {
				value, ok := params[field]
				if !ok {
					t.Errorf("Missing required IAM field: %s", field)
					continue
				}

				// Verify field is not empty
				if str, ok := value.(string); !ok || str == "" {
					t.Errorf("IAM field %s is empty or not a string: %v", field, value)
				}
			}

			// Verify method is not base64 encoded
			if method, ok := params[consts.FieldIAMHttpRequestMethod].(string); ok {
				if method != "POST" {
					t.Errorf("Expected method POST, got %s", method)
				}
			}

			// Verify URL, body, and headers are base64 encoded
			base64Fields := []string{
				consts.FieldIAMRequestURL,
				consts.FieldIAMRequestBody,
				consts.FieldIAMRequestHeaders,
			}

			for _, field := range base64Fields {
				if value, ok := params[field].(string); ok {
					if _, err := base64.StdEncoding.DecodeString(value); err != nil {
						t.Errorf("Field %s is not valid base64: %v", field, err)
					}
				}
			}

			// Test legacy field mapping
			if tt.parameters["aws_security_token"] != nil {
				// Verify the legacy token was used (by checking that headers contain Authorization)
				if headersB64, ok := params[consts.FieldIAMRequestHeaders].(string); ok {
					headersBytes, _ := base64.StdEncoding.DecodeString(headersB64)
					var headers map[string][]string
					json.Unmarshal(headersBytes, &headers)
					if _, hasAuth := headers["Authorization"]; !hasAuth {
						t.Error("Expected Authorization header when using legacy aws_security_token")
					}
				}
			}

			// header value inclusion (case-insensitive per RFC 2616)
			if headerValue, ok := tt.parameters[consts.FieldHeaderValue].(string); ok && headerValue != "" {
				if headersB64, ok := params[consts.FieldIAMRequestHeaders].(string); ok {
					headersBytes, _ := base64.StdEncoding.DecodeString(headersB64)
					var headers map[string][]string
					json.Unmarshal(headersBytes, &headers)

					var vaultHeaders []string
					var hasVaultHeader bool
					expectedHeaderName := "X-Vault-AWS-IAM-Server-ID"

					for headerName, headerValue := range headers {
						if strings.EqualFold(headerName, expectedHeaderName) {
							vaultHeaders = headerValue
							hasVaultHeader = true
							break
						}
					}

					if !hasVaultHeader || len(vaultHeaders) == 0 || vaultHeaders[0] != headerValue {
						t.Errorf("Expected %s header with value %s. Available headers: %v", expectedHeaderName, headerValue, headers)
					}
				}
			}
		})
	}
}
