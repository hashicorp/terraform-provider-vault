// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/awsutil/v2"
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

func TestAuthLoginAWS_ConfiguredRoleARN(t *testing.T) {
	tests := []struct {
		name                    string
		awsRoleARNExplicit      bool
		awsRoleARNFromConfig    string
		expectConfigured        bool
		expectConfiguredRoleARN string
	}{
		{
			name:                    "omitted-in-config",
			awsRoleARNExplicit:      false,
			awsRoleARNFromConfig:    "",
			expectConfigured:        false,
			expectConfiguredRoleARN: "",
		},
		{
			name:                    "explicit-empty-in-config",
			awsRoleARNExplicit:      true,
			awsRoleARNFromConfig:    "",
			expectConfigured:        false,
			expectConfiguredRoleARN: "",
		},
		{
			name:                    "explicit-value-in-config",
			awsRoleARNExplicit:      true,
			awsRoleARNFromConfig:    "arn:aws:iam::123456789012:role/from-config",
			expectConfigured:        true,
			expectConfiguredRoleARN: "arn:aws:iam::123456789012:role/from-config",
		},
		{
			name:                    "inconsistent-state-non-empty-without-explicit",
			awsRoleARNExplicit:      false,
			awsRoleARNFromConfig:    "arn:aws:iam::123456789012:role/from-config",
			expectConfigured:        false,
			expectConfiguredRoleARN: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginAWS{
				awsRoleARNExplicit:   tt.awsRoleARNExplicit,
				awsRoleARNFromConfig: tt.awsRoleARNFromConfig,
			}

			gotRoleARN, gotConfigured := l.configuredRoleARN()
			if gotConfigured != tt.expectConfigured {
				t.Fatalf("configuredRoleARN() configured = %v, want %v", gotConfigured, tt.expectConfigured)
			}

			if gotRoleARN != tt.expectConfiguredRoleARN {
				t.Fatalf("configuredRoleARN() role ARN = %q, want %q", gotRoleARN, tt.expectConfiguredRoleARN)
			}
		})
	}
}

func TestAuthLoginAWS_ManualAssumeRoleARN(t *testing.T) {
	tests := []struct {
		name                   string
		awsRoleARNExplicit     bool
		awsRoleARNFromConfig   string
		params                 map[string]interface{}
		expectManualAssume     bool
		expectManualAssumeRole string
	}{
		{
			name:                   "explicit-value-in-config",
			awsRoleARNExplicit:     true,
			awsRoleARNFromConfig:   "arn:aws:iam::123456789012:role/from-config",
			expectManualAssume:     true,
			expectManualAssumeRole: "arn:aws:iam::123456789012:role/from-config",
		},
		{
			name:                 "explicit-value-in-config-with-web-identity-skips-manual-assume",
			awsRoleARNExplicit:   true,
			awsRoleARNFromConfig: "arn:aws:iam::123456789012:role/from-config",
			params: map[string]interface{}{
				consts.FieldAWSWebIdentityTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
			},
			expectManualAssume:     false,
			expectManualAssumeRole: "",
		},
		{
			name:                 "explicit-empty-in-config-disables-manual-assume",
			awsRoleARNExplicit:   true,
			awsRoleARNFromConfig: "",
			params: map[string]interface{}{
				consts.FieldAWSRoleARN: "arn:aws:iam::123456789012:role/from-env",
			},
			expectManualAssume:     false,
			expectManualAssumeRole: "",
		},
		{
			name: "env-role-arn-without-web-identity",
			params: map[string]interface{}{
				consts.FieldAWSRoleARN: "arn:aws:iam::123456789012:role/from-env",
			},
			expectManualAssume:     true,
			expectManualAssumeRole: "arn:aws:iam::123456789012:role/from-env",
		},
		{
			name: "env-role-arn-with-web-identity-skips-manual-assume",
			params: map[string]interface{}{
				consts.FieldAWSRoleARN:              "arn:aws:iam::123456789012:role/from-env",
				consts.FieldAWSWebIdentityTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
			},
			expectManualAssume:     false,
			expectManualAssumeRole: "",
		},
		{
			name: "no-role-arn",
			params: map[string]interface{}{
				consts.FieldAWSWebIdentityTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
			},
			expectManualAssume:     false,
			expectManualAssumeRole: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginAWS{
				AuthLoginCommon:      AuthLoginCommon{params: tt.params},
				awsRoleARNExplicit:   tt.awsRoleARNExplicit,
				awsRoleARNFromConfig: tt.awsRoleARNFromConfig,
			}

			gotRoleARN, gotManualAssume := l.manualAssumeRoleARN()
			if gotManualAssume != tt.expectManualAssume {
				t.Fatalf("manualAssumeRoleARN() manual assume = %v, want %v", gotManualAssume, tt.expectManualAssume)
			}

			if gotRoleARN != tt.expectManualAssumeRole {
				t.Fatalf("manualAssumeRoleARN() role ARN = %q, want %q", gotRoleARN, tt.expectManualAssumeRole)
			}
		})
	}
}

func TestAuthLoginAWS_GetConfigStringField_Negative(t *testing.T) {
	tests := []struct {
		name  string
		raw   map[string]interface{}
		field string
	}{
		{
			name:  "missing-auth-block",
			raw:   map[string]interface{}{},
			field: consts.FieldAWSRoleARN,
		},
		{
			name: "missing-field-in-auth-block",
			raw: map[string]interface{}{
				consts.FieldAuthLoginAWS: []interface{}{
					map[string]interface{}{
						consts.FieldRole: "alice",
					},
				},
			},
			field: consts.FieldAWSRoleARN,
		},
		{
			name: "non-string-field-in-auth-block",
			raw: map[string]interface{}{
				consts.FieldAuthLoginAWS: []interface{}{
					map[string]interface{}{
						consts.FieldRole:       "alice",
						consts.FieldAWSRoleARN: true,
					},
				},
			},
			field: consts.FieldAWSRoleARN,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := map[string]*schema.Schema{
				consts.FieldAuthLoginAWS: GetAWSLoginSchema(consts.FieldAuthLoginAWS),
			}
			d := schema.TestResourceDataRaw(t, s, tt.raw)

			l := &AuthLoginAWS{
				AuthLoginCommon: AuthLoginCommon{authField: consts.FieldAuthLoginAWS},
			}

			got, ok := l.getConfigStringField(d, tt.field)
			if ok {
				t.Fatalf("getConfigStringField() ok = true, want false, got value %q", got)
			}

			if got != "" {
				t.Fatalf("getConfigStringField() value = %q, want empty string", got)
			}
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
			name: "static-creds-with-role-arn",
			fields: fields{
				AuthLoginCommon: AuthLoginCommon{
					params: map[string]interface{}{
						consts.FieldAWSAccessKeyID:     "key-id",
						consts.FieldAWSSecretAccessKey: "secret-key",
						consts.FieldAWSRoleARN:         "arn:aws:iam::123456789012:role/test-role",
						consts.FieldAWSRoleSessionName: "test-session",
					},
				},
			},
			logger: hclog.NewNullLogger(),
			want: &awsutil.CredentialsConfig{
				Region:          "us-east-1",
				AccessKey:       "key-id",
				SecretKey:       "secret-key",
				RoleARN:         "arn:aws:iam::123456789012:role/test-role",
				RoleSessionName: "test-session",
			},
			wantErr: false,
		},
		{
			name: "static-creds-with-session-token-and-role-arn",
			fields: fields{
				AuthLoginCommon: AuthLoginCommon{
					params: map[string]interface{}{
						consts.FieldAWSAccessKeyID:     "key-id",
						consts.FieldAWSSecretAccessKey: "secret-key",
						consts.FieldAWSSessionToken:    "session-token",
						consts.FieldAWSRoleARN:         "arn:aws:iam::123456789012:role/test-role",
					},
				},
			},
			logger: hclog.NewNullLogger(),
			want: &awsutil.CredentialsConfig{
				Region:       "us-east-1",
				AccessKey:    "key-id",
				SecretKey:    "secret-key",
				SessionToken: "session-token",
				RoleARN:      "arn:aws:iam::123456789012:role/test-role",
			},
			wantErr: false,
		},
		{
			name: "irsa-web-identity-with-role-arn",
			fields: fields{
				AuthLoginCommon: AuthLoginCommon{
					params: map[string]interface{}{
						consts.FieldAWSRoleARN:              "arn:aws:iam::123456789012:role/test-role",
						consts.FieldAWSRoleSessionName:      "irsa-session",
						consts.FieldAWSWebIdentityTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
						consts.FieldAWSRegion:               "us-west-2",
					},
				},
			},
			logger: hclog.NewNullLogger(),
			want: &awsutil.CredentialsConfig{
				Region:               "us-west-2",
				RoleARN:              "arn:aws:iam::123456789012:role/test-role",
				RoleSessionName:      "irsa-session",
				WebIdentityTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
			},
			wantErr: false,
		},
		{
			name: "irsa-web-identity-without-role-arn",
			fields: fields{
				AuthLoginCommon: AuthLoginCommon{
					params: map[string]interface{}{
						consts.FieldAWSWebIdentityTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
						consts.FieldAWSRegion:               "us-west-2",
					},
				},
			},
			logger:  hclog.NewNullLogger(),
			wantErr: true,
		},
		{
			name: "role-session-without-role-arn",
			fields: fields{
				AuthLoginCommon: AuthLoginCommon{
					params: map[string]interface{}{
						consts.FieldAWSRoleSessionName: "test-session",
					},
				},
			},
			logger:  hclog.NewNullLogger(),
			wantErr: true,
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
				AccessKey:    "key-id",
				SecretKey:    "sa-key",
				SessionToken: "session-token",
				// Note: IAMEndpoint and STSEndpoint have been replaced with endpoint resolvers in v2
				// and are no longer simple string fields
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
			if tt.wantErr {
				return
			}

			if got.HTTPClient == nil {
				t.Errorf("getCredentialsConfig() HTTPClient not initialized")
			}

			// Verify custom endpoint resolvers are set correctly when endpoints are provided
			// We check these explicitly because they're interfaces and can't be compared with DeepEqual
			if stsEndpoint, ok := tt.fields.AuthLoginCommon.params[consts.FieldAWSSTSEndpoint].(string); ok && stsEndpoint != "" {
				if got.STSEndpointResolver == nil {
					t.Error("Expected STSEndpointResolver to be set when aws_sts_endpoint is provided")
				} else {
					resolver, ok := got.STSEndpointResolver.(*customSTSEndpointResolver)
					if !ok {
						t.Error("STSEndpointResolver is not of type *customSTSEndpointResolver")
					} else if resolver.endpointURL != stsEndpoint {
						t.Errorf("STSEndpointResolver endpointURL = %v, want %v", resolver.endpointURL, stsEndpoint)
					}
				}
			}

			if iamEndpoint, ok := tt.fields.AuthLoginCommon.params[consts.FieldAWSIAMEndpoint].(string); ok && iamEndpoint != "" {
				if got.IAMEndpointResolver == nil {
					t.Error("Expected IAMEndpointResolver to be set when aws_iam_endpoint is provided")
				} else {
					resolver, ok := got.IAMEndpointResolver.(*customIAMEndpointResolver)
					if !ok {
						t.Error("IAMEndpointResolver is not of type *customIAMEndpointResolver")
					} else if resolver.endpointURL != iamEndpoint {
						t.Errorf("IAMEndpointResolver endpointURL = %v, want %v", resolver.endpointURL, iamEndpoint)
					}
				}
			}

			// Set HTTPClient, Logger, and endpoint resolvers to nil before DeepEqual comparison
			// We've already verified endpoint resolvers above
			got.HTTPClient = nil
			got.Logger = nil
			got.STSEndpointResolver = nil
			got.IAMEndpointResolver = nil
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getCredentialsConfig() got = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestAuthLoginAWS_RoleAssumption tests the manual role assumption logic
func TestAuthLoginAWS_RoleAssumption(t *testing.T) {
	tests := []struct {
		name                 string
		params               map[string]interface{}
		expectRoleAssumption bool
		expectSessionName    string
	}{
		{
			name: "with-role-arn-and-session-name",
			params: map[string]interface{}{
				consts.FieldAWSAccessKeyID:     "key-id",
				consts.FieldAWSSecretAccessKey: "secret-key",
				consts.FieldAWSRoleARN:         "arn:aws:iam::123456789012:role/test-role",
				consts.FieldAWSRoleSessionName: "custom-session",
			},
			expectRoleAssumption: true,
			expectSessionName:    "custom-session",
		},
		{
			name: "with-role-arn-default-session-name",
			params: map[string]interface{}{
				consts.FieldAWSAccessKeyID:     "key-id",
				consts.FieldAWSSecretAccessKey: "secret-key",
				consts.FieldAWSRoleARN:         "arn:aws:iam::123456789012:role/test-role",
			},
			expectRoleAssumption: true,
			expectSessionName:    "", // Session name is not set in config when not provided
		},
		{
			name: "without-role-arn",
			params: map[string]interface{}{
				consts.FieldAWSAccessKeyID:     "key-id",
				consts.FieldAWSSecretAccessKey: "secret-key",
			},
			expectRoleAssumption: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginAWS{
				AuthLoginCommon: AuthLoginCommon{
					params: tt.params,
				},
			}

			// Verify that getCredentialsConfig properly sets role ARN
			config, err := l.getCredentialsConfig(hclog.NewNullLogger())
			if err != nil {
				t.Fatalf("getCredentialsConfig() error = %v", err)
			}

			if tt.expectRoleAssumption {
				if config.RoleARN == "" {
					t.Errorf("Expected RoleARN to be set, got empty string")
				}
				if roleARN, ok := tt.params[consts.FieldAWSRoleARN].(string); ok {
					if config.RoleARN != roleARN {
						t.Errorf("Expected RoleARN = %v, got %v", roleARN, config.RoleARN)
					}
				}

				// Check session name
				expectedSessionName := tt.expectSessionName
				if config.RoleSessionName != expectedSessionName {
					t.Errorf("Expected RoleSessionName = %v, got %v", expectedSessionName, config.RoleSessionName)
				}
			} else {
				if config.RoleARN != "" {
					t.Errorf("Expected RoleARN to be empty, got %v", config.RoleARN)
				}
			}
		})
	}
}

// TestAuthLoginAWS_SessionTokenWithRoleARN tests that session token is handled correctly with role assumption
func TestAuthLoginAWS_SessionTokenWithRoleARN(t *testing.T) {
	tests := []struct {
		name                  string
		params                map[string]interface{}
		expectSessionTokenSet bool
	}{
		{
			name: "session-token-without-role-arn",
			params: map[string]interface{}{
				consts.FieldAWSAccessKeyID:     "key-id",
				consts.FieldAWSSecretAccessKey: "secret-key",
				consts.FieldAWSSessionToken:    "session-token",
			},
			expectSessionTokenSet: true,
		},
		{
			name: "session-token-with-role-arn",
			params: map[string]interface{}{
				consts.FieldAWSAccessKeyID:     "key-id",
				consts.FieldAWSSecretAccessKey: "secret-key",
				consts.FieldAWSSessionToken:    "session-token",
				consts.FieldAWSRoleARN:         "arn:aws:iam::123456789012:role/test-role",
			},
			expectSessionTokenSet: true,
		},
		{
			name: "no-session-token-with-role-arn",
			params: map[string]interface{}{
				consts.FieldAWSAccessKeyID:     "key-id",
				consts.FieldAWSSecretAccessKey: "secret-key",
				consts.FieldAWSRoleARN:         "arn:aws:iam::123456789012:role/test-role",
			},
			expectSessionTokenSet: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginAWS{
				AuthLoginCommon: AuthLoginCommon{
					params: tt.params,
				},
			}

			config, err := l.getCredentialsConfig(hclog.NewNullLogger())
			if err != nil {
				t.Fatalf("getCredentialsConfig() error = %v", err)
			}

			hasSessionToken := config.SessionToken != ""
			if hasSessionToken != tt.expectSessionTokenSet {
				t.Errorf("Expected SessionToken set = %v, got %v", tt.expectSessionTokenSet, hasSessionToken)
			}

			// Verify session token value matches if it should be set
			if tt.expectSessionTokenSet {
				if sessionToken, ok := tt.params[consts.FieldAWSSessionToken].(string); ok {
					if config.SessionToken != sessionToken {
						t.Errorf("Expected SessionToken = %v, got %v", sessionToken, config.SessionToken)
					}
				}
			}
		})
	}
}

// TestAuthLoginAWS_CustomEndpoints tests that custom STS and IAM endpoints are properly configured
func TestAuthLoginAWS_CustomEndpoints(t *testing.T) {
	tests := []struct {
		name              string
		params            map[string]interface{}
		expectSTSEndpoint bool
		expectIAMEndpoint bool
		stsEndpoint       string
		iamEndpoint       string
	}{
		{
			name: "with-custom-sts-endpoint",
			params: map[string]interface{}{
				consts.FieldAWSAccessKeyID:     "key-id",
				consts.FieldAWSSecretAccessKey: "secret-key",
				consts.FieldAWSSTSEndpoint:     "https://sts.custom.endpoint.com",
			},
			expectSTSEndpoint: true,
			expectIAMEndpoint: false,
			stsEndpoint:       "https://sts.custom.endpoint.com",
		},
		{
			name: "with-custom-iam-endpoint",
			params: map[string]interface{}{
				consts.FieldAWSAccessKeyID:     "key-id",
				consts.FieldAWSSecretAccessKey: "secret-key",
				consts.FieldAWSIAMEndpoint:     "https://iam.custom.endpoint.com",
			},
			expectSTSEndpoint: false,
			expectIAMEndpoint: true,
			iamEndpoint:       "https://iam.custom.endpoint.com",
		},
		{
			name: "with-both-custom-endpoints",
			params: map[string]interface{}{
				consts.FieldAWSAccessKeyID:     "key-id",
				consts.FieldAWSSecretAccessKey: "secret-key",
				consts.FieldAWSSTSEndpoint:     "https://sts.custom.endpoint.com",
				consts.FieldAWSIAMEndpoint:     "https://iam.custom.endpoint.com",
			},
			expectSTSEndpoint: true,
			expectIAMEndpoint: true,
			stsEndpoint:       "https://sts.custom.endpoint.com",
			iamEndpoint:       "https://iam.custom.endpoint.com",
		},
		{
			name: "without-custom-endpoints",
			params: map[string]interface{}{
				consts.FieldAWSAccessKeyID:     "key-id",
				consts.FieldAWSSecretAccessKey: "secret-key",
			},
			expectSTSEndpoint: false,
			expectIAMEndpoint: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginAWS{
				AuthLoginCommon: AuthLoginCommon{
					params: tt.params,
				},
			}

			logger := hclog.NewNullLogger()
			config, err := l.getCredentialsConfig(logger)
			if err != nil {
				t.Errorf("getCredentialsConfig() unexpected error = %v", err)
				return
			}

			// Check STS endpoint resolver
			if tt.expectSTSEndpoint {
				if config.STSEndpointResolver == nil {
					t.Error("Expected STSEndpointResolver to be set, but it was nil")
				} else {
					// Verify the resolver returns the correct endpoint
					resolver, ok := config.STSEndpointResolver.(*customSTSEndpointResolver)
					if !ok {
						t.Errorf("STSEndpointResolver is not of type *customSTSEndpointResolver")
					} else if resolver.endpointURL != tt.stsEndpoint {
						t.Errorf("STSEndpointResolver endpointURL = %v, want %v", resolver.endpointURL, tt.stsEndpoint)
					}
				}
			} else {
				if config.STSEndpointResolver != nil {
					t.Error("Expected STSEndpointResolver to be nil, but it was set")
				}
			}

			// Check IAM endpoint resolver
			if tt.expectIAMEndpoint {
				if config.IAMEndpointResolver == nil {
					t.Error("Expected IAMEndpointResolver to be set, but it was nil")
				} else {
					// Verify the resolver returns the correct endpoint
					resolver, ok := config.IAMEndpointResolver.(*customIAMEndpointResolver)
					if !ok {
						t.Errorf("IAMEndpointResolver is not of type *customIAMEndpointResolver")
					} else if resolver.endpointURL != tt.iamEndpoint {
						t.Errorf("IAMEndpointResolver endpointURL = %v, want %v", resolver.endpointURL, tt.iamEndpoint)
					}
				}
			} else {
				if config.IAMEndpointResolver != nil {
					t.Error("Expected IAMEndpointResolver to be nil, but it was set")
				}
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
				AuthLoginCommon: AuthLoginCommon{
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
				AuthLoginCommon: AuthLoginCommon{
					authField: "baz",
					mount:     "foo",
					params: map[string]interface{}{
						consts.FieldRole:               "bob",
						consts.FieldAWSAccessKeyID:     "test-key",
						consts.FieldAWSSecretAccessKey: "test-secret",
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

// TestSignAWSLogin_RegionHandling tests that signAWSLogin properly handles region
// configuration from various sources, especially when using generic auth_login.
// This test addresses issue #2766 where the AWS SDK requires a region to be set.
//
// The test verifies that:
// 1. Explicit sts_region parameter takes highest priority
// 2. AWS_REGION environment variable is used when no explicit parameter
// 3. AWS_DEFAULT_REGION is used as fallback
// 4. awsutil.GetRegion() provides us-east-1 as last resort default
func TestSignAWSLogin_RegionHandling(t *testing.T) {
	tests := []struct {
		name       string
		parameters map[string]interface{}
		envVars    map[string]string
	}{
		{
			name: "region-from-sts_region-parameter",
			parameters: map[string]interface{}{
				"role":       "test-role",
				"sts_region": "eu-west-1",
			},
		},
		{
			name: "region-from-AWS_REGION-env",
			parameters: map[string]interface{}{
				"role": "test-role",
			},
			envVars: map[string]string{
				envVarAWSRegion: "us-west-2",
			},
		},
		{
			name: "region-from-AWS_DEFAULT_REGION-env",
			parameters: map[string]interface{}{
				"role": "test-role",
			},
			envVars: map[string]string{
				envVarAWSDefaultRegion: "ap-southeast-1",
			},
		},
		{
			name: "sts_region-parameter-takes-precedence",
			parameters: map[string]interface{}{
				"role":       "test-role",
				"sts_region": "eu-central-1",
			},
			envVars: map[string]string{
				envVarAWSRegion: "us-east-1",
			},
		},
		{
			name: "fallback-to-us-east-1-when-no-region-configured",
			parameters: map[string]interface{}{
				"role": "test-role",
			},
			// No environment variables set - should default to us-east-1
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables if specified
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}
			// Call signAWSLogin
			err := signAWSLogin(tt.parameters, hclog.NewNullLogger())

			// The key validation: we should NEVER get a "Missing Region" error
			// This was the bug in issue #2766
			if err != nil && containsString(err.Error(), "Missing Region") {
				t.Errorf("signAWSLogin() got 'Missing Region' error which should have been fixed: %v", err)
			}
		})
	}
}

// Helper function to check if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && stringContains(s, substr)))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestGenerateLoginData_IncludesAuthorizationHeader(t *testing.T) {
	awsConfig := &aws.Config{
		Region: "us-east-1",
		Credentials: aws.NewCredentialsCache(
			aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
				return aws.Credentials{
					AccessKeyID:     "test-access-key",
					SecretAccessKey: "test-secret-key",
					SessionToken:    "test-session-token",
					Source:          "unit-test",
				}, nil
			}),
		),
	}

	loginData, err := generateLoginData(context.Background(), awsConfig, "localhost", "")
	if err != nil {
		t.Fatalf("generateLoginData() error = %v", err)
	}

	if got := loginData[consts.FieldIAMHttpRequestMethod]; got != http.MethodPost {
		t.Fatalf("generateLoginData() method = %v, want %v", got, http.MethodPost)
	}

	requestURL, ok := loginData[consts.FieldIAMRequestURL].(string)
	if !ok {
		t.Fatalf("generateLoginData() request URL has unexpected type %T", loginData[consts.FieldIAMRequestURL])
	}
	decodedURL, err := base64.StdEncoding.DecodeString(requestURL)
	if err != nil {
		t.Fatalf("DecodeString(requestURL) error = %v", err)
	}
	if !strings.Contains(string(decodedURL), "sts.us-east-1.amazonaws.com") {
		t.Fatalf("generateLoginData() URL = %q, want regional STS endpoint", string(decodedURL))
	}

	body, ok := loginData[consts.FieldIAMRequestBody].(string)
	if !ok {
		t.Fatalf("generateLoginData() request body has unexpected type %T", loginData[consts.FieldIAMRequestBody])
	}
	decodedBody, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("DecodeString(requestBody) error = %v", err)
	}
	if string(decodedBody) != stsGetCallerIdentityBody {
		t.Fatalf("generateLoginData() body = %q, want %q", string(decodedBody), stsGetCallerIdentityBody)
	}

	headers := decodeAWSLoginHeaders(t, loginData)
	authorization := headers.Get("Authorization")
	if authorization == "" {
		t.Fatal("generateLoginData() did not include Authorization header")
	}
	if !strings.Contains(authorization, "/us-east-1/sts/aws4_request") {
		t.Fatalf("Authorization header = %q, want credential scope containing region", authorization)
	}
	if got := headers.Get("X-Vault-AWS-IAM-Server-ID"); got != "localhost" {
		t.Fatalf("X-Vault-AWS-IAM-Server-ID = %q, want %q", got, "localhost")
	}
	if got := headers.Get("X-Amz-Security-Token"); got != "test-session-token" {
		t.Fatalf("X-Amz-Security-Token = %q, want %q", got, "test-session-token")
	}
	if got := headers.Get("Host"); got != "sts.us-east-1.amazonaws.com" {
		t.Fatalf("Host header = %q, want %q", got, "sts.us-east-1.amazonaws.com")
	}
	if got := headers.Get("Content-Type"); got != stsContentType {
		t.Fatalf("Content-Type = %q, want %q", got, stsContentType)
	}
}

func TestGenerateLoginData_RequiresCredentials(t *testing.T) {
	tests := []struct {
		name      string
		awsConfig *aws.Config
	}{
		{
			name:      "nil config",
			awsConfig: nil,
		},
		{
			name:      "nil credentials",
			awsConfig: &aws.Config{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loginData, err := generateLoginData(context.Background(), tt.awsConfig, "", "")
			if err == nil {
				t.Fatal("generateLoginData() error = nil, want error")
			}
			if err.Error() != "AWS credentials are not configured" {
				t.Fatalf("generateLoginData() error = %q, want %q", err.Error(), "AWS credentials are not configured")
			}
			if loginData != nil {
				t.Fatalf("generateLoginData() loginData = %#v, want nil", loginData)
			}
		})
	}
}

func TestGenerateLoginData_CredentialRetrievalError(t *testing.T) {
	wantErr := errors.New("credential provider failed")
	awsConfig := &aws.Config{
		Region: "us-east-1",
		Credentials: aws.NewCredentialsCache(
			aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
				return aws.Credentials{}, wantErr
			}),
		),
	}

	loginData, err := generateLoginData(context.Background(), awsConfig, "", "")
	if err == nil {
		t.Fatal("generateLoginData() error = nil, want error")
	}

	if !strings.Contains(err.Error(), "failed to retrieve AWS credentials:") {
		t.Fatalf("generateLoginData() error = %q, want wrapped credential retrieval prefix", err.Error())
	}
	if !strings.Contains(err.Error(), wantErr.Error()) {
		t.Fatalf("generateLoginData() error = %q, want underlying credential provider error %q", err.Error(), wantErr.Error())
	}

	if loginData != nil {
		t.Fatalf("generateLoginData() loginData = %#v, want nil", loginData)
	}
}

func TestGenerateLoginData_DefaultsRegionWhenEmpty(t *testing.T) {
	awsConfig := &aws.Config{
		Credentials: aws.NewCredentialsCache(
			aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
				return aws.Credentials{
					AccessKeyID:     "test-access-key",
					SecretAccessKey: "test-secret-key",
					Source:          "unit-test",
				}, nil
			}),
		),
	}

	loginData, err := generateLoginData(context.Background(), awsConfig, "", "")
	if err != nil {
		t.Fatalf("generateLoginData() error = %v", err)
	}

	requestURL, ok := loginData[consts.FieldIAMRequestURL].(string)
	if !ok {
		t.Fatalf("generateLoginData() request URL has unexpected type %T", loginData[consts.FieldIAMRequestURL])
	}

	decodedURL, err := base64.StdEncoding.DecodeString(requestURL)
	if err != nil {
		t.Fatalf("DecodeString(requestURL) error = %v", err)
	}

	wantHost := fmt.Sprintf("sts.%s.amazonaws.com", awsutil.DefaultRegion)
	if !strings.Contains(string(decodedURL), wantHost) {
		t.Fatalf("generateLoginData() URL = %q, want default regional STS endpoint %q", string(decodedURL), wantHost)
	}

	headers := decodeAWSLoginHeaders(t, loginData)
	authorization := headers.Get("Authorization")
	wantScope := fmt.Sprintf("/%s/sts/aws4_request", awsutil.DefaultRegion)
	if !strings.Contains(authorization, wantScope) {
		t.Fatalf("Authorization header = %q, want credential scope containing default region %q", authorization, wantScope)
	}
	if got := headers.Get("Host"); got != wantHost {
		t.Fatalf("Host header = %q, want %q", got, wantHost)
	}
}

func TestGenerateLoginData_UsesCustomSTSEndpoint(t *testing.T) {
	awsConfig := &aws.Config{
		Region: "us-east-1",
		Credentials: aws.NewCredentialsCache(
			aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
				return aws.Credentials{
					AccessKeyID:     "test-access-key",
					SecretAccessKey: "test-secret-key",
					Source:          "unit-test",
				}, nil
			}),
		),
	}

	loginData, err := generateLoginData(context.Background(), awsConfig, "", "https://sts.custom.endpoint.example.com/custom")
	if err != nil {
		t.Fatalf("generateLoginData() error = %v", err)
	}

	requestURL, ok := loginData[consts.FieldIAMRequestURL].(string)
	if !ok {
		t.Fatalf("generateLoginData() request URL has unexpected type %T", loginData[consts.FieldIAMRequestURL])
	}
	decodedURL, err := base64.StdEncoding.DecodeString(requestURL)
	if err != nil {
		t.Fatalf("DecodeString(requestURL) error = %v", err)
	}
	if string(decodedURL) != "https://sts.custom.endpoint.example.com/custom" {
		t.Fatalf("generateLoginData() URL = %q, want custom STS endpoint", string(decodedURL))
	}

	headers := decodeAWSLoginHeaders(t, loginData)
	authorization := headers.Get("Authorization")
	if !strings.Contains(authorization, "/us-east-1/sts/aws4_request") {
		t.Fatalf("Authorization header = %q, want credential scope containing configured region", authorization)
	}
	if got := headers.Get("Host"); got != "sts.custom.endpoint.example.com" {
		t.Fatalf("Host header = %q, want custom endpoint host", got)
	}
}

func TestSignAWSLogin_UsesCustomSTSEndpoint(t *testing.T) {
	parameters := map[string]interface{}{
		consts.FieldAWSAccessKeyID:     "test-access-key",
		consts.FieldAWSSecretAccessKey: "test-secret-key",
		"sts_region":                   "us-east-1",
		consts.FieldAWSSTSEndpoint:     "https://sts.custom.endpoint.example.com/custom",
	}

	if err := signAWSLogin(parameters, hclog.NewNullLogger()); err != nil {
		t.Fatalf("signAWSLogin() error = %v", err)
	}

	requestURL, ok := parameters[consts.FieldIAMRequestURL].(string)
	if !ok {
		t.Fatalf("signAWSLogin() request URL has unexpected type %T", parameters[consts.FieldIAMRequestURL])
	}

	decodedURL, err := base64.StdEncoding.DecodeString(requestURL)
	if err != nil {
		t.Fatalf("DecodeString(requestURL) error = %v", err)
	}
	if string(decodedURL) != "https://sts.custom.endpoint.example.com/custom" {
		t.Fatalf("signAWSLogin() URL = %q, want custom STS endpoint", string(decodedURL))
	}

	headers := decodeAWSLoginHeaders(t, parameters)
	if got := headers.Get("Host"); got != "sts.custom.endpoint.example.com" {
		t.Fatalf("Host header = %q, want custom endpoint host", got)
	}
	authorization := headers.Get("Authorization")
	if !strings.Contains(authorization, "/us-east-1/sts/aws4_request") {
		t.Fatalf("Authorization header = %q, want credential scope containing configured region", authorization)
	}
}

func TestResolveSTSSigningEndpoint(t *testing.T) {
	tests := []struct {
		name         string
		region       string
		endpointURL  string
		wantEndpoint stsSigningEndpoint
		wantErr      string
	}{
		{
			name:        "default regional endpoint",
			region:      "us-east-1",
			endpointURL: "",
			wantEndpoint: stsSigningEndpoint{
				requestURL:    "https://sts.us-east-1.amazonaws.com",
				signingName:   stsSigningName,
				signingRegion: "us-east-1",
			},
		},
		{
			name:        "custom endpoint",
			region:      "us-gov-west-1",
			endpointURL: "https://sts.vpce.example.internal/custom",
			wantEndpoint: stsSigningEndpoint{
				requestURL:    "https://sts.vpce.example.internal/custom",
				signingName:   stsSigningName,
				signingRegion: "us-gov-west-1",
			},
		},
		{
			name:        "invalid custom endpoint",
			region:      "us-east-1",
			endpointURL: "://bad-url",
			wantErr:     "failed to parse custom STS endpoint URL:",
		},
		{
			name:        "missing scheme custom endpoint",
			region:      "us-east-1",
			endpointURL: "sts.internal.example.com",
			wantErr:     "invalid custom STS endpoint URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveSTSSigningEndpoint(tt.region, tt.endpointURL)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("resolveSTSSigningEndpoint() error = nil, want error")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("resolveSTSSigningEndpoint() error = %q, want substring %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("resolveSTSSigningEndpoint() error = %v", err)
			}
			if got != tt.wantEndpoint {
				t.Fatalf("resolveSTSSigningEndpoint() = %#v, want %#v", got, tt.wantEndpoint)
			}
		})
	}
}

func TestBuildSignedGetCallerIdentityRequest(t *testing.T) {
	credentials := aws.Credentials{
		AccessKeyID:     "test-access-key",
		SecretAccessKey: "test-secret-key",
		SessionToken:    "test-session-token",
		Source:          "unit-test",
	}

	tests := []struct {
		name              string
		endpoint          stsSigningEndpoint
		region            string
		headerValue       string
		wantHost          string
		wantSigningRegion string
		wantSigningName   string
		wantHeaderValue   string
	}{
		{
			name: "uses endpoint signing values",
			endpoint: stsSigningEndpoint{
				requestURL:    "https://sts.custom.endpoint.example.com/custom",
				signingName:   "execute-api",
				signingRegion: "us-gov-west-1",
			},
			region:            "us-east-1",
			headerValue:       "localhost",
			wantHost:          "sts.custom.endpoint.example.com",
			wantSigningRegion: "us-gov-west-1",
			wantSigningName:   "execute-api",
			wantHeaderValue:   "localhost",
		},
		{
			name: "falls back to function inputs",
			endpoint: stsSigningEndpoint{
				requestURL: "https://sts.us-west-2.amazonaws.com",
			},
			region:            "us-west-2",
			wantHost:          "sts.us-west-2.amazonaws.com",
			wantSigningRegion: "us-west-2",
			wantSigningName:   stsSigningName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, body, err := buildSignedGetCallerIdentityRequest(context.Background(), credentials, tt.endpoint, tt.region, tt.headerValue)
			if err != nil {
				t.Fatalf("buildSignedGetCallerIdentityRequest() error = %v", err)
			}

			if req.Method != http.MethodPost {
				t.Fatalf("request method = %q, want %q", req.Method, http.MethodPost)
			}
			if req.URL.String() != tt.endpoint.requestURL {
				t.Fatalf("request URL = %q, want %q", req.URL.String(), tt.endpoint.requestURL)
			}
			if body != stsGetCallerIdentityBody {
				t.Fatalf("request body = %q, want %q", body, stsGetCallerIdentityBody)
			}
			if got := req.Header.Get("Content-Type"); got != stsContentType {
				t.Fatalf("Content-Type = %q, want %q", got, stsContentType)
			}
			if got := req.Header.Get("X-Vault-AWS-IAM-Server-ID"); got != tt.wantHeaderValue {
				t.Fatalf("X-Vault-AWS-IAM-Server-ID = %q, want %q", got, tt.wantHeaderValue)
			}
			if got := req.Header.Get("X-Amz-Security-Token"); got != credentials.SessionToken {
				t.Fatalf("X-Amz-Security-Token = %q, want %q", got, credentials.SessionToken)
			}
			if got := req.URL.Host; got != tt.wantHost {
				t.Fatalf("request URL host = %q, want %q", got, tt.wantHost)
			}

			authorization := req.Header.Get("Authorization")
			wantScope := fmt.Sprintf("/%s/%s/aws4_request", tt.wantSigningRegion, tt.wantSigningName)
			if !strings.Contains(authorization, wantScope) {
				t.Fatalf("Authorization = %q, want credential scope containing %q", authorization, wantScope)
			}
		})
	}
}

func decodeAWSLoginHeaders(t *testing.T, loginData map[string]interface{}) http.Header {
	t.Helper()

	encodedHeaders, ok := loginData[consts.FieldIAMRequestHeaders].(string)
	if !ok {
		t.Fatalf("generateLoginData() request headers have unexpected type %T", loginData[consts.FieldIAMRequestHeaders])
	}

	decodedHeaders, err := base64.StdEncoding.DecodeString(encodedHeaders)
	if err != nil {
		t.Fatalf("DecodeString(requestHeaders) error = %v", err)
	}

	var headers http.Header
	if err := json.Unmarshal(decodedHeaders, &headers); err != nil {
		t.Fatalf("json.Unmarshal(requestHeaders) error = %v", err)
	}

	return headers
}
