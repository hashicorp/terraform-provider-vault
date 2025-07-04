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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

// AWS test constants for mock STS responses and test data
const (
	mockRoleAccessKeyID     = "AKIAMOCKEDROLE"
	mockRoleSecretAccessKey = "MockedRoleSecret"
	mockRoleSessionToken    = "MockedRoleToken"
	mockRoleAssumedRoleID   = "AROAMOCKEDROLE:test-session"

	mockWebAccessKeyID     = "AKIAMOCKEDWEB"
	mockWebSecretAccessKey = "MockedWebSecret"
	mockWebSessionToken    = "MockedWebToken"
	mockWebAssumedRoleID   = "AROAMOCKEDWEB:web-session"

	testProfileAccessKeyID     = "profile-access-key"
	testProfileSecretAccessKey = "profile-secret-key"

	testAWSAccountID   = "123456789012"
	testRoleName       = "TestRole"
	testSessionName    = "test-session"
	testWebSessionName = "web-session"
)

var (
	testRoleARN           = fmt.Sprintf("arn:aws:iam::%s:role/%s", testAWSAccountID, testRoleName)
	testAssumedRoleARN    = fmt.Sprintf("arn:aws:sts::%s:assumed-role/%s/%s", testAWSAccountID, testRoleName, testSessionName)
	testWebAssumedRoleARN = fmt.Sprintf("arn:aws:sts::%s:assumed-role/%s/%s", testAWSAccountID, testRoleName, testWebSessionName)
)

// helper function to create temp profile and shared credentials
func setupTestAWSProfile(t *testing.T, profileName string) (configFile, credentialsFile string, cleanup func()) {
	tempDir, err := os.MkdirTemp("", "aws-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	configFile = filepath.Join(tempDir, "config")
	configContent := fmt.Sprintf(`[profile %s]
region = us-east-1
output = json
`, profileName)

	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to write config file: %v", err)
	}

	credentialsFile = filepath.Join(tempDir, "credentials")
	credentialsContent := fmt.Sprintf(`[%s]
aws_access_key_id = %s
aws_secret_access_key = %s
`, profileName, testProfileAccessKeyID, testProfileSecretAccessKey)

	if err := os.WriteFile(credentialsFile, []byte(credentialsContent), 0644); err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to write credentials file: %v", err)
	}

	cleanup = func() {
		os.RemoveAll(tempDir)
	}

	return configFile, credentialsFile, cleanup
}

// helper function to create temp web identity token file
func setupTestWebIdentityToken(t *testing.T) (tokenFile string, cleanup func()) {
	tempDir, err := os.MkdirTemp("", "aws-token-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	tokenFile = filepath.Join(tempDir, "token")
	tokenContent := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL29pZGMuZXhhbXBsZS5jb20iLCJzdWIiOiJ0ZXN0LXVzZXIiLCJhdWQiOiJzdHMuYW1hem9uYXdzLmNvbSIsImV4cCI6MTYzMDQ2MDAwMCwiaWF0IjoxNjMwNDU2NDAwfQ.test-signature"

	if err := os.WriteFile(tokenFile, []byte(tokenContent), 0644); err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to write token file: %v", err)
	}

	cleanup = func() {
		os.RemoveAll(tempDir)
	}

	return tokenFile, cleanup
}

type mockSTSClient struct{}

func (m *mockSTSClient) AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	return &sts.AssumeRoleOutput{
		Credentials: &types.Credentials{
			AccessKeyId:     aws.String(mockRoleAccessKeyID),
			SecretAccessKey: aws.String(mockRoleSecretAccessKey),
			SessionToken:    aws.String(mockRoleSessionToken),
			Expiration:      aws.Time(time.Now().Add(time.Hour)),
		},
		AssumedRoleUser: &types.AssumedRoleUser{
			Arn:           aws.String(testAssumedRoleARN),
			AssumedRoleId: aws.String(mockRoleAssumedRoleID),
		},
	}, nil
}

func (m *mockSTSClient) AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	return &sts.AssumeRoleWithWebIdentityOutput{
		Credentials: &types.Credentials{
			AccessKeyId:     aws.String(mockWebAccessKeyID),
			SecretAccessKey: aws.String(mockWebSecretAccessKey),
			SessionToken:    aws.String(mockWebSessionToken),
			Expiration:      aws.Time(time.Now().Add(time.Hour)),
		},
		AssumedRoleUser: &types.AssumedRoleUser{
			Arn:           aws.String(testWebAssumedRoleARN),
			AssumedRoleId: aws.String(mockWebAssumedRoleID),
		},
	}, nil
}

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

// aws config building from credential parameters
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
						consts.FieldAWSSTSEndpoint:          "sts.us-east-2.amazonaws.com",
						consts.FieldAWSRegion:               "us-east-2",
						consts.FieldAWSRoleARN:              testRoleARN,
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
				if credParams.Region != "us-east-2" {
					t.Errorf("expected Region = us-east-2, got %s", credParams.Region)
				}
				if credParams.RoleARN != testRoleARN {
					t.Errorf("expected RoleARN = %s, got %s", testRoleARN, credParams.RoleARN)
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

			credParams, err := l.collectCredentialParams()
			if (err != nil) != tt.wantErr {
				t.Errorf("collectCredentialParams() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				// we should have gotten err from collectCredentialParams
				return
			}

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

			if tt.validateConfig != nil {
				tt.validateConfig(t, cfg, credParams)
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

// test credential provider precedence order of identity (static > role > shared creds > env)
func TestAuthLoginAWS_CredentialProviderPrecedence(t *testing.T) {
	tests := []struct {
		name                    string
		params                  map[string]interface{}
		expectStaticCredentials bool
		expectAssumeRole        bool
		expectSharedCredentials bool
		generateProfile         bool
		expectRegion            string
	}{
		// 1. simple cases w or w/o role assumption
		{
			name: "static-credentials-only",
			params: map[string]interface{}{
				consts.FieldAWSAccessKeyID:     "test-key",
				consts.FieldAWSSecretAccessKey: "test-secret",
				consts.FieldAWSRegion:          "us-east-1",
			},
			expectStaticCredentials: true,
			expectAssumeRole:        false,
			expectSharedCredentials: false,
			generateProfile:         false,
			expectRegion:            "us-east-1",
		},
		{
			name: "static-credentials-with-role",
			params: map[string]interface{}{
				consts.FieldAWSAccessKeyID:     "test-key",
				consts.FieldAWSSecretAccessKey: "test-secret",
				consts.FieldAWSRoleARN:         testRoleARN,
				consts.FieldAWSRoleSessionName: "test-session",
				consts.FieldAWSRegion:          "us-east-1",
			},
			expectStaticCredentials: false, // role assumption should wrap static credentials
			expectAssumeRole:        true,
			expectSharedCredentials: false,
			generateProfile:         false,
			expectRegion:            "us-east-1",
		},
		{
			name: "profile-with-role",
			params: map[string]interface{}{
				consts.FieldAWSProfile:         "test-profile",
				consts.FieldAWSRoleARN:         testRoleARN,
				consts.FieldAWSRoleSessionName: "test-session",
			},
			expectStaticCredentials: false,
			expectAssumeRole:        true,
			expectSharedCredentials: false,
			generateProfile:         true,
		},
		{
			name: "profile-only",
			params: map[string]interface{}{
				consts.FieldAWSProfile: "test-profile",
			},
			expectStaticCredentials: false,
			expectAssumeRole:        false,
			expectSharedCredentials: true,
			generateProfile:         true,
		},

		// 2. precedence tests - when multiple credential sources are available
		{
			name: "precedence-static-over-profile",
			params: map[string]interface{}{
				consts.FieldAWSAccessKeyID:     "test-key",
				consts.FieldAWSSecretAccessKey: "test-secret",
				consts.FieldAWSProfile:         "test-profile",
				consts.FieldAWSRegion:          "us-east-1",
			},
			expectStaticCredentials: true, // static should take precedence
			expectAssumeRole:        false,
			expectSharedCredentials: false,
			generateProfile:         true, // profile mentioned but won't be used
			expectRegion:            "us-east-1",
		},
		{
			name: "precedence-role-over-static",
			params: map[string]interface{}{
				consts.FieldAWSAccessKeyID:     "test-key",
				consts.FieldAWSSecretAccessKey: "test-secret",
				consts.FieldAWSRoleARN:         testRoleARN,
				consts.FieldAWSRoleSessionName: "test-session",
				consts.FieldAWSRegion:          "us-east-1",
			},
			expectStaticCredentials: false, // Role should take precedence over static
			expectAssumeRole:        true,
			expectSharedCredentials: false,
			generateProfile:         false,
			expectRegion:            "us-east-1",
		},
		{
			name: "precedence-static-and-profile-with-role",
			params: map[string]interface{}{
				// Static, profile, and role all provided
				consts.FieldAWSAccessKeyID:     "test-key",
				consts.FieldAWSSecretAccessKey: "test-secret",
				consts.FieldAWSProfile:         "test-profile",
				consts.FieldAWSRoleARN:         testRoleARN,
				consts.FieldAWSRoleSessionName: "test-session",
				consts.FieldAWSRegion:          "us-east-1",
			},
			expectStaticCredentials: false, // Role takes precedence
			expectAssumeRole:        true,  // Role wraps the static credentials (not profile)
			expectSharedCredentials: false,
			generateProfile:         true, // profile mentioned but won't be used
			expectRegion:            "us-east-1",
		},
		{
			name: "precedence-web-identity-over-static",
			params: map[string]interface{}{
				// Static credentials and web identity token
				consts.FieldAWSAccessKeyID:          "test-key",
				consts.FieldAWSSecretAccessKey:      "test-secret",
				consts.FieldAWSRoleARN:              testRoleARN,
				consts.FieldAWSWebIdentityTokenFile: "/tmp/token",
				consts.FieldAWSRegion:               "us-east-1",
			},
			expectStaticCredentials: false, // Web identity role assumption takes precedence
			expectAssumeRole:        true,  // implies AssumeRoleWithWebIdentity
			expectSharedCredentials: false,
			generateProfile:         false,
			expectRegion:            "us-east-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cleanup func()
			params := make(map[string]interface{})
			for k, v := range tt.params {
				params[k] = v
			}

			// setup test AWS profile if needed
			if tt.generateProfile {
				configFile, credentialsFile, cleanupFunc := setupTestAWSProfile(t, "test-profile")
				cleanup = cleanupFunc

				t.Setenv("AWS_CONFIG_FILE", configFile)
				t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credentialsFile)
			}

			// setup temporary token file for web identity tests
			if tokenFile, exists := params[consts.FieldAWSWebIdentityTokenFile]; exists && tokenFile == "/tmp/token" {
				actualTokenFile, tokenCleanup := setupTestWebIdentityToken(t)
				params[consts.FieldAWSWebIdentityTokenFile] = actualTokenFile
				if cleanup != nil {
					originalCleanup := cleanup
					cleanup = func() {
						originalCleanup()
						tokenCleanup()
					}
				} else {
					cleanup = tokenCleanup
				}
			}

			if cleanup != nil {
				defer cleanup()
			}

			l := &AuthLoginAWS{
				AuthLoginCommon: AuthLoginCommon{
					params: params,
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
			var cfg *aws.Config
			if tt.expectAssumeRole {
				// Use mock STS client for role assumption tests
				mockSTS := &mockSTSClient{}
				cfg, err = buildAWSConfig(ctx, &credParams, WithSTSClient(mockSTS))
			} else {
				// Use standard config for non-role tests
				cfg, err = buildAWSConfig(ctx, &credParams)
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

			// retrieve creds for non-role tests
			//if !tt.expectAssumeRole {
			creds, err := cfg.Credentials.Retrieve(ctx)

			if err != nil {
				t.Fatalf("Failed to retrieve credentials: %v", err)
			}

			// verify the credential source based on test expectations
			if tt.expectAssumeRole {
				// For role assumption scenarios, verify we got mock STS credentials
				if tt.params[consts.FieldAWSWebIdentityTokenFile] != nil {
					// Web identity role assumption should return web identity mock credentials
					if creds.AccessKeyID != mockWebAccessKeyID {
						t.Errorf("Expected web identity mock credentials with AccessKeyID %s, got %s", mockWebAccessKeyID, creds.AccessKeyID)
					}
					if creds.SecretAccessKey != mockWebSecretAccessKey {
						t.Errorf("Expected web identity mock credentials with SecretAccessKey %s, got %s", mockWebSecretAccessKey, creds.SecretAccessKey)
					}
					if creds.SessionToken != mockWebSessionToken {
						t.Errorf("Expected web identity mock credentials with SessionToken %s, got %s", mockWebSessionToken, creds.SessionToken)
					}
				} else {
					// Regular role assumption should return role mock credentials
					if creds.AccessKeyID != mockRoleAccessKeyID {
						t.Errorf("Expected role mock credentials with AccessKeyID %s, got %s", mockRoleAccessKeyID, creds.AccessKeyID)
					}
					if creds.SecretAccessKey != mockRoleSecretAccessKey {
						t.Errorf("Expected role mock credentials with SecretAccessKey %s, got %s", mockRoleSecretAccessKey, creds.SecretAccessKey)
					}
					if creds.SessionToken != mockRoleSessionToken {
						t.Errorf("Expected role mock credentials with SessionToken %s, got %s", mockRoleSessionToken, creds.SessionToken)
					}
				}
			} else if tt.expectStaticCredentials {
				// For static credential scenarios, verify we got the configured static credentials
				if credParams.AccessKey != "" && creds.AccessKeyID != credParams.AccessKey {
					t.Errorf("Expected static credentials with AccessKey %s, got %s", credParams.AccessKey, creds.AccessKeyID)
				}
				if credParams.SecretKey != "" && creds.SecretAccessKey != credParams.SecretKey {
					t.Errorf("Expected static credentials with SecretKey %s, got %s", credParams.SecretKey, creds.SecretAccessKey)
				}
			} else if tt.expectSharedCredentials {
				// For shared credentials (profile), verify we got profile credentials
				if creds.AccessKeyID != testProfileAccessKeyID {
					t.Errorf("Expected profile credentials with AccessKeyID %s, got %s", testProfileAccessKeyID, creds.AccessKeyID)
				}
				if creds.SecretAccessKey != testProfileSecretAccessKey {
					t.Errorf("Expected profile credentials with SecretAccessKey %s, got %s", testProfileSecretAccessKey, creds.SecretAccessKey)
				}
			}
			//}

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

// TestCustomEndpoints verifies that custom STS and IAM endpoints are properly included in generated requests
func TestCustomEndpoints(t *testing.T) {
	tests := []struct {
		name        string
		stsEndpoint string
		roleARN     string
		staticCreds bool
	}{
		{
			name:        "custom-sts-endpoint-static-creds",
			stsEndpoint: "https://custom-sts.example.com",
			staticCreds: true,
		},
		{
			name:        "custom-sts-endpoint-with-role",
			stsEndpoint: "https://custom-sts.example.com",
			roleARN:     testRoleARN,
			staticCreds: true,
		},
		{
			name:        "vpc-endpoint-sts",
			stsEndpoint: "https://vpce-1234567890abcdef0-12345678.sts.us-west-2.vpce.amazonaws.com",
			staticCreds: true,
		},
		{
			name:        "localstack-endpoint",
			stsEndpoint: "http://localhost:4566",
			staticCreds: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build credential parameters
			credParams := credentialsParams{
				Region:      "us-east-1",
				STSEndpoint: tt.stsEndpoint,
			}

			if tt.staticCreds {
				credParams.AccessKey = "test-access-key"
				credParams.SecretKey = "test-secret-key"
			}

			if tt.roleARN != "" {
				credParams.RoleARN = tt.roleARN
				credParams.RoleSessionName = "test-session"
			}

			ctx := context.Background()

			var cfg *aws.Config
			var err error
			if tt.roleARN != "" {
				// Use mock STS client for role assumption
				mockSTS := &mockSTSClient{}
				cfg, err = buildAWSConfig(ctx, &credParams, WithSTSClient(mockSTS))
			} else {
				cfg, err = buildAWSConfig(ctx, &credParams)
			}

			if err != nil {
				t.Fatalf("buildAWSConfig() failed: %v", err)
			}

			// Test generateLoginData to verify STS endpoint usage
			loginData, err := generateLoginData(cfg, "", credParams.Region, credParams.STSEndpoint)
			if err != nil {
				t.Fatalf("generateLoginData() failed: %v", err)
			}

			// Verify login data contains expected fields
			expectedFields := []string{
				consts.FieldIAMHttpRequestMethod,
				consts.FieldIAMRequestURL,
				consts.FieldIAMRequestBody,
				consts.FieldIAMRequestHeaders,
			}

			for _, field := range expectedFields {
				if _, ok := loginData[field]; !ok {
					t.Errorf("Missing expected field %s in login data", field)
				}
			}

			// Verify that custom STS endpoint was used by checking the URL in login data
			if tt.stsEndpoint != "" {
				if urlB64, ok := loginData[consts.FieldIAMRequestURL].(string); ok {
					urlBytes, err := base64.StdEncoding.DecodeString(urlB64)
					if err != nil {
						t.Fatalf("Failed to decode URL: %v", err)
					}
					urlStr := string(urlBytes)

					// Verify the custom endpoint is used in the generated URL
					expectedHost := ""
					if strings.HasPrefix(tt.stsEndpoint, "https://") {
						expectedHost = strings.TrimPrefix(tt.stsEndpoint, "https://")
					} else if strings.HasPrefix(tt.stsEndpoint, "http://") {
						expectedHost = strings.TrimPrefix(tt.stsEndpoint, "http://")
					}

					if expectedHost != "" && !strings.Contains(urlStr, expectedHost) {
						t.Errorf("Expected URL to contain custom STS endpoint host %s, got %s", expectedHost, urlStr)
					}

					t.Logf("Successfully generated request with custom STS endpoint: %s", urlStr)
				}
			}

			// Verify request method and body are correct
			if method, ok := loginData[consts.FieldIAMHttpRequestMethod].(string); ok {
				if method != "POST" {
					t.Errorf("Expected method POST, got %s", method)
				}
			}

			if bodyB64, ok := loginData[consts.FieldIAMRequestBody].(string); ok {
				bodyBytes, err := base64.StdEncoding.DecodeString(bodyB64)
				if err != nil {
					t.Fatalf("Failed to decode body: %v", err)
				}
				body := string(bodyBytes)
				if !strings.Contains(body, "Action=GetCallerIdentity") {
					t.Errorf("Expected body to contain GetCallerIdentity action, got %s", body)
				}
			}
		})
	}
}
