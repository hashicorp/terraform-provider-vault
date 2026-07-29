// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testMount         = "my-azure"
	testRole          = "my-role"
	testGraphScope    = "https://graph.microsoft.com/.default"
	testTokenType     = "Bearer"
	testExpiresIn     = float64(3599)
	testExpiresInAlt  = float64(1800)
)

// newFakeVaultClient creates a Vault API client pointed at a test HTTP server.
func newFakeVaultClient(t *testing.T, server *httptest.Server) *api.Client {
	t.Helper()
	cfg := api.DefaultConfig()
	cfg.Address = server.URL
	cli, err := api.NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create Vault client: %v", err)
	}
	return cli
}

// newAzureTokenServer starts an httptest.Server that records the request path
// and scope, validates the HTTP method, then responds with tc.handlerStatus and
// tc.handlerPayload. The returned pointers are populated on the first request.
func newAzureTokenServer(t *testing.T, status int, payload interface{}) (*httptest.Server, *string, *string) {
	t.Helper()
	gotPath := new(string)
	gotScope := new(string)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*gotPath = r.URL.Path

		if r.Method != http.MethodPut {
			t.Errorf("method = %s, want PUT", r.Method)
		}

		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			if s, ok := body["scope"].(string); ok {
				*gotScope = s
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(payload)
	}))

	return server, gotPath, gotScope
}

// makeErrorPayload builds the Vault error response map used by handler stubs.
func makeErrorPayload(msg string) map[string]interface{} {
	return map[string]interface{}{
		"errors": []string{msg},
	}
}

// makeTokenPayload builds the nested Vault response map used by handler stubs.
// ext_expires_in is always set equal to expires_in, matching all current cases.
func makeTokenPayload(token, tokenType string, expiresIn float64) map[string]interface{} {
	return map[string]interface{}{
		"data": map[string]interface{}{
			"access_token":   token,
			"token_type":     tokenType,
			"expires_in":     expiresIn,
			"ext_expires_in": expiresIn,
		},
	}
}

func TestRequestAzureAccessToken(t *testing.T) {
	cases := map[string]struct {
		mount          string
		role           string
		scope          string
		handlerStatus  int
		handlerPayload interface{}
		wantErr        bool
		wantErrContain string
		wantToken      string
		wantTokenType  string
		wantExpiresIn  int64
		wantPath       string
	}{
		"success": {
			mount:          testMount,
			role:           testRole,
			scope:          testGraphScope,
			handlerStatus:  http.StatusOK,
			handlerPayload: makeTokenPayload("eyJ0eXAiOiJKV1Q.test-token", testTokenType, testExpiresIn),
			wantToken:      "eyJ0eXAiOiJKV1Q.test-token",
			wantTokenType:  testTokenType,
			wantExpiresIn: int64(testExpiresIn),
			wantPath:      "/v1/my-azure/token/my-role",
		},
		"alternate mount and role in path": {
			mount:          "azure",
			role:           "reader",
			scope:          testGraphScope,
			handlerStatus:  http.StatusOK,
			handlerPayload: makeTokenPayload("tok", testTokenType, testExpiresInAlt),
			wantToken:      "tok",
			wantTokenType:  testTokenType,
			wantExpiresIn: int64(testExpiresInAlt),
			wantPath:      "/v1/azure/token/reader",
		},
		"vault returns 404 - role not found": {
			mount:          testMount,
			role:           "missing-role",
			scope:          testGraphScope,
			handlerStatus:  http.StatusNotFound,
			handlerPayload: makeErrorPayload(`static role "missing-role" not found`),
			wantErr:        true,
			wantErrContain: "unable to write to Vault",
		},
		"vault returns 500 - internal error": {
			mount:          testMount,
			role:           testRole,
			scope:          testGraphScope,
			handlerStatus:  http.StatusInternalServerError,
			handlerPayload: makeErrorPayload("internal server error"),
			wantErr:        true,
			wantErrContain: "unable to write to Vault",
		},
		"vault returns empty data - no access_token field": {
			mount:         testMount,
			role:          testRole,
			scope:         testGraphScope,
			handlerStatus: http.StatusOK,
			handlerPayload: map[string]interface{}{
				"data": map[string]interface{}{},
			},
			wantErr:        true,
			wantErrContain: "access_token missing",
		},
		"scope sent in request body": {
			mount:          testMount,
			role:           testRole,
			scope:          "https://management.azure.com/.default",
			handlerStatus:  http.StatusOK,
			handlerPayload: makeTokenPayload("mgmt-token", testTokenType, testExpiresIn),
			wantToken:      "mgmt-token",
			wantTokenType:  testTokenType,
			wantExpiresIn: int64(testExpiresIn),
			wantPath:      "/v1/my-azure/token/my-role",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Arrange
			server, gotPath, gotScope := newAzureTokenServer(t, tc.handlerStatus, tc.handlerPayload)
			defer server.Close()
			cli := newFakeVaultClient(t, server)

			// Act
			got, err := requestAzureAccessToken(context.Background(), cli, tc.mount, tc.role, tc.scope)

			// Assert
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErrContain)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.wantPath, *gotPath)
			assert.Equal(t, tc.scope, *gotScope)
			assert.Equal(t, tc.wantToken, got.AccessToken)
			assert.Equal(t, tc.wantTokenType, got.TokenType)
			assert.Equal(t, tc.wantExpiresIn, got.ExpiresIn)
			assert.Equal(t, tc.wantExpiresIn, got.ExtExpiresIn)
		})
	}
}
