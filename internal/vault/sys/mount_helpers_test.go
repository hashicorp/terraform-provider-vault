// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

// TestMain suppresses log output during tests to reduce noise.
// Log messages can still be seen by setting the VAULT_LOG environment variable.
func TestMain(m *testing.M) {
	// Suppress log output unless explicitly requested
	if os.Getenv("VAULT_LOG") == "" {
		log.SetOutput(io.Discard)
	}
	os.Exit(m.Run())
}

// mockProviderMeta creates a mock provider meta for testing.
func mockProviderMeta(t *testing.T) interface{} {
	s := map[string]*schema.Schema{
		consts.FieldSkipGetVaultVersion: {
			Type:     schema.TypeBool,
			Optional: true,
			Default:  true,
		},
	}

	d := schema.TestResourceDataRaw(t, s, map[string]interface{}{
		consts.FieldSkipGetVaultVersion: true,
	})

	meta, _ := provider.NewProviderMeta(d)
	return meta
}

func TestMountHelper_CreateMount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		input          *MountModel
		validateServer func(t *testing.T, r *http.Request)
		wantErr        bool
	}{
		{
			name: "basic-mount",
			input: &MountModel{
				Path:                      types.StringValue("test-mount"),
				Type:                      types.StringValue("kv"),
				Description:               types.StringValue("test description"),
				DefaultLeaseTTLSeconds:    types.Int64Value(3600),
				MaxLeaseTTLSeconds:        types.Int64Value(7200),
				ForceNoCache:              types.BoolValue(false),
				Local:                     types.BoolValue(true),
				SealWrap:                  types.BoolValue(false),
				ExternalEntropyAccess:     types.BoolValue(false),
				Options:                   types.MapNull(types.StringType),
				AuditNonHMACRequestKeys:   types.ListNull(types.StringType),
				AuditNonHMACResponseKeys:  types.ListNull(types.StringType),
				AllowedManagedKeys:        types.SetNull(types.StringType),
				PassthroughRequestHeaders: types.ListNull(types.StringType),
				AllowedResponseHeaders:    types.ListNull(types.StringType),
				DelegatedAuthAccessors:    types.ListNull(types.StringType),
				ListingVisibility:         types.StringNull(),
				PluginVersion:             types.StringNull(),
				IdentityTokenKey:          types.StringNull(),
			},
			validateServer: func(t *testing.T, r *http.Request) {
				var input api.MountInput
				require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
				assert.Equal(t, "kv", input.Type)
				assert.Equal(t, "test description", input.Description)
				assert.Equal(t, "3600s", input.Config.DefaultLeaseTTL)
				assert.Equal(t, "7200s", input.Config.MaxLeaseTTL)
				assert.True(t, input.Local)
			},
			wantErr: false,
		},
		{
			name: "with-options",
			input: func() *MountModel {
				optionsMap, _ := types.MapValue(types.StringType, map[string]attr.Value{
					"version":      types.StringValue("2"),
					"cas_required": types.StringValue("true"),
				})
				return &MountModel{
					Path:                      types.StringValue("test-mount"),
					Type:                      types.StringValue("kv"),
					Description:               types.StringValue("test"),
					DefaultLeaseTTLSeconds:    types.Int64Value(0),
					MaxLeaseTTLSeconds:        types.Int64Value(0),
					ForceNoCache:              types.BoolValue(false),
					Local:                     types.BoolValue(false),
					SealWrap:                  types.BoolValue(false),
					ExternalEntropyAccess:     types.BoolValue(false),
					Options:                   optionsMap,
					AuditNonHMACRequestKeys:   types.ListNull(types.StringType),
					AuditNonHMACResponseKeys:  types.ListNull(types.StringType),
					AllowedManagedKeys:        types.SetNull(types.StringType),
					PassthroughRequestHeaders: types.ListNull(types.StringType),
					AllowedResponseHeaders:    types.ListNull(types.StringType),
					DelegatedAuthAccessors:    types.ListNull(types.StringType),
					ListingVisibility:         types.StringNull(),
					PluginVersion:             types.StringNull(),
					IdentityTokenKey:          types.StringNull(),
				}
			}(),
			validateServer: func(t *testing.T, r *http.Request) {
				var input api.MountInput
				require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
				assert.Len(t, input.Options, 2)
				assert.Equal(t, "2", input.Options["version"])
				assert.Equal(t, "true", input.Options["cas_required"])
			},
			wantErr: false,
		},
		{
			name: "with-audit-keys",
			input: func() *MountModel {
				ctx := context.Background()
				requestKeys, _ := types.ListValueFrom(ctx, types.StringType, []string{"key1", "key2"})
				responseKeys, _ := types.ListValueFrom(ctx, types.StringType, []string{"response_key"})
				return &MountModel{
					Path:                      types.StringValue("test-mount"),
					Type:                      types.StringValue("kv"),
					Description:               types.StringValue("test"),
					DefaultLeaseTTLSeconds:    types.Int64Value(0),
					MaxLeaseTTLSeconds:        types.Int64Value(0),
					ForceNoCache:              types.BoolValue(false),
					Local:                     types.BoolValue(false),
					SealWrap:                  types.BoolValue(false),
					ExternalEntropyAccess:     types.BoolValue(false),
					Options:                   types.MapNull(types.StringType),
					AuditNonHMACRequestKeys:   requestKeys,
					AuditNonHMACResponseKeys:  responseKeys,
					AllowedManagedKeys:        types.SetNull(types.StringType),
					PassthroughRequestHeaders: types.ListNull(types.StringType),
					AllowedResponseHeaders:    types.ListNull(types.StringType),
					DelegatedAuthAccessors:    types.ListNull(types.StringType),
					ListingVisibility:         types.StringNull(),
					PluginVersion:             types.StringNull(),
					IdentityTokenKey:          types.StringNull(),
				}
			}(),
			validateServer: func(t *testing.T, r *http.Request) {
				var input api.MountInput
				require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
				assert.Len(t, input.Config.AuditNonHMACRequestKeys, 2)
				assert.Len(t, input.Config.AuditNonHMACResponseKeys, 1)
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/mounts/test-mount" && r.Method == http.MethodPost {
					if tt.validateServer != nil {
						tt.validateServer(t, r)
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				http.NotFound(w, r)
			}))
			defer server.Close()

			config := api.DefaultConfig()
			config.Address = server.URL
			client, err := api.NewClient(config)
			require.NoError(t, err)

			meta := mockProviderMeta(t)
			ctx := context.Background()

			err = CreateMount(ctx, client, tt.input, tt.input.Type.ValueString(), meta)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMountHelper_UpdateMount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		data           *MountModel
		state          *MountModel
		validateServer func(t *testing.T, r *http.Request)
		wantErr        bool
	}{
		{
			name: "basic-update",
			state: &MountModel{
				DefaultLeaseTTLSeconds:    types.Int64Value(3600),
				MaxLeaseTTLSeconds:        types.Int64Value(7200),
				Options:                   types.MapNull(types.StringType),
				AuditNonHMACRequestKeys:   types.ListNull(types.StringType),
				AuditNonHMACResponseKeys:  types.ListNull(types.StringType),
				Description:               types.StringValue("old description"),
				AllowedManagedKeys:        types.SetNull(types.StringType),
				PassthroughRequestHeaders: types.ListNull(types.StringType),
				AllowedResponseHeaders:    types.ListNull(types.StringType),
				DelegatedAuthAccessors:    types.ListNull(types.StringType),
				ListingVisibility:         types.StringNull(),
				PluginVersion:             types.StringNull(),
				IdentityTokenKey:          types.StringNull(),
			},
			data: &MountModel{
				DefaultLeaseTTLSeconds:    types.Int64Value(7200),
				MaxLeaseTTLSeconds:        types.Int64Value(14400),
				Options:                   types.MapNull(types.StringType),
				AuditNonHMACRequestKeys:   types.ListNull(types.StringType),
				AuditNonHMACResponseKeys:  types.ListNull(types.StringType),
				Description:               types.StringValue("old description"),
				AllowedManagedKeys:        types.SetNull(types.StringType),
				PassthroughRequestHeaders: types.ListNull(types.StringType),
				AllowedResponseHeaders:    types.ListNull(types.StringType),
				DelegatedAuthAccessors:    types.ListNull(types.StringType),
				ListingVisibility:         types.StringNull(),
				PluginVersion:             types.StringNull(),
				IdentityTokenKey:          types.StringNull(),
			},
			validateServer: func(t *testing.T, r *http.Request) {
				var config map[string]interface{}
				require.NoError(t, json.NewDecoder(r.Body).Decode(&config))
				assert.Equal(t, "7200s", config["default_lease_ttl"])
				assert.Equal(t, "14400s", config["max_lease_ttl"])
			},
			wantErr: false,
		},
		{
			name: "only-changed-fields",
			state: &MountModel{
				DefaultLeaseTTLSeconds:    types.Int64Value(3600),
				MaxLeaseTTLSeconds:        types.Int64Value(7200),
				Options:                   types.MapNull(types.StringType),
				AuditNonHMACRequestKeys:   types.ListNull(types.StringType),
				AuditNonHMACResponseKeys:  types.ListNull(types.StringType),
				Description:               types.StringValue("old description"),
				AllowedManagedKeys:        types.SetNull(types.StringType),
				PassthroughRequestHeaders: types.ListNull(types.StringType),
				AllowedResponseHeaders:    types.ListNull(types.StringType),
				DelegatedAuthAccessors:    types.ListNull(types.StringType),
				ListingVisibility:         types.StringValue("unauth"),
				PluginVersion:             types.StringNull(),
				IdentityTokenKey:          types.StringNull(),
			},
			data: &MountModel{
				DefaultLeaseTTLSeconds:    types.Int64Value(3600),
				MaxLeaseTTLSeconds:        types.Int64Value(7200),
				Options:                   types.MapNull(types.StringType),
				AuditNonHMACRequestKeys:   types.ListNull(types.StringType),
				AuditNonHMACResponseKeys:  types.ListNull(types.StringType),
				Description:               types.StringValue("new description"),
				AllowedManagedKeys:        types.SetNull(types.StringType),
				PassthroughRequestHeaders: types.ListNull(types.StringType),
				AllowedResponseHeaders:    types.ListNull(types.StringType),
				DelegatedAuthAccessors:    types.ListNull(types.StringType),
				ListingVisibility:         types.StringValue("unauth"),
				PluginVersion:             types.StringNull(),
				IdentityTokenKey:          types.StringNull(),
			},
			validateServer: func(t *testing.T, r *http.Request) {
				var config map[string]interface{}
				require.NoError(t, json.NewDecoder(r.Body).Decode(&config))
				// Description should be included (changed)
				assert.Contains(t, config, consts.FieldDescription)
				assert.Equal(t, "new description", config[consts.FieldDescription])
				// ListingVisibility should NOT be included (unchanged)
				assert.NotContains(t, config, consts.FieldListingVisibility)
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/mounts/test-mount/tune" && r.Method == http.MethodPost {
					if tt.validateServer != nil {
						tt.validateServer(t, r)
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				http.NotFound(w, r)
			}))
			defer server.Close()

			config := api.DefaultConfig()
			config.Address = server.URL
			client, err := api.NewClient(config)
			require.NoError(t, err)

			meta := mockProviderMeta(t)
			ctx := context.Background()

			err = UpdateMount(ctx, client, "test-mount", tt.data, tt.state, meta)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMountHelper_ReadMount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		path           string
		serverResponse func(w http.ResponseWriter, r *http.Request)
		wantOutput     *MountModel
		wantErr        bool
	}{
		{
			name: "basic-read",
			path: "test-mount",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"data": map[string]interface{}{
						"type":                    "kv",
						"description":             "test mount",
						"accessor":                "kv_12345678",
						"local":                   false,
						"seal_wrap":               true,
						"external_entropy_access": false,
						"options": map[string]string{
							"version": "2",
						},
						"config": map[string]interface{}{
							"default_lease_ttl": 3600,
							"max_lease_ttl":     7200,
							"force_no_cache":    false,
						},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			wantOutput: &MountModel{
				Path:                   types.StringValue("test-mount"),
				Type:                   types.StringValue("kv"),
				Description:            types.StringValue("test mount"),
				Accessor:               types.StringValue("kv_12345678"),
				SealWrap:               types.BoolValue(true),
				DefaultLeaseTTLSeconds: types.Int64Value(3600),
				MaxLeaseTTLSeconds:     types.Int64Value(7200),
			},
			wantErr: false,
		},
		{
			name: "not-found",
			path: "nonexistent",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				response := map[string]interface{}{
					"errors": []string{"No secret engine mount at nonexistent/"},
				}
				json.NewEncoder(w).Encode(response)
			},
			wantOutput: nil,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					tt.serverResponse(w, r)
					return
				}
				http.NotFound(w, r)
			}))
			defer server.Close()

			config := api.DefaultConfig()
			config.Address = server.URL
			client, err := api.NewClient(config)
			require.NoError(t, err)

			ctx := context.Background()
			output, err := ReadMount(ctx, client, tt.path)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.wantOutput == nil {
					assert.Nil(t, output)
				} else {
					require.NotNil(t, output)
					assert.Equal(t, tt.wantOutput.Path, output.Path)
					assert.Equal(t, tt.wantOutput.Type, output.Type)
					assert.Equal(t, tt.wantOutput.Description, output.Description)
					assert.Equal(t, tt.wantOutput.Accessor, output.Accessor)
					assert.Equal(t, tt.wantOutput.SealWrap, output.SealWrap)
				}
			}
		})
	}
}

func TestMountHelper_DeleteMount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		path       string
		statusCode int
		wantErr    bool
	}{
		{
			name:       "successful-delete",
			path:       "test-mount",
			statusCode: http.StatusNoContent,
			wantErr:    false,
		},
		{
			name:       "error-delete",
			path:       "test-mount",
			statusCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/mounts/test-mount" && r.Method == http.MethodDelete {
					w.WriteHeader(tt.statusCode)
					if tt.statusCode != http.StatusNoContent {
						response := map[string]interface{}{
							"errors": []string{"internal server error"},
						}
						json.NewEncoder(w).Encode(response)
					}
					return
				}
				http.NotFound(w, r)
			}))
			defer server.Close()

			config := api.DefaultConfig()
			config.Address = server.URL
			client, err := api.NewClient(config)
			require.NoError(t, err)

			ctx := context.Background()
			err = DeleteMount(ctx, client, tt.path)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMountHelper_RemountMount(t *testing.T) {
	t.Parallel()

	const migrationID = "test-migration-id"

	tests := []struct {
		name            string
		oldPath         string
		newPath         string
		migrationStatus string
		startStatusCode int
		wantErr         bool
	}{
		{
			name:            "successful-remount",
			oldPath:         "old-mount",
			newPath:         "new-mount",
			migrationStatus: "success",
			startStatusCode: http.StatusOK,
			wantErr:         false,
		},
		{
			name:            "failed-migration",
			oldPath:         "old-mount",
			newPath:         "new-mount",
			migrationStatus: "failure",
			startStatusCode: http.StatusOK,
			wantErr:         true,
		},
		{
			name:            "start-remount-error",
			oldPath:         "old-mount",
			newPath:         "new-mount",
			startStatusCode: http.StatusInternalServerError,
			wantErr:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/sys/remount" && r.Method == http.MethodPost:
					var body map[string]interface{}
					require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
					assert.Equal(t, tt.oldPath, body["from"])
					assert.Equal(t, tt.newPath, body["to"])

					if tt.startStatusCode != http.StatusOK {
						w.WriteHeader(tt.startStatusCode)
						json.NewEncoder(w).Encode(map[string]interface{}{
							"errors": []string{"internal server error"},
						})
						return
					}

					json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"migration_id": migrationID,
						},
					})
					return
				case r.URL.Path == "/v1/sys/remount/status/"+migrationID && r.Method == http.MethodGet:
					json.NewEncoder(w).Encode(map[string]interface{}{
						"data": map[string]interface{}{
							"migration_id": migrationID,
							"migration_info": map[string]interface{}{
								"source_mount": tt.oldPath,
								"target_mount": tt.newPath,
								"status":       tt.migrationStatus,
							},
						},
					})
					return
				}
				http.NotFound(w, r)
			}))
			defer server.Close()

			config := api.DefaultConfig()
			config.Address = server.URL
			client, err := api.NewClient(config)
			require.NoError(t, err)

			ctx := context.Background()
			err = RemountMount(ctx, client, tt.oldPath, tt.newPath)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMountHelper_TuneMountWithMap(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/mounts/test-mount/tune" && r.Method == http.MethodPost {
			var config map[string]interface{}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&config))
			assert.Equal(t, "3600s", config["default_lease_ttl"])
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	config := api.DefaultConfig()
	config.Address = server.URL
	client, err := api.NewClient(config)
	require.NoError(t, err)

	ctx := context.Background()
	tuneConfig := map[string]interface{}{
		"default_lease_ttl": "3600s",
		"max_lease_ttl":     "7200s",
	}

	err = tuneMountWithMap(ctx, client, "test-mount", tuneConfig)
	assert.NoError(t, err)
}

func TestMountHelper_UpdateMount_RetryLogic(t *testing.T) {
	t.Parallel()

	attemptCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/mounts/test-mount/tune" && r.Method == http.MethodPost {
			attemptCount++
			// Fail first 2 attempts, succeed on 3rd
			if attemptCount < 3 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	config := api.DefaultConfig()
	config.Address = server.URL
	client, err := api.NewClient(config)
	require.NoError(t, err)

	state := &MountModel{
		DefaultLeaseTTLSeconds:    types.Int64Value(3600),
		MaxLeaseTTLSeconds:        types.Int64Value(7200),
		Options:                   types.MapNull(types.StringType),
		AuditNonHMACRequestKeys:   types.ListNull(types.StringType),
		AuditNonHMACResponseKeys:  types.ListNull(types.StringType),
		Description:               types.StringValue("old"),
		AllowedManagedKeys:        types.SetNull(types.StringType),
		PassthroughRequestHeaders: types.ListNull(types.StringType),
		AllowedResponseHeaders:    types.ListNull(types.StringType),
		DelegatedAuthAccessors:    types.ListNull(types.StringType),
		ListingVisibility:         types.StringNull(),
		PluginVersion:             types.StringNull(),
		IdentityTokenKey:          types.StringNull(),
	}

	data := &MountModel{
		DefaultLeaseTTLSeconds:    types.Int64Value(7200),
		MaxLeaseTTLSeconds:        types.Int64Value(14400),
		Options:                   types.MapNull(types.StringType),
		AuditNonHMACRequestKeys:   types.ListNull(types.StringType),
		AuditNonHMACResponseKeys:  types.ListNull(types.StringType),
		Description:               types.StringValue("old"),
		AllowedManagedKeys:        types.SetNull(types.StringType),
		PassthroughRequestHeaders: types.ListNull(types.StringType),
		AllowedResponseHeaders:    types.ListNull(types.StringType),
		DelegatedAuthAccessors:    types.ListNull(types.StringType),
		ListingVisibility:         types.StringNull(),
		PluginVersion:             types.StringNull(),
		IdentityTokenKey:          types.StringNull(),
	}

	meta := mockProviderMeta(t)
	ctx := context.Background()

	err = UpdateMount(ctx, client, "test-mount", data, state, meta)
	assert.NoError(t, err)
	assert.Equal(t, 3, attemptCount, "Expected 3 attempts")
}
