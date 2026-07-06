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

// mockProviderMetaEnt creates a mock provider meta pinned to a 1.16+ Enterprise
// Vault version via vault_version_override, so identity_token_key gating is
// treated as supported.
func mockProviderMetaEnt(t *testing.T) interface{} {
	s := map[string]*schema.Schema{
		consts.FieldSkipGetVaultVersion: {
			Type:     schema.TypeBool,
			Optional: true,
		},
		consts.FieldVaultVersionOverride: {
			Type:     schema.TypeString,
			Optional: true,
		},
	}

	d := schema.TestResourceDataRaw(t, s, map[string]interface{}{
		consts.FieldVaultVersionOverride: "1.16.0+ent",
	})

	meta, _ := provider.NewProviderMeta(d)
	return meta
}

// newTestClient spins up an httptest server with the given handler and returns
// a Vault API client pointed at it. The server is closed via t.Cleanup.
func newTestClient(t *testing.T, handler http.HandlerFunc) *api.Client {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	config := api.DefaultConfig()
	config.Address = server.URL
	config.MaxRetries = 0
	client, err := api.NewClient(config)
	require.NoError(t, err)

	return client
}

// baseMountModel returns a fully-initialized MountModel with all collection
// fields null and scalars set to deterministic values, so that two independent
// calls compare equal. Tests tweak only the fields they care about.
func baseMountModel() *MountModel {
	return &MountModel{
		Path:                      types.StringValue("test-mount"),
		Type:                      types.StringValue("kv"),
		Description:               types.StringValue("desc"),
		DefaultLeaseTTLSeconds:    types.Int64Value(3600),
		MaxLeaseTTLSeconds:        types.Int64Value(7200),
		ForceNoCache:              types.BoolValue(false),
		Local:                     types.BoolValue(false),
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
		Accessor:                  types.StringValue("kv_12345678"),
	}
}

func strList(t *testing.T, vals ...string) types.List {
	t.Helper()
	v, diags := types.ListValueFrom(context.Background(), types.StringType, vals)
	require.False(t, diags.HasError())
	return v
}

func strSet(t *testing.T, vals ...string) types.Set {
	t.Helper()
	v, diags := types.SetValueFrom(context.Background(), types.StringType, vals)
	require.False(t, diags.HasError())
	return v
}

func strMap(t *testing.T, kv map[string]string) types.Map {
	t.Helper()
	elems := make(map[string]attr.Value, len(kv))
	for k, v := range kv {
		elems[k] = types.StringValue(v)
	}
	m, diags := types.MapValue(types.StringType, elems)
	require.False(t, diags.HasError())
	return m
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestMountHelper_CreateMount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		modify         func(m *MountModel)
		validateServer func(t *testing.T, r *http.Request)
		wantErr        bool
	}{
		{
			name: "basic-mount",
			modify: func(m *MountModel) {
				m.Description = types.StringValue("test description")
				m.Local = types.BoolValue(true)
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
		},
		{
			name: "with-options",
			modify: func(m *MountModel) {
				m.Options = strMap(t, map[string]string{"version": "2", "cas_required": "true"})
			},
			validateServer: func(t *testing.T, r *http.Request) {
				var input api.MountInput
				require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
				assert.Len(t, input.Options, 2)
				assert.Equal(t, "2", input.Options["version"])
				assert.Equal(t, "true", input.Options["cas_required"])
			},
		},
		{
			name: "with-audit-keys",
			modify: func(m *MountModel) {
				m.AuditNonHMACRequestKeys = strList(t, "key1", "key2")
				m.AuditNonHMACResponseKeys = strList(t, "response_key")
			},
			validateServer: func(t *testing.T, r *http.Request) {
				var input api.MountInput
				require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
				assert.Len(t, input.Config.AuditNonHMACRequestKeys, 2)
				assert.Len(t, input.Config.AuditNonHMACResponseKeys, 1)
			},
		},
		{
			name: "with-headers-managed-keys-and-entropy",
			modify: func(m *MountModel) {
				m.Type = types.StringValue("pki")
				m.ExternalEntropyAccess = types.BoolValue(true)
				m.AllowedManagedKeys = strSet(t, "kms-key")
				m.PassthroughRequestHeaders = strList(t, "header1", "header2")
				m.AllowedResponseHeaders = strList(t, "header1", "header2")
				m.DelegatedAuthAccessors = strList(t, "accessor1", "accessor2")
				m.ListingVisibility = types.StringValue("hidden")
			},
			validateServer: func(t *testing.T, r *http.Request) {
				var input api.MountInput
				require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
				assert.True(t, input.ExternalEntropyAccess)
				assert.Equal(t, "hidden", input.Config.ListingVisibility)
				assert.Len(t, input.Config.PassthroughRequestHeaders, 2)
				assert.Len(t, input.Config.AllowedResponseHeaders, 2)
				assert.Len(t, input.Config.DelegatedAuthAccessors, 2)
				assert.Len(t, input.Config.AllowedManagedKeys, 1)
				assert.Equal(t, "kms-key", input.Config.AllowedManagedKeys[0])
			},
		},
		{
			name:    "vault-error",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/mounts/test-mount" && r.Method == http.MethodPost {
					if tt.wantErr {
						w.WriteHeader(http.StatusInternalServerError)
						writeJSON(w, map[string]interface{}{"errors": []string{"internal server error"}})
						return
					}
					if tt.validateServer != nil {
						tt.validateServer(t, r)
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				http.NotFound(w, r)
			})

			input := baseMountModel()
			if tt.modify != nil {
				tt.modify(input)
			}

			err := CreateMount(context.Background(), client, input, input.Type.ValueString(), mockProviderMeta(t))
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
		modifyState    func(m *MountModel)
		modifyData     func(m *MountModel)
		validateServer func(t *testing.T, r *http.Request)
		wantErr        bool
	}{
		{
			name: "basic-update",
			modifyData: func(m *MountModel) {
				m.DefaultLeaseTTLSeconds = types.Int64Value(7200)
				m.MaxLeaseTTLSeconds = types.Int64Value(14400)
			},
			validateServer: func(t *testing.T, r *http.Request) {
				var config map[string]interface{}
				require.NoError(t, json.NewDecoder(r.Body).Decode(&config))
				assert.Equal(t, "7200s", config["default_lease_ttl"])
				assert.Equal(t, "14400s", config["max_lease_ttl"])
			},
		},
		{
			name:        "only-changed-fields",
			modifyState: func(m *MountModel) { m.Description = types.StringValue("old description") },
			modifyData:  func(m *MountModel) { m.Description = types.StringValue("new description") },
			validateServer: func(t *testing.T, r *http.Request) {
				var config map[string]interface{}
				require.NoError(t, json.NewDecoder(r.Body).Decode(&config))
				// Description should be included (changed)
				assert.Contains(t, config, consts.FieldDescription)
				assert.Equal(t, "new description", config[consts.FieldDescription])
				// ListingVisibility should NOT be included (unchanged)
				assert.NotContains(t, config, consts.FieldListingVisibility)
			},
		},
		{
			name: "audit-keys-changed",
			modifyData: func(m *MountModel) {
				m.AuditNonHMACRequestKeys = strList(t, "req1", "req2")
				m.AuditNonHMACResponseKeys = strList(t, "resp1")
			},
			validateServer: func(t *testing.T, r *http.Request) {
				var config map[string]interface{}
				require.NoError(t, json.NewDecoder(r.Body).Decode(&config))
				// Audit keys changed, so they should be included.
				require.Contains(t, config, consts.FieldAuditNonHMACRequestKeys)
				require.Contains(t, config, consts.FieldAuditNonHMACResponseKeys)
				assert.Len(t, config[consts.FieldAuditNonHMACRequestKeys], 2)
				assert.Len(t, config[consts.FieldAuditNonHMACResponseKeys], 1)
			},
		},
		{
			// Regression test for VAULT-34426: removing allowed_response_headers
			// must send the (empty) field so Vault clears the previously set value.
			name: "allowed-response-headers-removal",
			modifyState: func(m *MountModel) {
				m.AllowedResponseHeaders = strList(t, "Content-Length", "WWW-Authenticate")
			},
			validateServer: func(t *testing.T, r *http.Request) {
				var config map[string]interface{}
				require.NoError(t, json.NewDecoder(r.Body).Decode(&config))
				// The field changed (set -> removed), so it must be present in the
				// tune request to clear it on the Vault side.
				assert.Contains(t, config, consts.FieldAllowedResponseHeaders)
			},
		},
		{
			name:    "vault-error",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/mounts/test-mount/tune" && r.Method == http.MethodPost {
					if tt.wantErr {
						w.WriteHeader(http.StatusInternalServerError)
						writeJSON(w, map[string]interface{}{"errors": []string{"internal server error"}})
						return
					}
					if tt.validateServer != nil {
						tt.validateServer(t, r)
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				http.NotFound(w, r)
			})

			state := baseMountModel()
			if tt.modifyState != nil {
				tt.modifyState(state)
			}
			data := baseMountModel()
			if tt.modifyData != nil {
				tt.modifyData(data)
			}

			err := UpdateMount(context.Background(), client, data, state, mockProviderMeta(t))
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
				writeJSON(w, map[string]interface{}{
					"data": map[string]interface{}{
						"type":                    "kv",
						"description":             "test mount",
						"accessor":                "kv_12345678",
						"local":                   false,
						"seal_wrap":               true,
						"external_entropy_access": false,
						"options":                 map[string]string{"version": "2"},
						"config": map[string]interface{}{
							"default_lease_ttl": 3600,
							"max_lease_ttl":     7200,
							"force_no_cache":    false,
						},
					},
				})
			},
			wantOutput: &MountModel{
				Path:                   types.StringValue("test-mount"),
				Type:                   types.StringValue("kv"),
				Description:            types.StringValue("test mount"),
				Accessor:               types.StringValue("kv_12345678"),
				SealWrap:               types.BoolValue(true),
				Local:                  types.BoolValue(false),
				ExternalEntropyAccess:  types.BoolValue(false),
				DefaultLeaseTTLSeconds: types.Int64Value(3600),
				MaxLeaseTTLSeconds:     types.Int64Value(7200),
				// options present -> non-null map; all other collections absent -> null.
				Options:                   strMap(t, map[string]string{"version": "2"}),
				AuditNonHMACRequestKeys:   types.ListNull(types.StringType),
				AuditNonHMACResponseKeys:  types.ListNull(types.StringType),
				AllowedManagedKeys:        types.SetNull(types.StringType),
				PassthroughRequestHeaders: types.ListNull(types.StringType),
				AllowedResponseHeaders:    types.ListNull(types.StringType),
				DelegatedAuthAccessors:    types.ListNull(types.StringType),
				ListingVisibility:         types.StringNull(),
				IdentityTokenKey:          types.StringNull(),
			},
		},
		{
			name: "full-collections",
			path: "test-mount",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, map[string]interface{}{
					"data": map[string]interface{}{
						"type":     "kv",
						"accessor": "kv_12345678",
						"options":  map[string]string{"version": "2", "cas_required": "true"},
						"config": map[string]interface{}{
							"default_lease_ttl":            3600,
							"max_lease_ttl":                7200,
							"force_no_cache":               false,
							"audit_non_hmac_request_keys":  []string{"req1", "req2"},
							"audit_non_hmac_response_keys": []string{"resp1"},
							"allowed_managed_keys":         []string{"kms-key"},
							"passthrough_request_headers":  []string{"h1", "h2"},
							"allowed_response_headers":     []string{"r1"},
							"delegated_auth_accessors":     []string{"a1", "a2"},
							"listing_visibility":           "unauth",
							"identity_token_key":           "my-key",
						},
					},
				})
			},
			wantOutput: &MountModel{
				Path:                      types.StringValue("test-mount"),
				Type:                      types.StringValue("kv"),
				Accessor:                  types.StringValue("kv_12345678"),
				SealWrap:                  types.BoolValue(false),
				Local:                     types.BoolValue(false),
				ExternalEntropyAccess:     types.BoolValue(false),
				DefaultLeaseTTLSeconds:    types.Int64Value(3600),
				MaxLeaseTTLSeconds:        types.Int64Value(7200),
				Options:                   strMap(t, map[string]string{"version": "2", "cas_required": "true"}),
				AuditNonHMACRequestKeys:   strList(t, "req1", "req2"),
				AuditNonHMACResponseKeys:  strList(t, "resp1"),
				AllowedManagedKeys:        strSet(t, "kms-key"),
				PassthroughRequestHeaders: strList(t, "h1", "h2"),
				AllowedResponseHeaders:    strList(t, "r1"),
				DelegatedAuthAccessors:    strList(t, "a1", "a2"),
				ListingVisibility:         types.StringValue("unauth"),
				IdentityTokenKey:          types.StringValue("my-key"),
			},
		},
		{
			name: "empty-collections-are-null",
			path: "test-mount",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, map[string]interface{}{
					"data": map[string]interface{}{
						"type":     "kv",
						"accessor": "kv_12345678",
						"options":  map[string]string{},
						"config": map[string]interface{}{
							"allowed_managed_keys":        []string{},
							"passthrough_request_headers": []string{},
							"allowed_response_headers":    []string{},
							"delegated_auth_accessors":    []string{},
						},
					},
				})
			},
			wantOutput: &MountModel{
				Path:                      types.StringValue("test-mount"),
				Type:                      types.StringValue("kv"),
				Accessor:                  types.StringValue("kv_12345678"),
				SealWrap:                  types.BoolValue(false),
				Local:                     types.BoolValue(false),
				ExternalEntropyAccess:     types.BoolValue(false),
				DefaultLeaseTTLSeconds:    types.Int64Value(0),
				MaxLeaseTTLSeconds:        types.Int64Value(0),
				Options:                   types.MapNull(types.StringType),
				AuditNonHMACRequestKeys:   types.ListNull(types.StringType),
				AuditNonHMACResponseKeys:  types.ListNull(types.StringType),
				AllowedManagedKeys:        types.SetNull(types.StringType),
				PassthroughRequestHeaders: types.ListNull(types.StringType),
				AllowedResponseHeaders:    types.ListNull(types.StringType),
				DelegatedAuthAccessors:    types.ListNull(types.StringType),
				ListingVisibility:         types.StringNull(),
				IdentityTokenKey:          types.StringNull(),
			},
		},
		{
			name: "local-mount-read",
			path: "test-mount",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, map[string]interface{}{
					"data": map[string]interface{}{
						"type":                    "transit",
						"description":             "local mount",
						"accessor":                "transit_87654321",
						"local":                   true,
						"seal_wrap":               false,
						"external_entropy_access": true,
						"config": map[string]interface{}{
							"default_lease_ttl": 3600,
							"max_lease_ttl":     7200,
							"force_no_cache":    false,
						},
					},
				})
			},
			wantOutput: &MountModel{
				Path:                      types.StringValue("test-mount"),
				Type:                      types.StringValue("transit"),
				Description:               types.StringValue("local mount"),
				Accessor:                  types.StringValue("transit_87654321"),
				SealWrap:                  types.BoolValue(false),
				Local:                     types.BoolValue(true),
				ExternalEntropyAccess:     types.BoolValue(true),
				DefaultLeaseTTLSeconds:    types.Int64Value(3600),
				MaxLeaseTTLSeconds:        types.Int64Value(7200),
				Options:                   types.MapNull(types.StringType),
				AuditNonHMACRequestKeys:   types.ListNull(types.StringType),
				AuditNonHMACResponseKeys:  types.ListNull(types.StringType),
				AllowedManagedKeys:        types.SetNull(types.StringType),
				PassthroughRequestHeaders: types.ListNull(types.StringType),
				AllowedResponseHeaders:    types.ListNull(types.StringType),
				DelegatedAuthAccessors:    types.ListNull(types.StringType),
				ListingVisibility:         types.StringNull(),
				IdentityTokenKey:          types.StringNull(),
			},
		},
		{
			name: "not-found",
			path: "nonexistent",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				writeJSON(w, map[string]interface{}{
					"errors": []string{"No secret engine mount at nonexistent/"},
				})
			},
			wantOutput: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					tt.serverResponse(w, r)
					return
				}
				http.NotFound(w, r)
			})

			output, found, err := ReadMount(context.Background(), client, tt.path)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			if tt.wantOutput == nil {
				assert.False(t, found)
				assert.Nil(t, output)
				return
			}

			assert.True(t, found)
			require.NotNil(t, output)
			assert.Equal(t, tt.wantOutput.Path, output.Path)
			assert.Equal(t, tt.wantOutput.Type, output.Type)
			assert.Equal(t, tt.wantOutput.Description, output.Description)
			assert.Equal(t, tt.wantOutput.Accessor, output.Accessor)
			assert.Equal(t, tt.wantOutput.SealWrap, output.SealWrap)
			assert.Equal(t, tt.wantOutput.Local, output.Local)
			assert.Equal(t, tt.wantOutput.ExternalEntropyAccess, output.ExternalEntropyAccess)
			assert.Equal(t, tt.wantOutput.DefaultLeaseTTLSeconds, output.DefaultLeaseTTLSeconds)
			assert.Equal(t, tt.wantOutput.MaxLeaseTTLSeconds, output.MaxLeaseTTLSeconds)
			assert.Equal(t, tt.wantOutput.ListingVisibility, output.ListingVisibility)
			assert.Equal(t, tt.wantOutput.IdentityTokenKey, output.IdentityTokenKey)
			// Collection fields: assert exact equality so empty Vault values are
			// read back as null (not empty), preventing state drift/parity regressions.
			assert.Equal(t, tt.wantOutput.Options, output.Options)
			assert.Equal(t, tt.wantOutput.AuditNonHMACRequestKeys, output.AuditNonHMACRequestKeys)
			assert.Equal(t, tt.wantOutput.AuditNonHMACResponseKeys, output.AuditNonHMACResponseKeys)
			assert.Equal(t, tt.wantOutput.AllowedManagedKeys, output.AllowedManagedKeys)
			assert.Equal(t, tt.wantOutput.PassthroughRequestHeaders, output.PassthroughRequestHeaders)
			assert.Equal(t, tt.wantOutput.AllowedResponseHeaders, output.AllowedResponseHeaders)
			assert.Equal(t, tt.wantOutput.DelegatedAuthAccessors, output.DelegatedAuthAccessors)
		})
	}
}

// TestMountHelper_IdentityTokenKeyPerpetualDiff documents the pre-1.16 /
// non-Enterprise behavior: a configured identity_token_key is silently dropped on
// create (not sent to Vault), then read back as null, leaving a perpetual diff
// against the configured value. mockProviderMeta skips the version check so the
// server is treated as unsupported.
func TestMountHelper_IdentityTokenKeyPerpetualDiff(t *testing.T) {
	t.Parallel()

	const path = "test-mount"

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/sys/mounts/"+path && r.Method == http.MethodPost:
			// identity_token_key is gated out for unsupported servers, so it
			// must not be sent in the create request.
			var input api.MountInput
			require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
			assert.Empty(t, input.Config.IdentityTokenKey)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet:
			// Vault ignored identity_token_key, so it's absent from the read.
			writeJSON(w, map[string]interface{}{
				"data": map[string]interface{}{
					"type":     "kv",
					"accessor": "kv_12345678",
					"config":   map[string]interface{}{},
				},
			})
		default:
			http.NotFound(w, r)
		}
	})

	// Config sets identity_token_key against a non-1.16 / non-Enterprise server.
	config := baseMountModel()
	config.IdentityTokenKey = types.StringValue("default-key")

	require.NoError(t, CreateMount(context.Background(), client, config, config.Type.ValueString(), mockProviderMeta(t)))

	output, found, err := ReadMount(context.Background(), client, path)
	require.NoError(t, err)
	require.True(t, found)
	// Read back as null because Vault silently ignored the configured value.
	assert.True(t, output.IdentityTokenKey.IsNull())

	// Applying the read into state nulls the field while config keeps its value,
	// so HasMountChanges keeps reporting a (perpetual) diff.
	state := baseMountModel()
	state.IdentityTokenKey = config.IdentityTokenKey
	state.ApplyMountOutput(output)
	assert.True(t, state.IdentityTokenKey.IsNull())
	assert.True(t, config.HasMountChanges(state))
}

// TestMountHelper_IdentityTokenKeySupported verifies that on a 1.16+ Enterprise
// server identity_token_key is sent in both create and tune requests.
func TestMountHelper_IdentityTokenKeySupported(t *testing.T) {
	t.Parallel()

	const path = "test-mount"

	var sawCreate, sawTune bool
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/sys/mounts/"+path && r.Method == http.MethodPost:
			var input api.MountInput
			require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
			assert.Equal(t, "default-key", input.Config.IdentityTokenKey)
			sawCreate = true
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/v1/sys/mounts/"+path+"/tune" && r.Method == http.MethodPost:
			var config map[string]interface{}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&config))
			assert.Equal(t, "default-key", config[consts.FieldIdentityTokenKey])
			sawTune = true
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})

	meta := mockProviderMetaEnt(t)

	config := baseMountModel()
	config.IdentityTokenKey = types.StringValue("default-key")
	require.NoError(t, CreateMount(context.Background(), client, config, config.Type.ValueString(), meta))
	assert.True(t, sawCreate, "identity_token_key must be sent on create")

	// State has no key, plan sets it -> changed -> sent in tune request.
	state := baseMountModel()
	require.NoError(t, UpdateMount(context.Background(), client, config, state, meta))
	assert.True(t, sawTune, "identity_token_key must be sent on update")
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

			client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/sys/mounts/test-mount" && r.Method == http.MethodDelete {
					w.WriteHeader(tt.statusCode)
					if tt.statusCode != http.StatusNoContent {
						writeJSON(w, map[string]interface{}{"errors": []string{"internal server error"}})
					}
					return
				}
				http.NotFound(w, r)
			})

			err := DeleteMount(context.Background(), client, tt.path)
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

			client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/sys/remount" && r.Method == http.MethodPost:
					var body map[string]interface{}
					require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
					assert.Equal(t, tt.oldPath, body["from"])
					assert.Equal(t, tt.newPath, body["to"])

					if tt.startStatusCode != http.StatusOK {
						w.WriteHeader(tt.startStatusCode)
						writeJSON(w, map[string]interface{}{"errors": []string{"internal server error"}})
						return
					}

					writeJSON(w, map[string]interface{}{
						"data": map[string]interface{}{"migration_id": migrationID},
					})
				case r.URL.Path == "/v1/sys/remount/status/"+migrationID && r.Method == http.MethodGet:
					writeJSON(w, map[string]interface{}{
						"data": map[string]interface{}{
							"migration_id": migrationID,
							"migration_info": map[string]interface{}{
								"source_mount": tt.oldPath,
								"target_mount": tt.newPath,
								"status":       tt.migrationStatus,
							},
						},
					})
				default:
					http.NotFound(w, r)
				}
			})

			err := RemountMount(context.Background(), client, tt.oldPath, tt.newPath)
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

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/mounts/test-mount/tune" && r.Method == http.MethodPost {
			var config map[string]interface{}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&config))
			assert.Equal(t, "3600s", config["default_lease_ttl"])
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	})

	tuneConfig := map[string]interface{}{
		"default_lease_ttl": "3600s",
		"max_lease_ttl":     "7200s",
	}

	err := tuneMountWithMap(context.Background(), client, "test-mount", tuneConfig)
	assert.NoError(t, err)
}

func TestMountHelper_UpdateMount_RetryLogic(t *testing.T) {
	t.Parallel()

	attemptCount := 0
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
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
	})

	state := baseMountModel()
	data := baseMountModel()
	data.DefaultLeaseTTLSeconds = types.Int64Value(7200)
	data.MaxLeaseTTLSeconds = types.Int64Value(14400)

	err := UpdateMount(context.Background(), client, data, state, mockProviderMeta(t))
	assert.NoError(t, err)
	assert.Equal(t, 3, attemptCount, "Expected 3 attempts")
}

func TestMountModel_HasMountChanges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		modify func(m *MountModel)
		want   bool
	}{
		{
			name:   "no-changes",
			modify: func(m *MountModel) {},
			want:   false,
		},
		{
			name:   "tunable-field-changed",
			modify: func(m *MountModel) { m.Description = types.StringValue("changed") },
			want:   true,
		},
		{
			name:   "accessor-ignored",
			modify: func(m *MountModel) { m.Accessor = types.StringValue("changed") },
			want:   false,
		},
		{
			name:   "path-ignored",
			modify: func(m *MountModel) { m.Path = types.StringValue("changed") },
			want:   false,
		},
		{
			name:   "type-ignored",
			modify: func(m *MountModel) { m.Type = types.StringValue("changed") },
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := baseMountModel()
			b := baseMountModel()
			tt.modify(b)

			assert.Equal(t, tt.want, a.HasMountChanges(b))
		})
	}
}

func TestMountModel_ApplyMountOutput(t *testing.T) {
	t.Parallel()

	out := &MountModel{
		Type:                     types.StringValue("kv"),
		Accessor:                 types.StringValue("kv_12345678"),
		Description:              types.StringValue("from vault"),
		DefaultLeaseTTLSeconds:   types.Int64Value(3600),
		MaxLeaseTTLSeconds:       types.Int64Value(7200),
		ForceNoCache:             types.BoolValue(true),
		AuditNonHMACRequestKeys:  strList(t, "key1"),
		AuditNonHMACResponseKeys: types.ListNull(types.StringType),
		ListingVisibility:        types.StringValue("unauth"),
		Options:                  strMap(t, map[string]string{"version": "2"}),
		SealWrap:                 types.BoolValue(true),
		ExternalEntropyAccess:    types.BoolValue(true),
		Local:                    types.BoolValue(true),
	}

	dst := &MountModel{
		// Path and PluginVersion are intentionally preserved by ApplyMountOutput.
		Path:          types.StringValue("keep-me"),
		PluginVersion: types.StringValue("v1.0.0"),
	}

	dst.ApplyMountOutput(out)

	// Mount-level fields are copied from the Vault output.
	assert.Equal(t, out.Type, dst.Type)
	assert.Equal(t, out.Accessor, dst.Accessor)
	assert.Equal(t, out.Description, dst.Description)
	assert.Equal(t, out.DefaultLeaseTTLSeconds, dst.DefaultLeaseTTLSeconds)
	assert.Equal(t, out.MaxLeaseTTLSeconds, dst.MaxLeaseTTLSeconds)
	assert.Equal(t, out.ForceNoCache, dst.ForceNoCache)
	assert.Equal(t, out.AuditNonHMACRequestKeys, dst.AuditNonHMACRequestKeys)
	assert.Equal(t, out.ListingVisibility, dst.ListingVisibility)
	assert.Equal(t, out.Options, dst.Options)
	assert.Equal(t, out.SealWrap, dst.SealWrap)
	assert.Equal(t, out.ExternalEntropyAccess, dst.ExternalEntropyAccess)
	assert.Equal(t, out.Local, dst.Local)

	// Path and plugin_version are not overwritten by ApplyMountOutput.
	assert.Equal(t, types.StringValue("keep-me"), dst.Path)
	assert.Equal(t, types.StringValue("v1.0.0"), dst.PluginVersion)
}
