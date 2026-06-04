// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

// MountInput contains the configuration for creating or updating a mount.
// This mirrors the structure used in SDKv2 but uses Plugin Framework types.
type MountInput struct {
	Path                      types.String
	Type                      types.String
	Description               types.String
	DefaultLeaseTTLSeconds    types.Int64
	MaxLeaseTTLSeconds        types.Int64
	ForceNoCache              types.Bool
	AuditNonHMACRequestKeys   types.List
	AuditNonHMACResponseKeys  types.List
	ListingVisibility         types.String
	PassthroughRequestHeaders types.List
	AllowedResponseHeaders    types.List
	PluginVersion             types.String
	AllowedManagedKeys        types.Set
	DelegatedAuthAccessors    types.List
	IdentityTokenKey          types.String
	Options                   types.Map
	SealWrap                  types.Bool
	ExternalEntropyAccess     types.Bool
	Local                     types.Bool
}

// MountOutput contains the mount information read from Vault.
// This mirrors the structure used in SDKv2 but uses Plugin Framework types.
type MountOutput struct {
	Path                      types.String
	Type                      types.String
	Description               types.String
	DefaultLeaseTTLSeconds    types.Int64
	MaxLeaseTTLSeconds        types.Int64
	ForceNoCache              types.Bool
	AuditNonHMACRequestKeys   types.List
	AuditNonHMACResponseKeys  types.List
	ListingVisibility         types.String
	PassthroughRequestHeaders types.List
	AllowedResponseHeaders    types.List
	PluginVersion             types.String
	AllowedManagedKeys        types.Set
	DelegatedAuthAccessors    types.List
	IdentityTokenKey          types.String
	Options                   types.Map
	SealWrap                  types.Bool
	ExternalEntropyAccess     types.Bool
	Local                     types.Bool
	Accessor                  types.String
}

// CreateMount creates a new mount in Vault using the provided configuration.
// This is the Plugin Framework equivalent of the SDKv2 createMount() function.
func CreateMount(ctx context.Context, client *api.Client, data *MountInput, meta interface{}) error {
	path := data.Path.ValueString()
	mountType := data.Type.ValueString()

	input := &api.MountInput{
		Type:        mountType,
		Description: data.Description.ValueString(),
		Config: api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", data.DefaultLeaseTTLSeconds.ValueInt64()),
			MaxLeaseTTL:     fmt.Sprintf("%ds", data.MaxLeaseTTLSeconds.ValueInt64()),
			ForceNoCache:    data.ForceNoCache.ValueBool(),
		},
		Local:                 data.Local.ValueBool(),
		SealWrap:              data.SealWrap.ValueBool(),
		ExternalEntropyAccess: data.ExternalEntropyAccess.ValueBool(),
	}

	// Handle options
	if !data.Options.IsNull() && !data.Options.IsUnknown() {
		options := make(map[string]string)
		diags := data.Options.ElementsAs(ctx, &options, false)
		if diags.HasError() {
			return fmt.Errorf("failed to parse options: %v", diags)
		}
		input.Options = options
	}

	// Handle audit_non_hmac_request_keys
	if !data.AuditNonHMACRequestKeys.IsNull() && !data.AuditNonHMACRequestKeys.IsUnknown() {
		var keys []string
		diags := data.AuditNonHMACRequestKeys.ElementsAs(ctx, &keys, false)
		if diags.HasError() {
			return fmt.Errorf("failed to parse audit_non_hmac_request_keys: %v", diags)
		}
		input.Config.AuditNonHMACRequestKeys = keys
	}

	// Handle audit_non_hmac_response_keys
	if !data.AuditNonHMACResponseKeys.IsNull() && !data.AuditNonHMACResponseKeys.IsUnknown() {
		var keys []string
		diags := data.AuditNonHMACResponseKeys.ElementsAs(ctx, &keys, false)
		if diags.HasError() {
			return fmt.Errorf("failed to parse audit_non_hmac_response_keys: %v", diags)
		}
		input.Config.AuditNonHMACResponseKeys = keys
	}

	// Handle allowed_managed_keys
	if !data.AllowedManagedKeys.IsNull() && !data.AllowedManagedKeys.IsUnknown() {
		var keys []string
		diags := data.AllowedManagedKeys.ElementsAs(ctx, &keys, false)
		if diags.HasError() {
			return fmt.Errorf("failed to parse allowed_managed_keys: %v", diags)
		}
		input.Config.AllowedManagedKeys = keys
	}

	// Handle passthrough_request_headers
	if !data.PassthroughRequestHeaders.IsNull() && !data.PassthroughRequestHeaders.IsUnknown() {
		var headers []string
		diags := data.PassthroughRequestHeaders.ElementsAs(ctx, &headers, false)
		if diags.HasError() {
			return fmt.Errorf("failed to parse passthrough_request_headers: %v", diags)
		}
		input.Config.PassthroughRequestHeaders = headers
	}

	// Handle allowed_response_headers
	if !data.AllowedResponseHeaders.IsNull() && !data.AllowedResponseHeaders.IsUnknown() {
		var headers []string
		diags := data.AllowedResponseHeaders.ElementsAs(ctx, &headers, false)
		if diags.HasError() {
			return fmt.Errorf("failed to parse allowed_response_headers: %v", diags)
		}
		input.Config.AllowedResponseHeaders = headers
	}

	// Handle delegated_auth_accessors
	if !data.DelegatedAuthAccessors.IsNull() && !data.DelegatedAuthAccessors.IsUnknown() {
		var accessors []string
		diags := data.DelegatedAuthAccessors.ElementsAs(ctx, &accessors, false)
		if diags.HasError() {
			return fmt.Errorf("failed to parse delegated_auth_accessors: %v", diags)
		}
		input.Config.DelegatedAuthAccessors = accessors
	}

	// Handle listing_visibility
	if !data.ListingVisibility.IsNull() && !data.ListingVisibility.IsUnknown() {
		input.Config.ListingVisibility = data.ListingVisibility.ValueString()
	}

	// Handle plugin_version
	if !data.PluginVersion.IsNull() && !data.PluginVersion.IsUnknown() {
		input.Config.PluginVersion = data.PluginVersion.ValueString()
	}

	// Handle identity_token_key (Vault 1.16+ Enterprise)
	useAPIVer116Ent := provider.IsAPISupported(meta, provider.VaultVersion116) && provider.IsEnterpriseSupported(meta)
	if useAPIVer116Ent && !data.IdentityTokenKey.IsNull() && !data.IdentityTokenKey.IsUnknown() {
		input.Config.IdentityTokenKey = data.IdentityTokenKey.ValueString()
	}

	log.Printf("[DEBUG] Creating mount %s in Vault", path)

	if err := client.Sys().MountWithContext(ctx, path, input); err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	return nil
}

// UpdateMount updates an existing mount in Vault with the provided configuration.
// This is the Plugin Framework equivalent of the SDKv2 updateMount() function.
// It compares the new data with the previous state to only send changed fields.
func UpdateMount(ctx context.Context, client *api.Client, path string, data *MountInput, state *MountInput, meta interface{}) error {
	// Build tune configuration. SDKv2 parity: always include options so that
	// clearing all options is persisted to Vault.
	options := make(map[string]string)
	if !data.Options.IsNull() && !data.Options.IsUnknown() {
		diags := data.Options.ElementsAs(ctx, &options, false)
		if diags.HasError() {
			return fmt.Errorf("failed to parse options: %v", diags)
		}
	}

	mapConfig := map[string]interface{}{
		"default_lease_ttl": fmt.Sprintf("%ds", data.DefaultLeaseTTLSeconds.ValueInt64()),
		"max_lease_ttl":     fmt.Sprintf("%ds", data.MaxLeaseTTLSeconds.ValueInt64()),
		"options":           options,
	}

	// Handle audit_non_hmac_request_keys - only if changed
	if !data.AuditNonHMACRequestKeys.Equal(state.AuditNonHMACRequestKeys) {
		var keys []string
		if !data.AuditNonHMACRequestKeys.IsNull() && !data.AuditNonHMACRequestKeys.IsUnknown() {
			diags := data.AuditNonHMACRequestKeys.ElementsAs(ctx, &keys, false)
			if diags.HasError() {
				return fmt.Errorf("failed to parse audit_non_hmac_request_keys: %v", diags)
			}
		}
		mapConfig[consts.FieldAuditNonHMACRequestKeys] = keys
	}

	// Handle audit_non_hmac_response_keys - only if changed
	if !data.AuditNonHMACResponseKeys.Equal(state.AuditNonHMACResponseKeys) {
		var keys []string
		if !data.AuditNonHMACResponseKeys.IsNull() && !data.AuditNonHMACResponseKeys.IsUnknown() {
			diags := data.AuditNonHMACResponseKeys.ElementsAs(ctx, &keys, false)
			if diags.HasError() {
				return fmt.Errorf("failed to parse audit_non_hmac_response_keys: %v", diags)
			}
		}
		mapConfig[consts.FieldAuditNonHMACResponseKeys] = keys
	}

	// Handle description - only if changed
	if !data.Description.Equal(state.Description) {
		mapConfig[consts.FieldDescription] = data.Description.ValueString()
	}

	// Handle allowed_managed_keys - only if changed
	if !data.AllowedManagedKeys.Equal(state.AllowedManagedKeys) {
		var keys []string
		if !data.AllowedManagedKeys.IsNull() && !data.AllowedManagedKeys.IsUnknown() {
			diags := data.AllowedManagedKeys.ElementsAs(ctx, &keys, false)
			if diags.HasError() {
				return fmt.Errorf("failed to parse allowed_managed_keys: %v", diags)
			}
		}
		mapConfig[consts.FieldAllowedManagedKeys] = keys
	}

	// Handle passthrough_request_headers - only if changed
	if !data.PassthroughRequestHeaders.Equal(state.PassthroughRequestHeaders) {
		var headers []string
		if !data.PassthroughRequestHeaders.IsNull() && !data.PassthroughRequestHeaders.IsUnknown() {
			diags := data.PassthroughRequestHeaders.ElementsAs(ctx, &headers, false)
			if diags.HasError() {
				return fmt.Errorf("failed to parse passthrough_request_headers: %v", diags)
			}
		}
		mapConfig[consts.FieldPassthroughRequestHeaders] = headers
	}

	// Handle allowed_response_headers - only if changed
	if !data.AllowedResponseHeaders.Equal(state.AllowedResponseHeaders) {
		var headers []string
		if !data.AllowedResponseHeaders.IsNull() && !data.AllowedResponseHeaders.IsUnknown() {
			diags := data.AllowedResponseHeaders.ElementsAs(ctx, &headers, false)
			if diags.HasError() {
				return fmt.Errorf("failed to parse allowed_response_headers: %v", diags)
			}
		}
		mapConfig[consts.FieldAllowedResponseHeaders] = headers
	}

	// Handle delegated_auth_accessors - only if changed
	if !data.DelegatedAuthAccessors.Equal(state.DelegatedAuthAccessors) {
		var accessors []string
		if !data.DelegatedAuthAccessors.IsNull() && !data.DelegatedAuthAccessors.IsUnknown() {
			diags := data.DelegatedAuthAccessors.ElementsAs(ctx, &accessors, false)
			if diags.HasError() {
				return fmt.Errorf("failed to parse delegated_auth_accessors: %v", diags)
			}
		}
		mapConfig[consts.FieldDelegatedAuthAccessors] = accessors
	}

	// Handle listing_visibility - only if changed
	if !data.ListingVisibility.Equal(state.ListingVisibility) {
		mapConfig[consts.FieldListingVisibility] = data.ListingVisibility.ValueString()
	}

	// Handle plugin_version - only if changed
	if !data.PluginVersion.Equal(state.PluginVersion) {
		mapConfig[consts.FieldPluginVersion] = data.PluginVersion.ValueString()
	}

	// Handle identity_token_key (Vault 1.16+ Enterprise) - only if changed
	useAPIVer116Ent := provider.IsAPISupported(meta, provider.VaultVersion116) && provider.IsEnterpriseSupported(meta)
	if useAPIVer116Ent && !data.IdentityTokenKey.Equal(state.IdentityTokenKey) {
		mapConfig[consts.FieldIdentityTokenKey] = data.IdentityTokenKey.ValueString()
	}

	log.Printf("[DEBUG] Updating mount %s in Vault", path)

	// Retry logic for VAULT-5521 workaround
	var tries int
	for {
		if err := tuneMountWithMap(ctx, client, path, mapConfig); err != nil {
			if tries > 10 {
				return fmt.Errorf("error updating Vault: %s", err)
			}
			tries++
			time.Sleep(1 * time.Second)
			continue
		}
		break
	}

	return nil
}

// ReadMount reads mount information from Vault and returns it as MountOutput.
// This is the Plugin Framework equivalent of the SDKv2 readMount() function.
func ReadMount(ctx context.Context, client *api.Client, path string) (*MountOutput, error) {
	log.Printf("[DEBUG] Reading mount %s from Vault", path)

	mount, err := mountutil.GetMount(ctx, client, path)
	if err != nil {
		if mountutil.IsMountNotFoundError(err) {
			log.Printf("[WARN] Mount %q not found", path)
			return nil, nil
		}
		return nil, err
	}

	output := &MountOutput{
		Path:                   types.StringValue(path),
		Type:                   types.StringValue(mount.Type),
		DefaultLeaseTTLSeconds: types.Int64Value(int64(mount.Config.DefaultLeaseTTL)),
		MaxLeaseTTLSeconds:     types.Int64Value(int64(mount.Config.MaxLeaseTTL)),
		ForceNoCache:           types.BoolValue(mount.Config.ForceNoCache),
		Accessor:               types.StringValue(mount.Accessor),
		Local:                  types.BoolValue(mount.Local),
		SealWrap:               types.BoolValue(mount.SealWrap),
		ExternalEntropyAccess:  types.BoolValue(mount.ExternalEntropyAccess),
	}

	// Handle description - use null when empty
	if mount.Description != "" {
		output.Description = types.StringValue(mount.Description)
	} else {
		output.Description = types.StringNull()
	}

	// Handle audit_non_hmac_request_keys
	if len(mount.Config.AuditNonHMACRequestKeys) > 0 {
		elements := make([]types.String, len(mount.Config.AuditNonHMACRequestKeys))
		for i, key := range mount.Config.AuditNonHMACRequestKeys {
			elements[i] = types.StringValue(key)
		}
		listValue, _ := types.ListValueFrom(ctx, types.StringType, elements)
		output.AuditNonHMACRequestKeys = listValue
	} else {
		output.AuditNonHMACRequestKeys = types.ListNull(types.StringType)
	}

	// Handle audit_non_hmac_response_keys
	if len(mount.Config.AuditNonHMACResponseKeys) > 0 {
		elements := make([]types.String, len(mount.Config.AuditNonHMACResponseKeys))
		for i, key := range mount.Config.AuditNonHMACResponseKeys {
			elements[i] = types.StringValue(key)
		}
		listValue, _ := types.ListValueFrom(ctx, types.StringType, elements)
		output.AuditNonHMACResponseKeys = listValue
	} else {
		output.AuditNonHMACResponseKeys = types.ListNull(types.StringType)
	}

	// Handle allowed_managed_keys
	if len(mount.Config.AllowedManagedKeys) > 0 {
		elements := make([]types.String, len(mount.Config.AllowedManagedKeys))
		for i, key := range mount.Config.AllowedManagedKeys {
			elements[i] = types.StringValue(key)
		}
		setValue, _ := types.SetValueFrom(ctx, types.StringType, elements)
		output.AllowedManagedKeys = setValue
	} else {
		output.AllowedManagedKeys = types.SetNull(types.StringType)
	}

	// Handle passthrough_request_headers
	if len(mount.Config.PassthroughRequestHeaders) > 0 {
		elements := make([]types.String, len(mount.Config.PassthroughRequestHeaders))
		for i, header := range mount.Config.PassthroughRequestHeaders {
			elements[i] = types.StringValue(header)
		}
		listValue, _ := types.ListValueFrom(ctx, types.StringType, elements)
		output.PassthroughRequestHeaders = listValue
	} else {
		output.PassthroughRequestHeaders = types.ListNull(types.StringType)
	}

	// Handle allowed_response_headers
	if len(mount.Config.AllowedResponseHeaders) > 0 {
		elements := make([]types.String, len(mount.Config.AllowedResponseHeaders))
		for i, header := range mount.Config.AllowedResponseHeaders {
			elements[i] = types.StringValue(header)
		}
		listValue, _ := types.ListValueFrom(ctx, types.StringType, elements)
		output.AllowedResponseHeaders = listValue
	} else {
		output.AllowedResponseHeaders = types.ListNull(types.StringType)
	}

	// Handle delegated_auth_accessors
	if len(mount.Config.DelegatedAuthAccessors) > 0 {
		elements := make([]types.String, len(mount.Config.DelegatedAuthAccessors))
		for i, accessor := range mount.Config.DelegatedAuthAccessors {
			elements[i] = types.StringValue(accessor)
		}
		listValue, _ := types.ListValueFrom(ctx, types.StringType, elements)
		output.DelegatedAuthAccessors = listValue
	} else {
		output.DelegatedAuthAccessors = types.ListNull(types.StringType)
	}

	// Handle listing_visibility
	if mount.Config.ListingVisibility != "" {
		output.ListingVisibility = types.StringValue(mount.Config.ListingVisibility)
	} else {
		output.ListingVisibility = types.StringNull()
	}

	// Handle plugin_version - note: PluginVersion is not in MountConfigOutput,
	// it's only available during mount creation/update
	output.PluginVersion = types.StringNull()

	// Handle identity_token_key
	if mount.Config.IdentityTokenKey != "" {
		output.IdentityTokenKey = types.StringValue(mount.Config.IdentityTokenKey)
	} else {
		output.IdentityTokenKey = types.StringNull()
	}

	// Handle options
	if len(mount.Options) > 0 {
		elements := make(map[string]attr.Value)
		for k, v := range mount.Options {
			elements[k] = types.StringValue(v)
		}
		mapValue, _ := types.MapValue(types.StringType, elements)
		output.Options = mapValue
	} else {
		output.Options = types.MapNull(types.StringType)
	}

	return output, nil
}

// DeleteMount unmounts a mount from Vault.
// This is the Plugin Framework equivalent of the SDKv2 mount delete functionality.
func DeleteMount(ctx context.Context, client *api.Client, path string) error {
	log.Printf("[DEBUG] Unmounting %s from Vault", path)

	if err := client.Sys().UnmountWithContext(ctx, path); err != nil {
		return fmt.Errorf("error deleting from Vault: %s", err)
	}

	return nil
}

// tuneMountWithMap is a helper function to tune a mount using a map configuration.
// This mirrors the SDKv2 implementation and works around VAULT-5521.
func tuneMountWithMap(ctx context.Context, c *api.Client, path string, config map[string]interface{}) error {
	r := c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/mounts/%s/tune", path))
	if err := r.SetJSONBody(config); err != nil {
		return err
	}

	resp, err := c.RawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
