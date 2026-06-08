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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

// GetMountAttributes returns all mount configuration schema attributes for Plugin Framework resources.
// Resources can use this to get a consistent set of mount fields and then add their backend-specific fields.
// The excludes parameter allows resources to exclude fields they define themselves with custom configurations.
func GetMountAttributes(excludes ...string) map[string]schema.Attribute {
	s := map[string]schema.Attribute{
		consts.FieldPath: schema.StringAttribute{
			MarkdownDescription: "Where the secret backend will be mounted",
			Required:            true,
		},
		consts.FieldType: schema.StringAttribute{
			MarkdownDescription: "Type of the backend, such as 'aws'",
			Required:            true,
			PlanModifiers: []planmodifier.String{
				stringplanmodifier.RequiresReplace(),
			},
		},
		consts.FieldDescription: schema.StringAttribute{
			MarkdownDescription: "Human-friendly description of the mount",
			Optional:            true,
		},
		consts.FieldDefaultLeaseTTLSeconds: schema.Int64Attribute{
			MarkdownDescription: "Default lease duration for tokens and secrets in seconds",
			Optional:            true,
			Computed:            true,
		},
		consts.FieldMaxLeaseTTLSeconds: schema.Int64Attribute{
			MarkdownDescription: "Maximum possible lease duration for tokens and secrets in seconds",
			Optional:            true,
			Computed:            true,
		},
		consts.FieldForceNoCache: schema.BoolAttribute{
			MarkdownDescription: "If set to true, disables caching",
			Optional:            true,
			Computed:            true,
		},
		consts.FieldAuditNonHMACRequestKeys: schema.ListAttribute{
			ElementType:         types.StringType,
			MarkdownDescription: "Specifies the list of keys that will not be HMAC'd by audit devices in the request data object",
			Optional:            true,
			Computed:            true,
		},
		consts.FieldAuditNonHMACResponseKeys: schema.ListAttribute{
			ElementType:         types.StringType,
			MarkdownDescription: "Specifies the list of keys that will not be HMAC'd by audit devices in the response data object",
			Optional:            true,
			Computed:            true,
		},
		consts.FieldListingVisibility: schema.StringAttribute{
			MarkdownDescription: "Specifies whether to show this mount in the UI-specific listing endpoint",
			Optional:            true,
		},
		consts.FieldPassthroughRequestHeaders: schema.ListAttribute{
			ElementType:         types.StringType,
			MarkdownDescription: "List of headers to allow and pass from the request to the plugin",
			Optional:            true,
		},
		consts.FieldAllowedResponseHeaders: schema.ListAttribute{
			ElementType:         types.StringType,
			MarkdownDescription: "List of headers to allow and pass from the plugin to the request",
			Optional:            true,
		},
		consts.FieldPluginVersion: schema.StringAttribute{
			MarkdownDescription: "Specifies the semantic version of the plugin to use, e.g. 'v1.0.0'",
			Optional:            true,
		},
		consts.FieldAllowedManagedKeys: schema.SetAttribute{
			ElementType:         types.StringType,
			MarkdownDescription: "List of managed key registry entry names that the mount in question is allowed to access",
			Optional:            true,
		},
		consts.FieldDelegatedAuthAccessors: schema.ListAttribute{
			ElementType:         types.StringType,
			MarkdownDescription: "List of auth accessor IDs that can delegate authentication to this mount",
			Optional:            true,
		},
		consts.FieldIdentityTokenKey: schema.StringAttribute{
			MarkdownDescription: "The key to use for signing plugin workload identity tokens",
			Optional:            true,
		},
		consts.FieldOptions: schema.MapAttribute{
			ElementType:         types.StringType,
			MarkdownDescription: "Specifies mount type specific options that are passed to the backend",
			Optional:            true,
		},
		consts.FieldSealWrap: schema.BoolAttribute{
			MarkdownDescription: "Enable seal wrapping for the mount, causing values stored by the mount to be wrapped by the seal's encryption capability",
			Optional:            true,
			Computed:            true,
			PlanModifiers: []planmodifier.Bool{
				boolplanmodifier.RequiresReplace(),
			},
		},
		consts.FieldExternalEntropyAccess: schema.BoolAttribute{
			MarkdownDescription: "Enable the secrets engine to access Vault's external entropy source",
			Optional:            true,
			Computed:            true,
			Default:             booldefault.StaticBool(false),
			PlanModifiers: []planmodifier.Bool{
				boolplanmodifier.RequiresReplace(),
			},
		},
		consts.FieldLocal: schema.BoolAttribute{
			MarkdownDescription: "Local mount flag that can be explicitly set to true to enforce local mount in HA environment",
			Optional:            true,
			Computed:            true,
			PlanModifiers: []planmodifier.Bool{
				boolplanmodifier.RequiresReplace(),
			},
		},
		consts.FieldAccessor: schema.StringAttribute{
			MarkdownDescription: "Accessor of the mount",
			Computed:            true,
		},
	}

	// Remove excluded fields
	for _, exclude := range excludes {
		delete(s, exclude)
	}

	return s
}

// MustAddMountSchema adds the mount configuration schema attributes to the
// given schema. It panics if any mount field collides with a field that
// already exists in the schema, surfacing the conflict at startup. Resources
// can pass excludes to omit mount fields they define themselves.
//
// This should be called from a resource's Schema() method.
func MustAddMountSchema(s *schema.Schema, excludes ...string) {
	for k, v := range GetMountAttributes(excludes...) {
		if _, ok := s.Attributes[k]; ok {
			panic(fmt.Sprintf("cannot add mount schema field %q, already exists in the Schema map", k))
		}

		s.Attributes[k] = v
	}
}

// MountModel holds the Terraform state/plan values for the mount configuration
// fields shared by all self-managing secret backend resources. Embed it into a
// resource model alongside base.BaseModel and the backend-specific fields. The
// Plugin Framework flattens embedded structs when reading the tfsdk tags, so the
// field names below must match the attributes returned by GetMountAttributes.
//
// Embedding this type (together with MustAddMountSchema for the schema) lets a
// resource reuse the mount fields, schema, and Vault conversions without copying
// per-resource boilerplate.
type MountModel struct {
	Path                      types.String `tfsdk:"path"`
	Type                      types.String `tfsdk:"type"`
	Description               types.String `tfsdk:"description"`
	DefaultLeaseTTLSeconds    types.Int64  `tfsdk:"default_lease_ttl_seconds"`
	MaxLeaseTTLSeconds        types.Int64  `tfsdk:"max_lease_ttl_seconds"`
	ForceNoCache              types.Bool   `tfsdk:"force_no_cache"`
	AuditNonHMACRequestKeys   types.List   `tfsdk:"audit_non_hmac_request_keys"`
	AuditNonHMACResponseKeys  types.List   `tfsdk:"audit_non_hmac_response_keys"`
	ListingVisibility         types.String `tfsdk:"listing_visibility"`
	PassthroughRequestHeaders types.List   `tfsdk:"passthrough_request_headers"`
	AllowedResponseHeaders    types.List   `tfsdk:"allowed_response_headers"`
	PluginVersion             types.String `tfsdk:"plugin_version"`
	AllowedManagedKeys        types.Set    `tfsdk:"allowed_managed_keys"`
	DelegatedAuthAccessors    types.List   `tfsdk:"delegated_auth_accessors"`
	IdentityTokenKey          types.String `tfsdk:"identity_token_key"`
	Options                   types.Map    `tfsdk:"options"`
	SealWrap                  types.Bool   `tfsdk:"seal_wrap"`
	ExternalEntropyAccess     types.Bool   `tfsdk:"external_entropy_access"`
	Local                     types.Bool   `tfsdk:"local"`
	Accessor                  types.String `tfsdk:"accessor"`
}

// HasMountChanges reports whether any tunable/replaceable mount field differs
// between the receiver (typically the plan) and other (typically the prior
// state). Resources can use this to decide whether a mount update is needed
// before calling UpdateMount. path, type, and accessor are excluded: path/type
// are not tunable and accessor is computed.
func (m *MountModel) HasMountChanges(other *MountModel) bool {
	return !m.Description.Equal(other.Description) ||
		!m.DefaultLeaseTTLSeconds.Equal(other.DefaultLeaseTTLSeconds) ||
		!m.MaxLeaseTTLSeconds.Equal(other.MaxLeaseTTLSeconds) ||
		!m.ForceNoCache.Equal(other.ForceNoCache) ||
		!m.AuditNonHMACRequestKeys.Equal(other.AuditNonHMACRequestKeys) ||
		!m.AuditNonHMACResponseKeys.Equal(other.AuditNonHMACResponseKeys) ||
		!m.ListingVisibility.Equal(other.ListingVisibility) ||
		!m.PassthroughRequestHeaders.Equal(other.PassthroughRequestHeaders) ||
		!m.AllowedResponseHeaders.Equal(other.AllowedResponseHeaders) ||
		!m.PluginVersion.Equal(other.PluginVersion) ||
		!m.AllowedManagedKeys.Equal(other.AllowedManagedKeys) ||
		!m.DelegatedAuthAccessors.Equal(other.DelegatedAuthAccessors) ||
		!m.IdentityTokenKey.Equal(other.IdentityTokenKey) ||
		!m.Options.Equal(other.Options) ||
		!m.Local.Equal(other.Local) ||
		!m.SealWrap.Equal(other.SealWrap) ||
		!m.ExternalEntropyAccess.Equal(other.ExternalEntropyAccess)
}

// ApplyMountOutput copies the mount-level attributes read back from Vault into
// the mount model. plugin_version is intentionally not overwritten because Vault
// does not return it on read (see ReadMount); the configured/state value is kept.
func (m *MountModel) ApplyMountOutput(out *MountModel) {
	m.Type = out.Type
	m.Accessor = out.Accessor
	m.Description = out.Description
	m.DefaultLeaseTTLSeconds = out.DefaultLeaseTTLSeconds
	m.MaxLeaseTTLSeconds = out.MaxLeaseTTLSeconds
	m.ForceNoCache = out.ForceNoCache
	m.AuditNonHMACRequestKeys = out.AuditNonHMACRequestKeys
	m.AuditNonHMACResponseKeys = out.AuditNonHMACResponseKeys
	m.ListingVisibility = out.ListingVisibility
	m.PassthroughRequestHeaders = out.PassthroughRequestHeaders
	m.AllowedResponseHeaders = out.AllowedResponseHeaders
	m.AllowedManagedKeys = out.AllowedManagedKeys
	m.DelegatedAuthAccessors = out.DelegatedAuthAccessors
	m.IdentityTokenKey = out.IdentityTokenKey
	m.Options = out.Options
	m.SealWrap = out.SealWrap
	m.ExternalEntropyAccess = out.ExternalEntropyAccess
	m.Local = out.Local
}

// CreateMount creates a new mount in Vault using the provided configuration.
// This is the Plugin Framework equivalent of the SDKv2 createMount() function.
func CreateMount(ctx context.Context, client *api.Client, data *MountModel, mountType string, meta interface{}) error {
	path := data.Path.ValueString()

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
func UpdateMount(ctx context.Context, client *api.Client, path string, data *MountModel, state *MountModel, meta interface{}) error {
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

// ReadMount reads mount information from Vault and returns it as a MountModel.
// This is the Plugin Framework equivalent of the SDKv2 readMount() function.
func ReadMount(ctx context.Context, client *api.Client, path string) (*MountModel, error) {
	log.Printf("[DEBUG] Reading mount %s from Vault", path)

	mount, err := mountutil.GetMount(ctx, client, path)
	if err != nil {
		if mountutil.IsMountNotFoundError(err) {
			log.Printf("[WARN] Mount %q not found", path)
			return nil, nil
		}
		return nil, err
	}

	output := &MountModel{
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

// RemountMount moves a mount from oldPath to newPath in Vault. This is the
// Plugin Framework equivalent of the SDKv2 resource_mount remount handling and
// lets resources support in-place path changes instead of destroy/recreate.
// Callers should drop RequiresReplace() from the path attribute and invoke this
// from Update when the planned path differs from the prior state path.
func RemountMount(ctx context.Context, client *api.Client, oldPath, newPath string) error {
	log.Printf("[DEBUG] Remount %s to %s in Vault", oldPath, newPath)

	if err := client.Sys().RemountWithContext(ctx, oldPath, newPath); err != nil {
		return fmt.Errorf("error remounting in Vault: %s", err)
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
