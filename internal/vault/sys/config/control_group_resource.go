// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/vault/api"
)

const (
	// controlGroupPath is the Vault API endpoint for control group configuration.
	// This is a singleton resource - only one configuration exists per Vault cluster.
	controlGroupPath = "sys/config/control-group"
)

var (
	// Compile-time interface checks to ensure ControlGroupConfigResource implements required interfaces
	_ resource.Resource                = &ControlGroupConfigResource{}
	_ resource.ResourceWithConfigure   = &ControlGroupConfigResource{}
	_ resource.ResourceWithImportState = &ControlGroupConfigResource{}
)

func NewControlGroupConfigResource() resource.Resource {
	return &ControlGroupConfigResource{}
}

type ControlGroupConfigResource struct {
	base.ResourceWithConfigure
}

// ControlGroupConfigModel represents the Terraform state/plan model for control group configuration.
// It extends BaseModelLegacy which provides common fields like ID and Namespace.
type ControlGroupConfigModel struct {
	base.BaseModelLegacy

	// MaxTTL is the maximum time-to-live for control group wrapping tokens.
	// Can be specified as duration string (e.g., "2h") or seconds (e.g., "7200").
	MaxTTL types.String `tfsdk:"max_ttl"`
}

// durationOrSecondsValidator validates that max_ttl can be parsed as either
// a duration string (e.g., "2h", "30m") or as seconds (e.g., "7200").
type durationOrSecondsValidator struct{}

func (v durationOrSecondsValidator) Description(_ context.Context) string {
	return "Invalid duration string"
}

func (v durationOrSecondsValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateString performs validation on the max_ttl attribute during plan phase.
// This ensures users get immediate feedback if they provide an invalid duration format.
func (v durationOrSecondsValidator) ValidateString(ctx context.Context, request validator.StringRequest, response *validator.StringResponse) {
	// Skip validation for null or unknown values (computed values during plan)
	if request.ConfigValue.IsNull() || request.ConfigValue.IsUnknown() {
		return
	}

	// Attempt to normalize the value - this will fail if it's not a valid duration
	if _, err := normalizeMaxTTL(request.ConfigValue.ValueString()); err != nil {
		response.Diagnostics.AddError(v.Description(ctx), fmt.Sprintf("Failed to parse value as a duration string or seconds, err=%s", err))
	}
}

func (r *ControlGroupConfigResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_config_control_group"
}

func (r *ControlGroupConfigResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the singleton control group configuration. Requires Vault Enterprise 1.10.0 or later.",
		Attributes: map[string]schema.Attribute{
			consts.FieldMaxTTL: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The maximum ttl for a control group wrapping token. This can be provided in seconds or duration (for example, 2h). Requires Vault Enterprise 1.10.0 or later.",
				Validators: []validator.String{
					durationOrSecondsValidator{},
				},
			},
		},
	}

	base.MustAddLegacyBaseSchema(&resp.Schema)
}

func (r *ControlGroupConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ControlGroupConfigModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !r.featureSupported(resp.Diagnostics.AddError) {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultRequest, err := toWriteRequest(&data)
	if err != nil {
		resp.Diagnostics.AddError("Invalid max_ttl", err.Error())
		return
	}

	if _, err := vaultClient.Logical().WriteWithContext(ctx, controlGroupPath, vaultRequest); err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	if err := r.readIntoModel(ctx, vaultClient, &data); err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}

	data.ID = types.StringValue(controlGroupPath)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ControlGroupConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ControlGroupConfigModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !r.featureSupported(resp.Diagnostics.AddError) {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	secret, err := vaultClient.Logical().ReadWithContext(ctx, controlGroupPath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if secret == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	// Extract and normalize the max_ttl value from Vault's response
	maxTTL, err := extractMaxTTL(secret.Data)
	if err != nil {
		resp.Diagnostics.AddError("Unable to parse Vault response data", err.Error())
		return
	}

	if maxTTL == "" {
		data.MaxTTL = types.StringNull()
	} else {
		// Preserve the user's original format if it's semantically equivalent to what Vault returned.
		// This prevents unnecessary diffs when users specify "2h" but Vault returns "7200".
		if v, ok := preserveExistingMaxTTL(data.MaxTTL, maxTTL); ok {
			data.MaxTTL = types.StringValue(v)
		} else {
			data.MaxTTL = types.StringValue(maxTTL)
		}
	}

	data.ID = types.StringValue(controlGroupPath)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ControlGroupConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data ControlGroupConfigModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !r.featureSupported(resp.Diagnostics.AddError) {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultRequest, err := toWriteRequest(&data)
	if err != nil {
		resp.Diagnostics.AddError("Invalid max_ttl", err.Error())
		return
	}

	if _, err := vaultClient.Logical().WriteWithContext(ctx, controlGroupPath, vaultRequest); err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}

	if err := r.readIntoModel(ctx, vaultClient, &data); err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}

	data.ID = types.StringValue(controlGroupPath)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ControlGroupConfigResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ControlGroupConfigModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !r.featureSupported(resp.Diagnostics.AddError) {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	if _, err := vaultClient.Logical().DeleteWithContext(ctx, controlGroupPath); err != nil {
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
		return
	}
}

// ImportState handles importing the control group configuration into Terraform state.
// Since this is a singleton resource, the import ID is always the same path.
func (r *ControlGroupConfigResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	id := strings.TrimSpace(request.ID)
	// Allow empty ID for convenience - default to the control group path
	if id == "" {
		id = controlGroupPath
	}

	// Validate that the import ID matches the expected path (with or without leading slash)
	if id != controlGroupPath && id != "/"+controlGroupPath {
		response.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Unexpected import identifier %q, expected %q", request.ID, controlGroupPath),
		)
		return
	}

	// Set the resource ID in state
	response.Diagnostics.Append(response.State.SetAttribute(ctx, path.Root(consts.FieldID), controlGroupPath)...)

	// Support namespace-aware imports via environment variable
	// This allows importing resources from specific Vault namespaces
	if ns := os.Getenv(consts.EnvVarVaultNamespaceImport); ns != "" {
		response.Diagnostics.Append(
			response.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...,
		)
	}
}

// readIntoModel is a helper function that reads the control group configuration from Vault
// and populates the Terraform model. This is used after Create/Update operations to ensure
// the state reflects what was actually stored in Vault.
func (r *ControlGroupConfigResource) readIntoModel(ctx context.Context, vaultClient *api.Client, data *ControlGroupConfigModel) error {
	secret, err := vaultClient.Logical().ReadWithContext(ctx, controlGroupPath)
	if err != nil {
		return err
	}
	if secret == nil {
		return fmt.Errorf("control group configuration not found")
	}

	maxTTL, err := extractMaxTTL(secret.Data)
	if err != nil {
		return err
	}

	if maxTTL == "" {
		data.MaxTTL = types.StringNull()
	} else {
		// Preserve the user's original format if semantically equivalent
		if v, ok := preserveExistingMaxTTL(data.MaxTTL, maxTTL); ok {
			data.MaxTTL = types.StringValue(v)
		} else {
			data.MaxTTL = types.StringValue(maxTTL)
		}
	}

	return nil
}

// toWriteRequest converts the Terraform model to a Vault API request payload.
// It normalizes the max_ttl value to seconds for consistency with Vault's API.
func toWriteRequest(data *ControlGroupConfigModel) (map[string]interface{}, error) {
	request := map[string]interface{}{}

	// If max_ttl is not set, return an empty request (Vault will use defaults)
	if data.MaxTTL.IsNull() || data.MaxTTL.IsUnknown() {
		return request, nil
	}

	// Normalize the max_ttl to seconds (e.g., "2h" becomes "7200")
	maxTTL, err := normalizeMaxTTL(data.MaxTTL.ValueString())
	if err != nil {
		return nil, err
	}

	request[consts.FieldMaxTTL] = maxTTL
	return request, nil
}

// extractMaxTTL extracts and normalizes the max_ttl value from Vault's API response.
// Vault returns max_ttl as a numeric value in seconds.
func extractMaxTTL(data map[string]interface{}) (string, error) {
	v, ok := data[consts.FieldMaxTTL]
	if !ok || v == nil {
		return "", nil
	}

	// Vault returns max_ttl as a number (seconds), convert to string
	return normalizeMaxTTL(fmt.Sprintf("%v", v))
}

// normalizeMaxTTL converts a duration string or seconds value to a normalized seconds string.
// Examples: "2h" -> "7200", "30m" -> "1800", "7200" -> "7200"
// This ensures consistent comparison and storage regardless of input format.
func normalizeMaxTTL(v string) (string, error) {
	// ParseDurationSecond handles both duration strings ("2h") and plain seconds ("7200")
	d, err := parseutil.ParseDurationSecond(strings.TrimSpace(v))
	if err != nil {
		return "", err
	}

	// Convert to seconds as a string for consistent representation
	return strconv.FormatInt(int64(d/time.Second), 10), nil
}

// preserveExistingMaxTTL attempts to preserve the user's original max_ttl format
// if it's semantically equivalent to what Vault returned. This prevents unnecessary
// plan diffs when a user specifies "2h" but Vault returns "7200".
//
// Returns: (originalValue, true) if formats are equivalent, ("", false) otherwise.
func preserveExistingMaxTTL(existing types.String, normalizedFromAPI string) (string, bool) {
	// Can't preserve if there's no existing value
	if existing.IsNull() || existing.IsUnknown() {
		return "", false
	}

	existingRaw := strings.TrimSpace(existing.ValueString())
	if existingRaw == "" {
		return "", false
	}

	// Normalize the existing value to compare with API response
	existingNormalized, err := normalizeMaxTTL(existingRaw)
	if err != nil {
		return "", false
	}

	// If both normalize to the same value, preserve the user's original format
	if existingNormalized == normalizedFromAPI {
		return existingRaw, true
	}

	return "", false
}

// featureSupported checks if the Vault server supports control group configuration.
// This feature requires Vault Enterprise 1.10.0 or later.
// The function takes an error callback to allow flexible error reporting across different contexts.
func (r *ControlGroupConfigResource) featureSupported(addError func(summary string, detail string)) bool {
	// Ensure provider metadata is available for version checks
	if r.Meta() == nil {
		addError("Provider Not Configured", "Provider metadata is unavailable for control group feature checks.")
		return false
	}

	// Check if Vault version is 1.10.0 or later
	if !provider.IsAPISupported(r.Meta(), provider.VaultVersion110) {
		currentVersion := "unknown"
		if v := r.Meta().GetVaultVersion(); v != nil {
			currentVersion = v.String()
		}

		addError(
			"Feature Not Supported",
			"Control group configuration requires Vault version 1.10.0 or later. Current Vault version: "+currentVersion,
		)
		return false
	}

	// Check if Vault is Enterprise edition (control groups are an Enterprise feature)
	if !provider.IsEnterpriseSupported(r.Meta()) {
		addError(
			"Feature Not Supported",
			"Control group configuration requires Vault Enterprise.",
		)
		return false
	}

	return true
}
