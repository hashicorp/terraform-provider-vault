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
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
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
// It extends BaseModel, which provides common fields like Namespace.
type ControlGroupConfigModel struct {
	base.BaseModel

	// ID is a computed field for the resource identifier
	ID types.String `tfsdk:"id"`

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
		Attributes: map[string]schema.Attribute{
			consts.FieldID: schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The resource ID.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldMaxTTL: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The maximum ttl for a control group wrapping token. This can be provided in seconds or duration (for example, 2h).",
				Validators: []validator.String{
					durationOrSecondsValidator{},
				},
			},
		},
	}

	base.MustAddBaseSchema(&resp.Schema)
}

func (r *ControlGroupConfigResource) readFromVault(
	ctx context.Context,
	data *ControlGroupConfigModel,
	diagnostics *diag.Diagnostics,
) bool {
	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		diagnostics.AddError(errutil.ClientConfigureErr(err))
		return false
	}

	secret, err := vaultClient.Logical().ReadWithContext(ctx, controlGroupPath)
	if err != nil {
		diagnostics.AddError(errutil.VaultReadErr(err))
		return false
	}
	if secret == nil {
		return false
	}

	// Extract and normalize the max_ttl value from Vault's response
	maxTTL, err := extractMaxTTL(secret.Data)
	if err != nil {
		diagnostics.AddError("Unable to parse Vault response data", err.Error())
		return false
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
	return true
}

func (r *ControlGroupConfigResource) writeAndRefresh(
	ctx context.Context,
	data *ControlGroupConfigModel,
	errorFunc func(error) (string, string),
	diagnostics *diag.Diagnostics,
) *ControlGroupConfigModel {
	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		diagnostics.AddError(errutil.ClientConfigureErr(err))
		return nil
	}

	vaultRequest, err := toWriteRequest(data)
	if err != nil {
		diagnostics.AddError("Invalid max_ttl", err.Error())
		return nil
	}

	if _, err := vaultClient.Logical().WriteWithContext(ctx, controlGroupPath, vaultRequest); err != nil {
		diagnostics.AddError(errorFunc(err))
		return nil
	}

	data.ID = types.StringValue(controlGroupPath)

	// Read back from Vault to ensure state consistency
	refreshed := *data
	if !r.readFromVault(ctx, &refreshed, diagnostics) {
		if diagnostics.HasError() {
			return nil
		}

		return data
	}

	return &refreshed
}

func (r *ControlGroupConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ControlGroupConfigModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	stateData := r.writeAndRefresh(ctx, &data, errutil.VaultCreateErr, &resp.Diagnostics)
	if resp.Diagnostics.HasError() || stateData == nil {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, stateData)...)
}

func (r *ControlGroupConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ControlGroupConfigModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Use the common read helper
	if !r.readFromVault(ctx, &data, &resp.Diagnostics) {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ControlGroupConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data ControlGroupConfigModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	stateData := r.writeAndRefresh(ctx, &data, errutil.VaultUpdateErr, &resp.Diagnostics)
	if resp.Diagnostics.HasError() || stateData == nil {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, stateData)...)
}

func (r *ControlGroupConfigResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ControlGroupConfigModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
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

// toWriteRequest converts the Terraform model to a Vault API request payload.
func toWriteRequest(data *ControlGroupConfigModel) (map[string]interface{}, error) {
	request := map[string]interface{}{}

	// If max_ttl is not set, return an empty request (Vault will use defaults)
	if data.MaxTTL.IsNull() || data.MaxTTL.IsUnknown() {
		return request, nil
	}

	request[consts.FieldMaxTTL] = data.MaxTTL.ValueString()
	return request, nil
}

// extractMaxTTL extracts the max_ttl value from Vault's API response.
// Vault may return max_ttl as either a string or a number, so we handle both cases.
func extractMaxTTL(data map[string]interface{}) (string, error) {
	v, ok := data[consts.FieldMaxTTL]
	if !ok || v == nil {
		return "", nil
	}

	s, ok := v.(string)
	if ok {
		return strings.TrimSpace(s), nil
	}

	return fmt.Sprintf("%v", v), nil
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
