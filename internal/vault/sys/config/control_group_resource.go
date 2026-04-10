// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
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
// It extends BaseModel which provides common fields like Namespace.
type ControlGroupConfigModel struct {
	base.BaseModel

	// ID is a computed field for the resource identifier
	ID types.String `tfsdk:"id"`

	// MaxTTL is the maximum time-to-live for control group wrapping tokens.
	// Can be specified as duration string (e.g., "2h") or seconds (e.g., "7200").
	MaxTTL types.String `tfsdk:"max_ttl"`
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
			},
		},
	}

	base.MustAddBaseSchema(&resp.Schema)
}

func (r *ControlGroupConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	r.createOrUpdate(ctx, req, resp, true)
}

func (r *ControlGroupConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
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

	setMaxTTLInModel(&data.MaxTTL, maxTTL)

	data.ID = types.StringValue(controlGroupPath)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ControlGroupConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	r.createOrUpdate(ctx, req, resp, false)
}

// createOrUpdate is a shared helper function for Create and Update operations.
// The isCreate parameter determines which error message to use for write failures.
func (r *ControlGroupConfigResource) createOrUpdate(ctx context.Context, req interface{}, resp interface{}, isCreate bool) {
	var data ControlGroupConfigModel

	// Type assert to get the correct request/response types
	var createReq resource.CreateRequest
	var createResp *resource.CreateResponse
	var updateReq resource.UpdateRequest
	var updateResp *resource.UpdateResponse

	if isCreate {
		createReq = req.(resource.CreateRequest)
		createResp = resp.(*resource.CreateResponse)
		createResp.Diagnostics.Append(createReq.Plan.Get(ctx, &data)...)
		if createResp.Diagnostics.HasError() {
			return
		}
	} else {
		updateReq = req.(resource.UpdateRequest)
		updateResp = resp.(*resource.UpdateResponse)
		updateResp.Diagnostics.Append(updateReq.Plan.Get(ctx, &data)...)
		if updateResp.Diagnostics.HasError() {
			return
		}
	}

	addError := func(summary string, detail string) {
		if isCreate {
			createResp.Diagnostics.AddError(summary, detail)
		} else {
			updateResp.Diagnostics.AddError(summary, detail)
		}
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		addError(errutil.ClientConfigureErr(err))
		return
	}

	vaultRequest, err := toWriteRequest(&data)
	if err != nil {
		addError("Invalid max_ttl", err.Error())
		return
	}

	if _, err := vaultClient.Logical().WriteWithContext(ctx, controlGroupPath, vaultRequest); err != nil {
		if isCreate {
			addError(errutil.VaultCreateErr(err))
		} else {
			addError(errutil.VaultUpdateErr(err))
		}
		return
	}

	// Set the ID before calling Read
	data.ID = types.StringValue(controlGroupPath)

	// Set state first so Read can access it
	if isCreate {
		createResp.Diagnostics.Append(createResp.State.Set(ctx, &data)...)
		if createResp.Diagnostics.HasError() {
			return
		}

		// Use Read to refresh the state from Vault
		readReq := resource.ReadRequest{State: createResp.State}
		readResp := &resource.ReadResponse{State: createResp.State, Diagnostics: createResp.Diagnostics}
		r.Read(ctx, readReq, readResp)
		createResp.Diagnostics = readResp.Diagnostics
		createResp.State = readResp.State
	} else {
		updateResp.Diagnostics.Append(updateResp.State.Set(ctx, &data)...)
		if updateResp.Diagnostics.HasError() {
			return
		}

		// Use Read to refresh the state from Vault
		readReq := resource.ReadRequest{State: updateResp.State}
		readResp := &resource.ReadResponse{State: updateResp.State, Diagnostics: updateResp.Diagnostics}
		r.Read(ctx, readReq, readResp)
		updateResp.Diagnostics = readResp.Diagnostics
		updateResp.State = readResp.State
	}
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

// ImportState handles importing the control group configuration into Terraform state.
// Since this is a singleton resource, the import ID is always the same path.
func (r *ControlGroupConfigResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	id := strings.TrimSpace(request.ID)
	// Allow empty ID for convenience - default to the control group path
	if id == "" {
		id = controlGroupPath
	}

	// Get namespace from environment variable if set
	var data ControlGroupConfigModel
	if ns := os.Getenv(consts.EnvVarVaultNamespaceImport); ns != "" {
		data.Namespace = types.StringValue(ns)
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		response.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	secret, err := vaultClient.Logical().ReadWithContext(ctx, controlGroupPath)
	if err != nil {
		response.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if secret == nil {
		response.Diagnostics.AddError(
			"Resource Not Found",
			"Control group configuration not found in Vault",
		)
		return
	}

	// Extract and normalize the max_ttl value from Vault's response
	maxTTL, err := extractMaxTTL(secret.Data)
	if err != nil {
		response.Diagnostics.AddError("Unable to parse Vault response data", err.Error())
		return
	}

	setMaxTTLInModel(&data.MaxTTL, maxTTL)

	response.Diagnostics.Append(response.State.Set(ctx, &data)...)
}

// setMaxTTLInModel sets the max_ttl value in the model, preserving the user's original format
// if it matches what Vault returned. This prevents unnecessary diffs.
func setMaxTTLInModel(modelMaxTTL *types.String, fromAPI string) {
	if fromAPI == "" {
		*modelMaxTTL = types.StringNull()
	} else {
		// Preserve the user's original format if it matches
		if v, ok := preserveExistingMaxTTL(*modelMaxTTL, fromAPI); ok {
			*modelMaxTTL = types.StringValue(v)
		} else {
			*modelMaxTTL = types.StringValue(fromAPI)
		}
	}
}

// toWriteRequest converts the Terraform model to a Vault API request payload.
func toWriteRequest(data *ControlGroupConfigModel) (map[string]interface{}, error) {
	request := map[string]interface{}{}

	// If max_ttl is not set, return an empty request (Vault will use defaults)
	if data.MaxTTL.IsNull() || data.MaxTTL.IsUnknown() {
		return request, nil
	}

	// Pass the max_ttl value directly to Vault (accepts both duration strings and seconds)
	request[consts.FieldMaxTTL] = data.MaxTTL.ValueString()
	return request, nil
}

// extractMaxTTL extracts the max_ttl value from Vault's API response.
// Vault can return max_ttl as either a string or numeric value.
func extractMaxTTL(data map[string]interface{}) (string, error) {
	v, ok := data[consts.FieldMaxTTL]
	if !ok || v == nil {
		return "", nil
	}

	// Convert to string - handles both string and numeric responses
	return fmt.Sprintf("%v", v), nil
}

// preserveExistingMaxTTL attempts to preserve the user's original max_ttl format
// if it's semantically equivalent to what Vault returned. This prevents unnecessary
// plan diffs when users specify "2h" but Vault returns "7200".
//
// Returns: (originalValue, true) if values are equivalent, ("", false) otherwise.
func preserveExistingMaxTTL(existing types.String, fromAPI string) (string, bool) {
	// Can't preserve if there's no existing value
	if existing.IsNull() || existing.IsUnknown() {
		return "", false
	}

	existingRaw := strings.TrimSpace(existing.ValueString())
	if existingRaw == "" {
		return "", false
	}

	// If values match exactly, preserve the user's original format
	if existingRaw == fromAPI {
		return existingRaw, true
	}

	// Try to parse both values as durations to compare semantically
	existingDuration, err1 := parseutil.ParseDurationSecond(existingRaw)
	apiDuration, err2 := parseutil.ParseDurationSecond(fromAPI)

	// If both parse successfully and are equal, preserve the user's format
	if err1 == nil && err2 == nil && existingDuration == apiDuration {
		return existingRaw, true
	}

	return "", false
}
