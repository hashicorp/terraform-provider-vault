// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package transform

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
	vaultclient "github.com/hashicorp/vault/api"
)

var (
	_ resource.Resource                = &TransformationFPEResource{}
	_ resource.ResourceWithConfigure   = &TransformationFPEResource{}
	_ resource.ResourceWithImportState = &TransformationFPEResource{}
)

func NewTransformationFPEResource() resource.Resource {
	return &TransformationFPEResource{}
}

type TransformationFPEResource struct {
	base.ResourceWithConfigure
}

type TransformationFPEModel struct {
	base.BaseModel

	Mount           types.String `tfsdk:"mount"`
	Name            types.String `tfsdk:"name"`
	Template        types.String `tfsdk:"template"`
	TweakSource     types.String `tfsdk:"tweak_source"`
	AllowedRoles    types.List   `tfsdk:"allowed_roles"`
	DeletionAllowed types.Bool   `tfsdk:"deletion_allowed"`
	MaxTweakLen     types.Int64  `tfsdk:"max_tweak_len"`
	FPEAlgorithm    types.String `tfsdk:"fpe_algorithm"`
}

func (r *TransformationFPEResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_transform_transformation_fpe"
}

func (r *TransformationFPEResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Creates and manages a Format Preserving Encryption (FPE) transformation in a Vault Transform secrets engine.",
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Path where the Transform secrets engine is mounted. Changing this field replaces this resource.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldName: schema.StringAttribute{
				MarkdownDescription: "Name of the transformation. Changing this field replaces this resource.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldTemplate: schema.StringAttribute{
				MarkdownDescription: "Name of the template used to match values on encode and decode operations.",
				Required:            true,
			},
			consts.FieldTweakSource: schema.StringAttribute{
				MarkdownDescription: "Source of the tweak value. Valid values are `supplied`, `generated` and `internal`. Vault uses `supplied` if not set.",
				Optional:            true,
				Computed:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("supplied", "generated", "internal"),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldAllowedRoles: schema.ListAttribute{
				MarkdownDescription: "Roles allowed to use this transformation. A role using this transformation must be in this list for encode and decode operations to work.",
				Optional:            true,
				ElementType:         types.StringType,
			},
			consts.FieldDeletionAllowed: schema.BoolAttribute{
				MarkdownDescription: "If `true`, this transformation can be deleted. Otherwise deletion is blocked while this value is `false`. Deleting the transformation deletes the underlying key, making FPE-encoded values impossible to decode without restoring from a backup.",
				Optional:            true,
				Computed:            true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldMaxTweakLen: schema.Int64Attribute{
				MarkdownDescription: "Maximum tweak size, in bytes, allowed for this transformation. Valid values are 0 to 32; 0 allows a tweak of any length. Changing this field replaces this resource.",
				Optional:            true,
				Computed:            true,
				Validators: []validator.Int64{
					int64validator.Between(0, 32),
				},
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
					int64planmodifier.RequiresReplace(),
				},
			},
			consts.FieldFpeAlgorithm: schema.StringAttribute{
				MarkdownDescription: "FPE algorithm used by this transformation (for example `ff1`). Read-only; returned by Vault and never sent on create or update.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
	base.MustAddBaseSchema(&resp.Schema)
}

// readFromVault populates data from Vault. It returns false if the transformation
// does not exist (or on error, in which case the returned diag.Diagnostics contains the error).
func (r *TransformationFPEResource) readFromVault(ctx context.Context, cli *vaultclient.Client, data *TransformationFPEModel) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics

	secret, err := cli.Logical().ReadWithContext(ctx, readPath(data.Mount.ValueString(), data.Name.ValueString()))
	if err != nil {
		diags.AddError(errutil.VaultReadErr(err))
		return false, diags
	}
	if secret == nil || secret.Data == nil {
		return false, diags
	}

	// Vault accepts a single `template` on write but returns a `templates` list on read.
	if templates, ok := secret.Data[consts.FieldTemplates].([]any); ok && len(templates) > 0 {
		if v, ok := templates[0].(string); ok {
			data.Template = types.StringValue(v)
		}
	}

	if v, ok := secret.Data[consts.FieldTweakSource].(string); ok {
		data.TweakSource = types.StringValue(v)
	} else if data.TweakSource.IsUnknown() {
		data.TweakSource = types.StringNull()
	}

	if v, ok := secret.Data[consts.FieldDeletionAllowed].(bool); ok {
		data.DeletionAllowed = types.BoolValue(v)
	} else if data.DeletionAllowed.IsUnknown() {
		data.DeletionAllowed = types.BoolValue(false)
	}

	if v := util.Int64ValueOrNull(secret.Data[consts.FieldMaxTweakLen]); !v.IsNull() {
		data.MaxTweakLen = v
	} else if data.MaxTweakLen.IsUnknown() {
		data.MaxTweakLen = types.Int64Value(0)
	}

	if v, ok := secret.Data[consts.FieldFpeAlgorithm].(string); ok {
		data.FPEAlgorithm = types.StringValue(v)
	} else if data.FPEAlgorithm.IsUnknown() {
		data.FPEAlgorithm = types.StringNull()
	}

	// Vault returns an empty list when no roles are set. Keep null in that case when the
	// config omitted allowed_roles, otherwise Terraform sees null become [] after apply.
	roles := []string{}
	if raw, ok := secret.Data[consts.FieldAllowedRoles].([]any); ok {
		for _, item := range raw {
			if s, ok := item.(string); ok {
				roles = append(roles, s)
			}
		}
	}
	if len(roles) == 0 && (data.AllowedRoles.IsNull() || data.AllowedRoles.IsUnknown()) {
		data.AllowedRoles = types.ListNull(types.StringType)
	} else {
		list, d := types.ListValueFrom(ctx, types.StringType, roles)
		diags.Append(d...)
		if d.HasError() {
			return false, diags
		}
		data.AllowedRoles = list
	}

	return true, diags
}

// requestBody builds the request body for POST transformations/fpe/:name from the plan
func (r *TransformationFPEResource) requestBody(ctx context.Context, plan *TransformationFPEModel, create bool) (map[string]any, diag.Diagnostics) {
	var diags diag.Diagnostics

	body := map[string]any{
		consts.FieldTemplate: plan.Template.ValueString(),
	}
	if !plan.TweakSource.IsNull() && !plan.TweakSource.IsUnknown() {
		body[consts.FieldTweakSource] = plan.TweakSource.ValueString()
	}
	if !plan.DeletionAllowed.IsNull() && !plan.DeletionAllowed.IsUnknown() {
		body[consts.FieldDeletionAllowed] = plan.DeletionAllowed.ValueBool()
	}
	if create && !plan.MaxTweakLen.IsNull() && !plan.MaxTweakLen.IsUnknown() {
		body[consts.FieldMaxTweakLen] = plan.MaxTweakLen.ValueInt64()
	}

	// On update an omitted allowed_roles would leave the previous roles in place,
	// so always send the list (empty when unset) to let roles be removed.
	roles := []string{}
	if !plan.AllowedRoles.IsNull() && !plan.AllowedRoles.IsUnknown() {
		diags.Append(plan.AllowedRoles.ElementsAs(ctx, &roles, false)...)
	}
	if !create || len(roles) > 0 {
		body[consts.FieldAllowedRoles] = roles
	}

	return body, diags
}

func (r *TransformationFPEResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan TransformationFPEModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Vault silently ignores max_tweak_len before 2.2.0, which would surface as an inconsistent result after apply.
	if !plan.MaxTweakLen.IsNull() && !plan.MaxTweakLen.IsUnknown() && !r.Meta().IsAPISupported(provider.VaultVersion220) {
		resp.Diagnostics.AddAttributeError(
			path.Root(consts.FieldMaxTweakLen),
			"Unsupported Vault version",
			fmt.Sprintf("%s requires Vault version %s or later.", consts.FieldMaxTweakLen, provider.VaultVersion220),
		)
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), plan.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	body, d := r.requestBody(ctx, &plan, true)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	if _, err := cli.Logical().WriteWithContext(ctx, typedPath(plan.Mount.ValueString(), typeFPE, plan.Name.ValueString()), body); err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	found, d := r.readFromVault(ctx, cli, &plan)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !found {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *TransformationFPEResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state TransformationFPEModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), state.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	found, d := r.readFromVault(ctx, cli, &state)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !found {
		tflog.Warn(ctx, "FPE transformation not found, removing from state")
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *TransformationFPEResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan TransformationFPEModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), plan.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	body, d := r.requestBody(ctx, &plan, false)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	if _, err := cli.Logical().WriteWithContext(ctx, typedPath(plan.Mount.ValueString(), typeFPE, plan.Name.ValueString()), body); err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}

	found, d := r.readFromVault(ctx, cli, &plan)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !found {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *TransformationFPEResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state TransformationFPEModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), state.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Vault blocks deletion while deletion_allowed is false; the error is surfaced as-is.
	if _, err := cli.Logical().DeleteWithContext(ctx, readPath(state.Mount.ValueString(), state.Name.ValueString())); err != nil {
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
		return
	}
}

func (r *TransformationFPEResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parsed, err := parseTransformationID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}

	var data TransformationFPEModel
	data.Mount = types.StringValue(parsed.Mount)
	data.Name = types.StringValue(parsed.Name)

	// Namespaced resources can only be imported by providing the namespace through an
	// environment variable. Persist it so the imported state matches the configuration.
	if ns := os.Getenv(consts.EnvVarVaultNamespaceImport); ns != "" {
		data.Namespace = types.StringValue(ns)
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Only FPE transformations can be managed by this resource.
	secret, err := cli.Logical().ReadWithContext(ctx, readPath(parsed.Mount, parsed.Name))
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if secret == nil || secret.Data == nil {
		resp.Diagnostics.AddError("Resource not found", fmt.Sprintf("Transformation %q not found on mount %q", parsed.Name, parsed.Mount))
		return
	}
	if t, ok := secret.Data[consts.FieldType].(string); ok && t != typeFPE {
		resp.Diagnostics.AddError(
			"Transformation is not an FPE transformation",
			fmt.Sprintf("Transformation %q on mount %q has type %q and cannot be managed by vault_transform_transformation_fpe.", parsed.Name, parsed.Mount, t),
		)
		return
	}

	found, d := r.readFromVault(ctx, cli, &data)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !found {
		resp.Diagnostics.AddError("Resource not found", fmt.Sprintf("Transformation %q not found on mount %q", parsed.Name, parsed.Mount))
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
