// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package transform

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
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
	_ resource.Resource                = &MaskingTransformationResource{}
	_ resource.ResourceWithConfigure   = &MaskingTransformationResource{}
	_ resource.ResourceWithImportState = &MaskingTransformationResource{}
)

// NewTransformationMaskingResource returns the implementation for this resource.
func NewTransformationMaskingResource() resource.Resource {
	return &MaskingTransformationResource{}
}

// MaskingTransformationResource manages a Vault Transform masking transformation
// (/transformations/masking/:name).
type MaskingTransformationResource struct {
	base.ResourceWithConfigure
}

// MaskingTransformationResourceModel describes the Terraform resource data model.
type MaskingTransformationResourceModel struct {
	base.BaseModel

	Mount types.String `tfsdk:"mount"`
	Name  types.String `tfsdk:"name"`

	Template         types.String `tfsdk:"template"`
	MaskingCharacter types.String `tfsdk:"masking_character"`

	AllowedRoles types.List `tfsdk:"allowed_roles"`
}

func (r *MaskingTransformationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_transform_transformation_masking"
}

func (r *MaskingTransformationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	attrs := map[string]schema.Attribute{
		consts.FieldMount: schema.StringAttribute{
			MarkdownDescription: "Path where the Transform secret backend is mounted. Changing this field replaces this resource.",
			Required:            true,
			PlanModifiers: []planmodifier.String{
				stringplanmodifier.RequiresReplace(),
			},
		},
		consts.FieldName: schema.StringAttribute{
			MarkdownDescription: "Name of the transformation to create. Changing this field replaces this resource.",
			Required:            true,
			PlanModifiers: []planmodifier.String{
				stringplanmodifier.RequiresReplace(),
			},
		},
		consts.FieldTemplate: schema.StringAttribute{
			MarkdownDescription: "Specifies the template name to use for matching value on encode and decode operations when using this transformation.",
			Required:            true,
		},
		consts.FieldMaskingCharacter: schema.StringAttribute{
			MarkdownDescription: "Specifies the single character to use for masking. Defaults to `*` when not set.",
			Optional:            true,
			Computed:            true,
			Validators: []validator.String{
				stringvalidator.LengthBetween(1, 1),
			},
			PlanModifiers: []planmodifier.String{
				stringplanmodifier.UseStateForUnknown(),
			},
		},
		consts.FieldAllowedRoles: schema.ListAttribute{
			MarkdownDescription: "The list of roles allowed to perform this transformation. Defaults to an empty list when not set.",
			Optional:            true,
			Computed:            true,
			ElementType:         types.StringType,
			PlanModifiers: []planmodifier.List{
				listplanmodifier.UseStateForUnknown(),
			},
		},
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Creates a Vault Transform masking transformation. Requires Vault Enterprise.",
		Attributes:          attrs,
	}
	base.MustAddBaseSchema(&resp.Schema)
}

func (r *MaskingTransformationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan MaskingTransformationResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), plan.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	if !provider.IsEnterpriseSupported(r.Meta()) {
		resp.Diagnostics.AddError("Unsupported Vault edition", "The Transform secrets engine requires Vault Enterprise.")
		return
	}

	body, d := plan.requestBody(ctx)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	if _, err := cli.Logical().WriteWithContext(ctx, typedPath(plan.Mount.ValueString(), typeMasking, plan.Name.ValueString()), body); err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	found, d := r.readFromVault(ctx, cli, &plan)
	resp.Diagnostics.Append(d...)
	if d.HasError() {
		return
	}
	if !found {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *MaskingTransformationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state MaskingTransformationResourceModel
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
		tflog.Warn(ctx, "Transform transformation not found, removing from state")
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *MaskingTransformationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan MaskingTransformationResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), plan.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	body, d := plan.requestBody(ctx)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	if _, err := cli.Logical().WriteWithContext(ctx, typedPath(plan.Mount.ValueString(), typeMasking, plan.Name.ValueString()), body); err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}

	found, d := r.readFromVault(ctx, cli, &plan)
	resp.Diagnostics.Append(d...)
	if d.HasError() {
		return
	}
	if !found {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *MaskingTransformationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state MaskingTransformationResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), state.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	p := typedPath(state.Mount.ValueString(), typeMasking, state.Name.ValueString())
	if _, err := cli.Logical().DeleteWithContext(ctx, p); err != nil {
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
		return
	}
}

func (r *MaskingTransformationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parsed, err := parseTransformationID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}
	data := MaskingTransformationResourceModel{
		Mount: types.StringValue(parsed.Mount),
		Name:  types.StringValue(parsed.Name),
	}
	// Namespaced resources can only be imported by providing the namespace through an
	// environment variable. It is persisted so the imported state matches the configuration.
	if ns := os.Getenv(consts.EnvVarVaultNamespaceImport); ns != "" {
		data.Namespace = types.StringValue(ns)
	}

	if !provider.IsEnterpriseSupported(r.Meta()) {
		resp.Diagnostics.AddError("Unsupported Vault edition", "The Transform secrets engine requires Vault Enterprise.")
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	found, d := r.readFromVault(ctx, cli, &data)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !found {
		resp.Diagnostics.AddError("Resource not found", fmt.Sprintf("Transform transformation %q not found on mount %q", data.Name.ValueString(), data.Mount.ValueString()))
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// readFromVault populates data from Vault. It returns false if the transformation does
// not exist (or on error, in which case the returned diag.Diagnostics contains the error).
func (r *MaskingTransformationResource) readFromVault(ctx context.Context, cli *vaultclient.Client, data *MaskingTransformationResourceModel) (bool, diag.Diagnostics) {
	secretData, diags := readTransformation(ctx, cli, data.Mount.ValueString(), data.Name.ValueString(), typeMasking)
	if diags.HasError() || secretData == nil {
		return false, diags
	}

	data.Template = util.StringValueOrNull(secretData[consts.FieldTemplate])

	// Vault accepts masking_character as a string but returns it as its integer character code
	// (e.g. 42 for "*").
	data.MaskingCharacter = types.StringNull()
	if code := util.Int64ValueOrNull(secretData[consts.FieldMaskingCharacter]); !code.IsNull() {
		data.MaskingCharacter = types.StringValue(string(rune(code.ValueInt64())))
	}

	if raw, ok := secretData[consts.FieldAllowedRoles]; ok && raw != nil {
		roles, d := types.ListValueFrom(ctx, types.StringType, raw)
		diags.Append(d...)
		if !d.HasError() {
			data.AllowedRoles = roles
		}
	} else if data.AllowedRoles.IsUnknown() {
		data.AllowedRoles = types.ListNull(types.StringType)
	}

	return true, diags
}

// requestBody builds the create and update request body from the plan. Vault uses the same
// endpoint for both.
func (m *MaskingTransformationResourceModel) requestBody(ctx context.Context) (map[string]any, diag.Diagnostics) {
	var diags diag.Diagnostics
	body := map[string]any{
		"template": m.Template.ValueString(),
	}
	if !m.MaskingCharacter.IsNull() && !m.MaskingCharacter.IsUnknown() {
		body["masking_character"] = m.MaskingCharacter.ValueString()
	}
	if !m.AllowedRoles.IsNull() && !m.AllowedRoles.IsUnknown() {
		roles := make([]string, 0, len(m.AllowedRoles.Elements()))
		diags.Append(m.AllowedRoles.ElementsAs(ctx, &roles, false)...)
		if !diags.HasError() {
			body["allowed_roles"] = roles
		}
	}
	return body, diags
}
