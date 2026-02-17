// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
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
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
)

var caImportedIDRe = regexp.MustCompile(`^([^/]+)/ca/([^/]+)$`)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &KMIPCAImportedResource{}

// NewKMIPCAImportedResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewKMIPCAImportedResource() resource.Resource { return &KMIPCAImportedResource{} }

// KMIPCAImportedResource implements the methods that define this resource
type KMIPCAImportedResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

// KMIPCAImportedModel describes the Terraform resource data model to match the
// resource schema.
type KMIPCAImportedModel struct {
	base.BaseModel

	Path       types.String `tfsdk:"path"`
	Name       types.String `tfsdk:"name"`
	CAPem      types.String `tfsdk:"ca_pem"`
	ScopeName  types.String `tfsdk:"scope_name"`
	ScopeField types.String `tfsdk:"scope_field"`
	RoleName   types.String `tfsdk:"role_name"`
	RoleField  types.String `tfsdk:"role_field"`
}

// KMIPCAImportedAPIModel describes the Vault API data model.
type KMIPCAImportedAPIModel struct {
	CAPem      string `json:"ca_pem" mapstructure:"ca_pem"`
	ScopeName  string `json:"scope_name" mapstructure:"scope_name"`
	ScopeField string `json:"scope_field" mapstructure:"scope_field"`
	RoleName   string `json:"role_name" mapstructure:"role_name"`
	RoleField  string `json:"role_field" mapstructure:"role_field"`
}

// exactlyOneOfValidator validates that exactly one of two fields is set
type exactlyOneOfValidator struct {
	otherField string
}

func (v exactlyOneOfValidator) Description(ctx context.Context) string {
	return fmt.Sprintf("Exactly one of this field or %s must be specified.", v.otherField)
}

func (v exactlyOneOfValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v exactlyOneOfValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	// Check if current field is set
	currentFieldSet := !req.ConfigValue.IsNull() && req.ConfigValue.ValueString() != ""

	// Get the other field value
	var otherFieldValue types.String
	diags := req.Config.GetAttribute(ctx, path.Root(v.otherField), &otherFieldValue)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	otherFieldSet := !otherFieldValue.IsNull() && otherFieldValue.ValueString() != ""

	// Exactly one must be set
	if currentFieldSet && otherFieldSet {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Conflicting Attribute Configuration",
			fmt.Sprintf("Only one of %s or %s can be specified, not both.",
				req.Path.String(), v.otherField),
		)
	} else if !currentFieldSet && !otherFieldSet {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Missing Attribute Configuration",
			fmt.Sprintf("Exactly one of %s or %s must be specified.",
				req.Path.String(), v.otherField),
		)
	}
}

func (r *KMIPCAImportedResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_kmip_secret_ca_imported"
}

func (r *KMIPCAImportedResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldPath: schema.StringAttribute{
				MarkdownDescription: "Path where KMIP backend is mounted.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldName: schema.StringAttribute{
				MarkdownDescription: "Name to identify the CA.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"ca_pem": schema.StringAttribute{
				MarkdownDescription: "CA certificate in PEM format.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"scope_name": schema.StringAttribute{
				MarkdownDescription: "The scope name to associate with this CA. Must specify exactly one of scope_name or scope_field.",
				Optional:            true,
				Validators: []validator.String{
					exactlyOneOfValidator{otherField: "scope_field"},
				},
			},
			"scope_field": schema.StringAttribute{
				MarkdownDescription: "The field in the certificate to use for the scope (CN, O, OU, or UID). Must specify exactly one of scope_name or scope_field.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("CN", "O", "OU", "UID"),
					exactlyOneOfValidator{otherField: "scope_name"},
				},
			},
			"role_name": schema.StringAttribute{
				MarkdownDescription: "The role name to associate with this CA. Must specify exactly one of role_name or role_field.",
				Optional:            true,
				Validators: []validator.String{
					exactlyOneOfValidator{otherField: "role_field"},
				},
			},
			"role_field": schema.StringAttribute{
				MarkdownDescription: "The field in the certificate to use for the role (CN, O, OU, or UID). Must specify exactly one of role_name or role_field.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("CN", "O", "OU", "UID"),
					exactlyOneOfValidator{otherField: "role_name"},
				},
			},
		},
		MarkdownDescription: "Manage imported KMIP secret engine CAs.",
	}
	base.MustAddBaseSchema(&resp.Schema)
}

// Create is called during the terraform apply command.
func (r *KMIPCAImportedResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data KMIPCAImportedModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	backend := data.Path.ValueString()
	name := data.Name.ValueString()
	apiPath := fmt.Sprintf("%s/ca/%s/import", backend, name)

	vaultRequest := map[string]any{
		"ca_pem": data.CAPem.ValueString(),
	}

	// Add scope configuration
	if !data.ScopeName.IsNull() && !data.ScopeName.IsUnknown() {
		vaultRequest["scope_name"] = data.ScopeName.ValueString()
	}
	if !data.ScopeField.IsNull() && !data.ScopeField.IsUnknown() {
		vaultRequest["scope_field"] = data.ScopeField.ValueString()
	}

	// Add role configuration
	if !data.RoleName.IsNull() && !data.RoleName.IsUnknown() {
		vaultRequest["role_name"] = data.RoleName.ValueString()
	}
	if !data.RoleField.IsNull() && !data.RoleField.IsUnknown() {
		vaultRequest["role_field"] = data.RoleField.ValueString()
	}

	writeResp, err := cli.Logical().WriteWithContext(ctx, apiPath, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	var apiModel KMIPCAImportedAPIModel
	err = model.ToAPIModel(writeResp.Data, &apiModel)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Map API response to Terraform model
	mapImportedAPIModelToTerraformModel(&apiModel, &data)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during the terraform apply, terraform plan, and terraform refresh commands.
func (r *KMIPCAImportedResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data KMIPCAImportedModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	backend := data.Path.ValueString()
	name := data.Name.ValueString()
	apiPath := fmt.Sprintf("%s/ca/%s", backend, name)

	readResp, err := cli.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if readResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	var apiModel KMIPCAImportedAPIModel
	err = model.ToAPIModel(readResp.Data, &apiModel)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Map API response to Terraform model
	mapImportedAPIModelToTerraformModel(&apiModel, &data)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *KMIPCAImportedResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data KMIPCAImportedModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	backend := data.Path.ValueString()
	name := data.Name.ValueString()
	apiPath := fmt.Sprintf("%s/ca/%s", backend, name)

	// Only scope and role fields can be updated
	vaultRequest := make(map[string]any)

	if !data.ScopeName.IsNull() && !data.ScopeName.IsUnknown() {
		vaultRequest["scope_name"] = data.ScopeName.ValueString()
	}
	if !data.ScopeField.IsNull() && !data.ScopeField.IsUnknown() {
		vaultRequest["scope_field"] = data.ScopeField.ValueString()
	}
	if !data.RoleName.IsNull() && !data.RoleName.IsUnknown() {
		vaultRequest["role_name"] = data.RoleName.ValueString()
	}
	if !data.RoleField.IsNull() && !data.RoleField.IsUnknown() {
		vaultRequest["role_field"] = data.RoleField.ValueString()
	}

	writeResp, err := cli.Logical().WriteWithContext(ctx, apiPath, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}

	var apiModel KMIPCAImportedAPIModel
	err = model.ToAPIModel(writeResp.Data, &apiModel)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Map API response to Terraform model
	mapImportedAPIModelToTerraformModel(&apiModel, &data)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// mapImportedAPIModelToTerraformModel maps the API response fields to the Terraform model
func mapImportedAPIModelToTerraformModel(apiModel *KMIPCAImportedAPIModel, data *KMIPCAImportedModel) {
	// Note: ca_pem is not updated from API response as it's user-provided input
	// and may have formatting differences (trailing newlines, etc.)

	if apiModel.ScopeName != "" {
		data.ScopeName = types.StringValue(apiModel.ScopeName)
	}
	if apiModel.ScopeField != "" {
		data.ScopeField = types.StringValue(apiModel.ScopeField)
	}
	if apiModel.RoleName != "" {
		data.RoleName = types.StringValue(apiModel.RoleName)
	}
	if apiModel.RoleField != "" {
		data.RoleField = types.StringValue(apiModel.RoleField)
	}
}

func (r *KMIPCAImportedResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data KMIPCAImportedModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	backend := data.Path.ValueString()
	name := data.Name.ValueString()
	apiPath := fmt.Sprintf("%s/ca/%s", backend, name)

	if _, err := cli.Logical().DeleteWithContext(ctx, apiPath); err != nil {
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
		return
	}
}

func (r *KMIPCAImportedResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := req.ID

	matches := caImportedIDRe.FindStringSubmatch(id)
	if len(matches) != 3 {
		resp.Diagnostics.AddError(
			"Unexpected Import Identifier",
			fmt.Sprintf("Expected ID in format '<backend>/ca/<name>', got: %q", id),
		)
		return
	}

	backend := matches[1]
	name := matches[2]

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldPath), backend)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), name)...)
}

// Made with Bob
