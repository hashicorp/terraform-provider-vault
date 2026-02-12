// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
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

var caIDRe = regexp.MustCompile(`^([^/]+)/ca/([^/]+)$`)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &KMIPCAResource{}

// NewKMIPCAResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewKMIPCAResource() resource.Resource { return &KMIPCAResource{} }

// KMIPCAResource implements the methods that define this resource
type KMIPCAResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

// KMIPCAModel describes the Terraform resource data model to match the
// resource schema.
type KMIPCAModel struct {
	base.BaseModel

	Path       types.String `tfsdk:"path"`
	Name       types.String `tfsdk:"name"`
	CAPem      types.String `tfsdk:"ca_pem"`
	KeyType    types.String `tfsdk:"key_type"`
	KeyBits    types.Int64  `tfsdk:"key_bits"`
	TTL        types.Int64  `tfsdk:"ttl"`
	ScopeName  types.String `tfsdk:"scope_name"`
	ScopeField types.String `tfsdk:"scope_field"`
	RoleName   types.String `tfsdk:"role_name"`
	RoleField  types.String `tfsdk:"role_field"`
}

// KMIPCAAPIModel describes the Vault API data model.
type KMIPCAAPIModel struct {
	CAPem      string `json:"ca_pem" mapstructure:"ca_pem"`
	KeyType    string `json:"key_type" mapstructure:"key_type"`
	KeyBits    int64  `json:"key_bits" mapstructure:"key_bits"`
	ScopeName  string `json:"scope_name" mapstructure:"scope_name"`
	ScopeField string `json:"scope_field" mapstructure:"scope_field"`
	RoleName   string `json:"role_name" mapstructure:"role_name"`
	RoleField  string `json:"role_field" mapstructure:"role_field"`
}

// importedCAExactlyOneOfValidator validates that exactly one of two fields is set
// when ca_pem is specified (imported CA scenario), and that neither field is set
// when ca_pem is not specified (generated CA scenario)
type importedCAExactlyOneOfValidator struct {
	otherField string
}

func (v importedCAExactlyOneOfValidator) Description(ctx context.Context) string {
	return fmt.Sprintf("For imported CAs, exactly one of this field or %s must be specified. For generated CAs, neither should be specified.", v.otherField)
}

func (v importedCAExactlyOneOfValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v importedCAExactlyOneOfValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	// Get the ca_pem value to determine if this is an import
	var caPem types.String
	diags := req.Config.GetAttribute(ctx, path.Root("ca_pem"), &caPem)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check if current field is set
	currentFieldSet := !req.ConfigValue.IsNull() && req.ConfigValue.ValueString() != ""

	isImport := !caPem.IsNull() && caPem.ValueString() != ""

	if isImport {
		// For imported CAs, validate exactly one of the two fields is set
		// Get the other field value
		var otherFieldValue types.String
		diags = req.Config.GetAttribute(ctx, path.Root(v.otherField), &otherFieldValue)
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
				fmt.Sprintf("For imported CAs, only one of %s or %s can be specified, not both.",
					req.Path.String(), v.otherField),
			)
		} else if !currentFieldSet && !otherFieldSet {
			resp.Diagnostics.AddAttributeError(
				req.Path,
				"Missing Attribute Configuration",
				fmt.Sprintf("For imported CAs, exactly one of %s or %s must be specified.",
					req.Path.String(), v.otherField),
			)
		}
	} else {
		// For generated CAs, neither field should be set
		if currentFieldSet {
			resp.Diagnostics.AddAttributeError(
				req.Path,
				"Invalid Attribute Configuration",
				fmt.Sprintf("For generated CAs, %s cannot be specified. This field is only valid for imported CAs.",
					req.Path.String()),
			)
		}
	}
}

func (r *KMIPCAResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_kmip_secret_ca"
}

func (r *KMIPCAResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
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
				MarkdownDescription: "CA certificate in PEM format. Required for imported CAs. Conflicts with key_type, key_bits, and ttl.",
				Optional:            true,
				Sensitive:           true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"key_type": schema.StringAttribute{
				MarkdownDescription: "CA key type (rsa or ec). Required for generated CAs. Conflicts with ca_pem.",
				Optional:            true,
				Computed:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("rsa", "ec"),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"key_bits": schema.Int64Attribute{
				MarkdownDescription: "CA key bits. Valid values depend on key_type. Required for generated CAs. Conflicts with ca_pem.",
				Optional:            true,
				Computed:            true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"ttl": schema.Int64Attribute{
				MarkdownDescription: "CA TTL in seconds. Defaults to 365 days. Only used for generated CAs. Conflicts with ca_pem.",
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(31536000),
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"scope_name": schema.StringAttribute{
				MarkdownDescription: "The scope name to associate with this CA. For imported CAs, must specify exactly one of scope_name or scope_field.",
				Optional:            true,
				Validators: []validator.String{
					importedCAExactlyOneOfValidator{otherField: "scope_field"},
				},
			},
			"scope_field": schema.StringAttribute{
				MarkdownDescription: "The field in the certificate to use for the scope (CN, O, OU, or UID). For imported CAs, must specify exactly one of scope_name or scope_field.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("CN", "O", "OU", "UID"),
					importedCAExactlyOneOfValidator{otherField: "scope_name"},
				},
			},
			"role_name": schema.StringAttribute{
				MarkdownDescription: "The role name to associate with this CA. For imported CAs, must specify exactly one of role_name or role_field.",
				Optional:            true,
				Validators: []validator.String{
					importedCAExactlyOneOfValidator{otherField: "role_field"},
				},
			},
			"role_field": schema.StringAttribute{
				MarkdownDescription: "The field in the certificate to use for the role (CN, O, OU, or UID). For imported CAs, must specify exactly one of role_name or role_field.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("CN", "O", "OU", "UID"),
					importedCAExactlyOneOfValidator{otherField: "role_name"},
				},
			},
		},
		MarkdownDescription: "Manage KMIP secret engine CAs. Supports both generating new CAs and importing existing ones.",
	}
	base.MustAddBaseSchema(&resp.Schema)
}

// Create is called during the terraform apply command.
func (r *KMIPCAResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data KMIPCAModel
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

	// Determine if this is a generate or import operation
	isImport := !data.CAPem.IsNull() && data.CAPem.ValueString() != ""
	isGenerate := !data.KeyType.IsNull() && data.KeyType.ValueString() != ""

	if isImport && isGenerate {
		resp.Diagnostics.AddError(
			"Invalid Configuration",
			"Cannot specify both ca_pem (for import) and key_type/key_bits (for generate). Choose one approach.",
		)
		return
	}

	if !isImport && !isGenerate {
		resp.Diagnostics.AddError(
			"Invalid Configuration",
			"Must specify either ca_pem (for import) or key_type and key_bits (for generate).",
		)
		return
	}

	var apiPath string
	var vaultRequest map[string]any
	var diags diag.Diagnostics

	if isImport {
		apiPath = fmt.Sprintf("%s/ca/%s/import", backend, name)
		vaultRequest, diags = buildImportRequestFromModel(ctx, &data)
	} else {
		apiPath = fmt.Sprintf("%s/ca/%s/generate", backend, name)
		vaultRequest, diags = buildGenerateRequestFromModel(ctx, &data)
	}

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	writeResp, err := cli.Logical().WriteWithContext(ctx, apiPath, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	var apiModel KMIPCAAPIModel
	err = model.ToAPIModel(writeResp.Data, &apiModel)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Map API response to Terraform model
	mapAPIModelToTerraformModel(&apiModel, &data)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during the terraform apply, terraform plan, and terraform refresh commands.
func (r *KMIPCAResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data KMIPCAModel
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

	var apiModel KMIPCAAPIModel
	err = model.ToAPIModel(readResp.Data, &apiModel)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Map API response to Terraform model
	// Note: ca_pem is returned from API but we don't update it in state for security
	mapAPIModelToTerraformModel(&apiModel, &data)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *KMIPCAResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data KMIPCAModel
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

	// Only scope and role fields can be updated (and only for imported CAs)
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

	var apiModel KMIPCAAPIModel
	err = model.ToAPIModel(writeResp.Data, &apiModel)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Map API response to Terraform model
	mapAPIModelToTerraformModel(&apiModel, &data)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func buildGenerateRequestFromModel(ctx context.Context, data *KMIPCAModel) (map[string]any, diag.Diagnostics) {
	var diags diag.Diagnostics

	vaultRequest := map[string]any{
		"key_type": data.KeyType.ValueString(),
		"key_bits": data.KeyBits.ValueInt64(),
	}

	if !data.TTL.IsNull() && !data.TTL.IsUnknown() {
		vaultRequest["ttl"] = data.TTL.ValueInt64()
	}

	return vaultRequest, diags
}

func buildImportRequestFromModel(ctx context.Context, data *KMIPCAModel) (map[string]any, diag.Diagnostics) {
	var diags diag.Diagnostics

	vaultRequest := map[string]any{
		"ca_pem": data.CAPem.ValueString(),
	}

	// For imported CAs, we need scope and role configuration
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

	return vaultRequest, diags
}

// mapAPIModelToTerraformModel maps the API response fields to the Terraform model
func mapAPIModelToTerraformModel(apiModel *KMIPCAAPIModel, data *KMIPCAModel) {
	// Map key_type - only set if returned from API
	if apiModel.KeyType != "" {
		data.KeyType = types.StringValue(apiModel.KeyType)
	} else if data.KeyType.IsUnknown() {
		// For imported CAs, key_type is not returned, set to null
		data.KeyType = types.StringNull()
	}

	// Map key_bits - only set if returned from API
	if apiModel.KeyBits > 0 {
		data.KeyBits = types.Int64Value(apiModel.KeyBits)
	} else if data.KeyBits.IsUnknown() {
		// For imported CAs, key_bits is not returned, set to null
		data.KeyBits = types.Int64Null()
	}

	// Map scope and role fields
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

func (r *KMIPCAResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data KMIPCAModel

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

func (r *KMIPCAResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := req.ID

	matches := caIDRe.FindStringSubmatch(id)
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
