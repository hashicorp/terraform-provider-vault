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

var caGeneratedIDRe = regexp.MustCompile(`^([^/]+)/ca/([^/]+)$`)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &KMIPCAGeneratedResource{}

// NewKMIPCAGeneratedResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewKMIPCAGeneratedResource() resource.Resource { return &KMIPCAGeneratedResource{} }

// KMIPCAGeneratedResource implements the methods that define this resource
type KMIPCAGeneratedResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

// KMIPCAGeneratedModel describes the Terraform resource data model to match the
// resource schema.
type KMIPCAGeneratedModel struct {
	base.BaseModel

	Path    types.String `tfsdk:"path"`
	Name    types.String `tfsdk:"name"`
	CAPem   types.String `tfsdk:"ca_pem"`
	KeyType types.String `tfsdk:"key_type"`
	KeyBits types.Int64  `tfsdk:"key_bits"`
	TTL     types.Int64  `tfsdk:"ttl"`
}

// KMIPCAGeneratedAPIModel describes the Vault API data model.
type KMIPCAGeneratedAPIModel struct {
	CAPem   string `json:"ca_pem" mapstructure:"ca_pem"`
	KeyType string `json:"key_type" mapstructure:"key_type"`
	KeyBits int64  `json:"key_bits" mapstructure:"key_bits"`
	TTL     int64  `json:"ttl" mapstructure:"ttl"`
}

func (r *KMIPCAGeneratedResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_kmip_secret_ca_generated"
}

func (r *KMIPCAGeneratedResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
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
				Computed:            true,
			},
			"key_type": schema.StringAttribute{
				MarkdownDescription: "CA key type (rsa or ec).",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("rsa", "ec"),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIfConfigured(),
				},
			},
			"key_bits": schema.Int64Attribute{
				MarkdownDescription: "CA key bits. Valid values depend on key_type: For rsa: 2048, 3072, 4096. For ec: 224, 256, 384, 521.",
				Required:            true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplaceIfConfigured(),
				},
			},
			"ttl": schema.Int64Attribute{
				MarkdownDescription: "CA TTL in seconds. Defaults to 365 days.",
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(31536000),
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplaceIfConfigured(),
				},
			},
		},
		MarkdownDescription: "Manage generated KMIP secret engine CAs.",
	}
	base.MustAddBaseSchema(&resp.Schema)
}

// Create is called during the terraform apply command.
func (r *KMIPCAGeneratedResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data KMIPCAGeneratedModel
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
	apiPath := fmt.Sprintf("%s/ca/%s/generate", backend, name)

	vaultRequest := map[string]any{
		"key_type": data.KeyType.ValueString(),
		"key_bits": data.KeyBits.ValueInt64(),
	}

	if !data.TTL.IsNull() && !data.TTL.IsUnknown() {
		vaultRequest["ttl"] = data.TTL.ValueInt64()
	}

	writeResp, err := cli.Logical().WriteWithContext(ctx, apiPath, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	var apiModel KMIPCAGeneratedAPIModel
	err = model.ToAPIModel(writeResp.Data, &apiModel)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Map API response to Terraform model
	if apiModel.CAPem != "" {
		data.CAPem = types.StringValue(apiModel.CAPem)
	}
	if apiModel.KeyType != "" {
		data.KeyType = types.StringValue(apiModel.KeyType)
	}
	if apiModel.KeyBits > 0 {
		data.KeyBits = types.Int64Value(apiModel.KeyBits)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during the terraform apply, terraform plan, and terraform refresh commands.
func (r *KMIPCAGeneratedResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data KMIPCAGeneratedModel
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

	var apiModel KMIPCAGeneratedAPIModel
	err = model.ToAPIModel(readResp.Data, &apiModel)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Map API response to Terraform model
	if apiModel.CAPem != "" {
		data.CAPem = types.StringValue(apiModel.CAPem)
	}
	if apiModel.KeyType != "" {
		data.KeyType = types.StringValue(apiModel.KeyType)
	}
	if apiModel.KeyBits > 0 {
		data.KeyBits = types.Int64Value(apiModel.KeyBits)
	}
	if apiModel.TTL > 0 {
		data.TTL = types.Int64Value(apiModel.TTL)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *KMIPCAGeneratedResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// All fields require replacement, so this should never be called
	resp.Diagnostics.AddError(
		"Update Not Supported",
		"All fields in this resource require replacement. This update should not have been called.",
	)
}

func (r *KMIPCAGeneratedResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data KMIPCAGeneratedModel

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

func (r *KMIPCAGeneratedResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := req.ID

	matches := caGeneratedIDRe.FindStringSubmatch(id)
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
