// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
)

var _ resource.Resource = &AzureKMSResource{}
var _ resource.ResourceWithImportState = &AzureKMSResource{}

type AzureKMSResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

type AzureKMSResourceModel struct {
	base.BaseModelLegacy
	Path          types.String `tfsdk:"path"`
	Name          types.String `tfsdk:"name"`
	KeyCollection types.String `tfsdk:"key_collection"`
	TenantID      types.String `tfsdk:"tenant_id"`
	ClientID      types.String `tfsdk:"client_id"`
	ClientSecret  types.String `tfsdk:"client_secret"`
	Environment   types.String `tfsdk:"environment"`
	UUID          types.String `tfsdk:"uuid"`
}

func NewAzureKMSResource() resource.Resource {
	return &AzureKMSResource{}
}

func (r *AzureKMSResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_keymgmt_azure_kms"
}

func (r *AzureKMSResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an Azure Key Vault provider for Vault Key Management",

		Attributes: map[string]schema.Attribute{
			consts.FieldPath: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Path where the Key Management secrets engine is mounted",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldName: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the Azure Key Vault provider",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldKeyCollection: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Azure Key Vault name where keys are stored",
			},
			consts.FieldTenantID: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Azure Active Directory tenant ID",
			},
			consts.FieldClientID: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Azure service principal client ID",
			},
			consts.FieldClientSecret: schema.StringAttribute{
				Required:            true,
				Sensitive:           true,
				MarkdownDescription: "Azure service principal client secret",
			},
			consts.FieldEnvironment: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Azure environment (e.g., AzurePublicCloud, AzureUSGovernment, AzureChinaCloud, AzureGermanCloud)",
			},
			consts.FieldUUID: schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "UUID of the KMS provider",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
	base.MustAddLegacyBaseSchema(&resp.Schema)
}

func (r *AzureKMSResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data AzureKMSResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error getting Vault client", err.Error())
		return
	}

	vaultPath := data.Path.ValueString()
	name := data.Name.ValueString()
	apiPath := buildKMSPath(vaultPath, name)

	writeData := map[string]interface{}{
		"provider":       "azurekeyvault",
		"key_collection": data.KeyCollection.ValueString(),
		"tenant_id":      data.TenantID.ValueString(),
		"client_id":      data.ClientID.ValueString(),
		"client_secret":  data.ClientSecret.ValueString(),
	}

	if !data.Environment.IsNull() {
		writeData["environment"] = data.Environment.ValueString()
	}

	if _, err := cli.Logical().WriteWithContext(ctx, apiPath, writeData); err != nil {
		resp.Diagnostics.AddError("Error creating Azure Key Vault provider", fmt.Sprintf("Error creating Azure Key Vault provider at %s: %s", apiPath, err))
		return
	}

	data.ID = types.StringValue(apiPath)
	r.read(ctx, cli, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AzureKMSResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data AzureKMSResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error getting Vault client", err.Error())
		return
	}

	r.read(ctx, cli, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.ID.IsNull() {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AzureKMSResource) read(ctx context.Context, cli *api.Client, data *AzureKMSResourceModel, diags *diag.Diagnostics) {
	apiPath := data.ID.ValueString()
	vaultResp, err := cli.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		diags.AddError("Error reading Azure Key Vault provider", fmt.Sprintf("Error reading Azure Key Vault provider at %s: %s", apiPath, err))
		return
	}

	if vaultResp == nil {
		data.ID = types.StringNull()
		return
	}

	parts := strings.Split(strings.Trim(apiPath, "/"), "/")
	kmsIndex := -1
	for i, part := range parts {
		if part == "kms" {
			kmsIndex = i
			break
		}
	}

	if kmsIndex == -1 || kmsIndex+1 >= len(parts) {
		diags.AddError("Invalid path structure", fmt.Sprintf("Invalid KMS path: %s", apiPath))
		return
	}

	data.Path = types.StringValue(strings.Join(parts[:kmsIndex], "/"))
	data.Name = types.StringValue(parts[kmsIndex+1])

	if v, ok := vaultResp.Data["key_collection"].(string); ok {
		data.KeyCollection = types.StringValue(v)
	}
	if v, ok := vaultResp.Data["uuid"].(string); ok {
		data.UUID = types.StringValue(v)
	}
	if v, ok := vaultResp.Data["tenant_id"].(string); ok {
		data.TenantID = types.StringValue(v)
	}
	if v, ok := vaultResp.Data["client_id"].(string); ok {
		data.ClientID = types.StringValue(v)
	}
	if v, ok := vaultResp.Data["environment"].(string); ok {
		data.Environment = types.StringValue(v)
	}
}

func (r *AzureKMSResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state AzureKMSResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), plan.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error getting Vault client", err.Error())
		return
	}

	apiPath := plan.ID.ValueString()
	writeData := map[string]interface{}{
		"provider": "azurekeyvault",
	}
	hasChanges := false

	if !plan.KeyCollection.Equal(state.KeyCollection) {
		writeData["key_collection"] = plan.KeyCollection.ValueString()
		hasChanges = true
	}
	if !plan.TenantID.Equal(state.TenantID) {
		writeData["tenant_id"] = plan.TenantID.ValueString()
		hasChanges = true
	}
	if !plan.ClientID.Equal(state.ClientID) {
		writeData["client_id"] = plan.ClientID.ValueString()
		hasChanges = true
	}
	if !plan.ClientSecret.Equal(state.ClientSecret) {
		writeData["client_secret"] = plan.ClientSecret.ValueString()
		hasChanges = true
	}
	if !plan.Environment.Equal(state.Environment) {
		writeData["environment"] = plan.Environment.ValueString()
		hasChanges = true
	}

	if hasChanges {
		if _, err := cli.Logical().WriteWithContext(ctx, apiPath, writeData); err != nil {
			resp.Diagnostics.AddError("Error updating Azure Key Vault provider", fmt.Sprintf("Error updating Azure Key Vault provider at %s: %s", apiPath, err))
			return
		}
	}

	r.read(ctx, cli, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *AzureKMSResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data AzureKMSResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error getting Vault client", err.Error())
		return
	}

	apiPath := data.ID.ValueString()
	if _, err := cli.Logical().DeleteWithContext(ctx, apiPath); err != nil {
		resp.Diagnostics.AddError("Error deleting Azure Key Vault provider", fmt.Sprintf("Error deleting Azure Key Vault provider at %s: %s", apiPath, err))
		return
	}
}
