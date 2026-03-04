// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

var _ resource.Resource = &AzureKMSResource{}
var _ resource.ResourceWithImportState = &AzureKMSResource{}

type AzureKMSResource struct {
	base.ResourceWithConfigure
}

type AzureKMSResourceModel struct {
	base.BaseModel
	Path          types.String `tfsdk:"path"`
	Name          types.String `tfsdk:"name"`
	KeyCollection types.String `tfsdk:"key_collection"`
	TenantID      types.String `tfsdk:"tenant_id"`
	ClientID      types.String `tfsdk:"client_id"`
	ClientSecret  types.String `tfsdk:"client_secret"`
	Environment   types.String `tfsdk:"environment"`
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
				MarkdownDescription: "Azure environment (e.g., AzurePublicCloud, AzureUSGovernmentCloud, AzureChinaCloud, AzureGermanCloud)",
			},
		},
	}
	base.MustAddBaseSchema(&resp.Schema)
}

func (r *AzureKMSResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data AzureKMSResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultPath := data.Path.ValueString()
	name := data.Name.ValueString()
	apiPath := buildKMSPath(vaultPath, name)

	writeData := map[string]interface{}{
		"provider":       ProviderAzureKV,
		"key_collection": data.KeyCollection.ValueString(),
	}

	// Azure credentials must be sent as a nested credentials object
	creds := make(map[string]string)
	creds["tenant_id"] = data.TenantID.ValueString()
	creds["client_id"] = data.ClientID.ValueString()
	creds["client_secret"] = data.ClientSecret.ValueString()

	if !data.Environment.IsNull() {
		creds["environment"] = data.Environment.ValueString()
	}

	writeData["credentials"] = creds

	if _, err := cli.Logical().WriteWithContext(ctx, apiPath, writeData); err != nil {
		resp.Diagnostics.AddError(errCreating("Azure Key Vault provider", apiPath, err))
		return
	}

	// Read back the state from Vault
	vaultResp, err := cli.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		resp.Diagnostics.AddError(errReading("Azure Key Vault provider", apiPath, err))
		return
	}

	if vaultResp == nil {
		resp.Diagnostics.AddError(
			"Unexpected error after creating Azure Key Vault provider",
			fmt.Sprintf("Azure Key Vault provider not found at path %q immediately after creation", apiPath),
		)
		return
	}

	// Parse response data
	r.parseAzureKMSResponse(vaultResp.Data, &data)

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
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Build API path and read from Vault
	apiPath := buildKMSPath(data.Path.ValueString(), data.Name.ValueString())
	vaultResp, err := cli.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		resp.Diagnostics.AddError(errReading("Azure Key Vault provider", apiPath, err))
		return
	}

	if vaultResp == nil {
		tflog.Warn(ctx, "Azure Key Vault provider not found, removing from state", map[string]interface{}{
			"path": apiPath,
		})
		resp.State.RemoveResource(ctx)
		return
	}

	// Parse response data
	r.parseAzureKMSResponse(vaultResp.Data, &data)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
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
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	apiPath := buildKMSPath(plan.Path.ValueString(), plan.Name.ValueString())
	writeData := map[string]interface{}{
		"provider": ProviderAzureKV,
	}
	hasChanges := false

	if !plan.KeyCollection.Equal(state.KeyCollection) {
		writeData["key_collection"] = plan.KeyCollection.ValueString()
		hasChanges = true
	}

	credentialsChanged := !plan.TenantID.Equal(state.TenantID) ||
		!plan.ClientID.Equal(state.ClientID) ||
		!plan.ClientSecret.Equal(state.ClientSecret) ||
		!plan.Environment.Equal(state.Environment)

	if credentialsChanged {
		// Re-send all credential fields together under the nested credentials object,
		// consistent with how Create() sends them to the Vault API.
		creds := map[string]interface{}{
			"tenant_id":     plan.TenantID.ValueString(),
			"client_id":     plan.ClientID.ValueString(),
			"client_secret": plan.ClientSecret.ValueString(),
		}
		if !plan.Environment.IsNull() {
			creds["environment"] = plan.Environment.ValueString()
		}
		writeData["credentials"] = creds
		hasChanges = true
	}

	if hasChanges {
		if _, err := cli.Logical().WriteWithContext(ctx, apiPath, writeData); err != nil {
			resp.Diagnostics.AddError(errUpdating("Azure Key Vault provider", apiPath, err))
			return
		}
	}

	// Read back the state from Vault
	vaultResp, err := cli.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		resp.Diagnostics.AddError(errReading("Azure Key Vault provider", apiPath, err))
		return
	}

	if vaultResp == nil {
		resp.Diagnostics.AddError(
			"Unexpected error after updating Azure Key Vault provider",
			fmt.Sprintf("Azure Key Vault provider not found at path %q immediately after update", apiPath),
		)
		return
	}

	// Parse response data
	r.parseAzureKMSResponse(vaultResp.Data, &plan)

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
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	apiPath := buildKMSPath(data.Path.ValueString(), data.Name.ValueString())
	if _, err := cli.Logical().DeleteWithContext(ctx, apiPath); err != nil {
		resp.Diagnostics.AddError(errDeleting("Azure Key Vault provider", apiPath, err))
		return
	}
}

func (r *AzureKMSResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if req.ID == "" {
		resp.Diagnostics.AddError(
			"Empty Import ID",
			"Import ID cannot be empty. Expected format: <mount>/kms/<name>",
		)
		return
	}

	mount, name, err := parseKMSPath(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Unable to parse import ID: %s\n\nExpected format: <mount>/kms/<name>\nExample: keymgmt/kms/my-azure-kms\n\nError: %s", req.ID, err.Error()),
		)
		return
	}

	if mount == "" || name == "" {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Import ID contains empty fields. Expected format: <mount>/kms/<name>\nExample: keymgmt/kms/my-azure-kms\n\nParsed mount: %q, name: %q", mount, name),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldPath), mount)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), name)...)

	if ns := os.Getenv(consts.EnvVarVaultNamespaceImport); ns != "" {
		tflog.Debug(ctx, fmt.Sprintf("Setting namespace from %s: %s", consts.EnvVarVaultNamespaceImport, ns))
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...)
	}
}

// parseAzureKMSResponse parses the Vault API response data into the resource model
func (r *AzureKMSResource) parseAzureKMSResponse(responseData map[string]interface{}, data *AzureKMSResourceModel) {
	if v, ok := responseData["key_collection"].(string); ok {
		data.KeyCollection = types.StringValue(v)
	}
	if v, ok := responseData["tenant_id"].(string); ok {
		data.TenantID = types.StringValue(v)
	}
	if v, ok := responseData["client_id"].(string); ok {
		data.ClientID = types.StringValue(v)
	}
	if v, ok := responseData["environment"].(string); ok {
		data.Environment = types.StringValue(v)
	}
}
