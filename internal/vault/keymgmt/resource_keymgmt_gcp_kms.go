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

var _ resource.Resource = &GCPKMSResource{}
var _ resource.ResourceWithImportState = &GCPKMSResource{}

type GCPKMSResource struct {
	base.ResourceWithConfigure
}

type GCPKMSResourceModel struct {
	base.BaseModel
	Mount              types.String `tfsdk:"mount"`
	Name               types.String `tfsdk:"name"`
	KeyCollection      types.String `tfsdk:"key_collection"`
	ServiceAccountFile types.String `tfsdk:"service_account_file"`
	Project            types.String `tfsdk:"project"`
	Location           types.String `tfsdk:"location"`
}

func NewGCPKMSResource() resource.Resource {
	return &GCPKMSResource{}
}

func (r *GCPKMSResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_keymgmt_gcp_kms"
}

func (r *GCPKMSResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a GCP Cloud KMS provider for Vault Key Management",

		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Path of the Key Management secrets engine mount. Must match the `path` of a `vault_mount` resource with `type = \"keymgmt\"`. Use `vault_mount.<name>.path` here.",

				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldName: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the GCP Cloud KMS provider",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldKeyCollection: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "GCP Key Ring name where keys are stored",
			},
			consts.FieldServiceAccountFile: schema.StringAttribute{
				Required:            true,
				Sensitive:           true,
				MarkdownDescription: "GCP service account JSON credentials file content",
			},
			consts.FieldProject: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "GCP project ID",
			},
			consts.FieldLocation: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "GCP location/region (e.g., us-central1, global)",
			},
		},
	}
	base.MustAddBaseSchema(&resp.Schema)
}

func (r *GCPKMSResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data GCPKMSResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultPath := data.Mount.ValueString()
	name := data.Name.ValueString()
	apiPath := BuildKMSPath(vaultPath, name)

	writeData := map[string]interface{}{
		"provider":       ProviderGCPCKMS,
		"key_collection": data.KeyCollection.ValueString(),
	}

	// GCP credentials must be sent as a nested credentials object
	creds := make(map[string]string)
	creds["service_account_file"] = data.ServiceAccountFile.ValueString()
	creds["project"] = data.Project.ValueString()
	creds["location"] = data.Location.ValueString()

	writeData["credentials"] = creds

	if _, err := cli.Logical().WriteWithContext(ctx, apiPath, writeData); err != nil {
		resp.Diagnostics.AddError(ErrCreating(ResourceTypeGCPCKMS, apiPath, err))
		return
	}

	// Read back the state from Vault
	vaultResp, err := cli.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		resp.Diagnostics.AddError(ErrReading(ResourceTypeGCPCKMS, apiPath, err))
		return
	}

	if vaultResp == nil {
		resp.Diagnostics.AddError(
			"Unexpected error after creating GCP Cloud KMS provider",
			fmt.Sprintf("GCP Cloud KMS provider not found at path %q immediately after creation", apiPath),
		)
		return
	}

	// Parse response data
	r.parseGCPKMSResponse(vaultResp.Data, &data)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *GCPKMSResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data GCPKMSResourceModel
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
	apiPath := BuildKMSPath(data.Mount.ValueString(), data.Name.ValueString())
	vaultResp, err := cli.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		resp.Diagnostics.AddError(ErrReading(ResourceTypeGCPCKMS, apiPath, err))
		return
	}

	if vaultResp == nil {
		tflog.Warn(ctx, "GCP Cloud KMS provider not found, removing from state", map[string]interface{}{
			"path": apiPath,
		})
		resp.State.RemoveResource(ctx)
		return
	}

	// Parse response data
	r.parseGCPKMSResponse(vaultResp.Data, &data)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *GCPKMSResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state GCPKMSResourceModel
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

	// Build API path from fields
	apiPath := BuildKMSPath(plan.Mount.ValueString(), plan.Name.ValueString())
	writeData := map[string]interface{}{
		"provider": ProviderGCPCKMS,
	}
	hasChanges := false

	if !plan.KeyCollection.Equal(state.KeyCollection) {
		writeData["key_collection"] = plan.KeyCollection.ValueString()
		hasChanges = true
	}

	credentials := map[string]interface{}{}
	credentialsChanged := false

	if !plan.ServiceAccountFile.Equal(state.ServiceAccountFile) {
		credentials["service_account_file"] = plan.ServiceAccountFile.ValueString()
		credentialsChanged = true
	}
	if !plan.Project.Equal(state.Project) {
		credentials["project"] = plan.Project.ValueString()
		credentialsChanged = true
	}
	if !plan.Location.Equal(state.Location) {
		credentials["location"] = plan.Location.ValueString()
		credentialsChanged = true
	}

	if credentialsChanged {
		// Re-send all credential fields together under the nested credentials object
		credentials["service_account_file"] = plan.ServiceAccountFile.ValueString()
		credentials["project"] = plan.Project.ValueString()
		credentials["location"] = plan.Location.ValueString()
		writeData["credentials"] = credentials
		hasChanges = true
	}

	if hasChanges {
		if _, err := cli.Logical().WriteWithContext(ctx, apiPath, writeData); err != nil {
			resp.Diagnostics.AddError(ErrUpdating(ResourceTypeGCPCKMS, apiPath, err))
			return
		}
	}

	// Read back the state from Vault
	vaultResp, err := cli.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		resp.Diagnostics.AddError(ErrReading(ResourceTypeGCPCKMS, apiPath, err))
		return
	}

	if vaultResp == nil {
		resp.Diagnostics.AddError(
			"Unexpected error after updating GCP Cloud KMS provider",
			fmt.Sprintf("GCP Cloud KMS provider not found at path %q immediately after update", apiPath),
		)
		return
	}

	// Parse response data
	r.parseGCPKMSResponse(vaultResp.Data, &plan)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *GCPKMSResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data GCPKMSResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Build API path from fields
	apiPath := BuildKMSPath(data.Mount.ValueString(), data.Name.ValueString())
	if _, err := cli.Logical().DeleteWithContext(ctx, apiPath); err != nil {
		resp.Diagnostics.AddError(ErrDeleting(ResourceTypeGCPCKMS, apiPath, err))
		return
	}
}

func (r *GCPKMSResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Validate import ID is not empty
	if req.ID == "" {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			"Import identifier cannot be empty. Expected format: '<mount_path>/kms/<name>', "+
				"namespace can be specified using the env var "+consts.EnvVarVaultNamespaceImport,
		)
		return
	}

	// Parse the import ID to extract path and name
	mountPath, kmsName, err := ParseKMSPath(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			fmt.Sprintf("The import identifier %q is not valid: %s. Expected format: '<mount_path>/kms/<name>', "+
				"namespace can be specified using the env var %s", req.ID, err.Error(), consts.EnvVarVaultNamespaceImport),
		)
		return
	}

	// Set the individual fields in state
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mountPath)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), kmsName)...)

	// Handle namespace if needed
	ns := os.Getenv(consts.EnvVarVaultNamespaceImport)
	if ns != "" {
		tflog.Info(
			ctx,
			fmt.Sprintf("Environment variable %s set, attempting TF state import", consts.EnvVarVaultNamespaceImport),
			map[string]any{consts.FieldNamespace: ns},
		)
		resp.Diagnostics.Append(
			resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...,
		)
	}
}

// parseGCPKMSResponse parses the Vault API response data into the resource model
func (r *GCPKMSResource) parseGCPKMSResponse(responseData map[string]interface{}, data *GCPKMSResourceModel) {
	if v, ok := responseData["key_collection"].(string); ok {
		data.KeyCollection = types.StringValue(v)
	}
	if v, ok := responseData["project"].(string); ok {
		data.Project = types.StringValue(v)
	}
	if v, ok := responseData["location"].(string); ok {
		data.Location = types.StringValue(v)
	}
}
