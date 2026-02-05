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
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

var _ resource.Resource = &GCPKMSResource{}
var _ resource.ResourceWithImportState = &GCPKMSResource{}

type GCPKMSResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

type GCPKMSResourceModel struct {
	base.BaseModelLegacy
	Path               types.String `tfsdk:"path"`
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
			consts.FieldPath: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Path where the Key Management secrets engine is mounted",
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
	base.MustAddLegacyBaseSchema(&resp.Schema)
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

	vaultPath := data.Path.ValueString()
	name := data.Name.ValueString()
	apiPath := buildKMSPath(vaultPath, name)

	writeData := map[string]interface{}{
		"provider":             "gcpckms",
		"key_collection":       data.KeyCollection.ValueString(),
		"service_account_file": data.ServiceAccountFile.ValueString(),
		"project":              data.Project.ValueString(),
		"location":             data.Location.ValueString(),
	}

	if _, err := cli.Logical().WriteWithContext(ctx, apiPath, writeData); err != nil {
		resp.Diagnostics.AddError("Error creating GCP Cloud KMS provider", fmt.Sprintf("Error creating GCP Cloud KMS provider at %s: %s", apiPath, err))
		return
	}

	data.ID = types.StringValue(apiPath)
	r.read(ctx, cli, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

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

func (r *GCPKMSResource) read(ctx context.Context, cli *api.Client, data *GCPKMSResourceModel, diags *diag.Diagnostics) {
	apiPath := data.ID.ValueString()
	vaultResp, err := cli.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		diags.AddError("Error reading GCP Cloud KMS provider", fmt.Sprintf("Error reading GCP Cloud KMS provider at %s: %s", apiPath, err))
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
	if v, ok := vaultResp.Data["project"].(string); ok {
		data.Project = types.StringValue(v)
	}
	if v, ok := vaultResp.Data["location"].(string); ok {
		data.Location = types.StringValue(v)
	}
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

	apiPath := plan.ID.ValueString()
	writeData := map[string]interface{}{
		"provider": "gcpckms",
	}
	hasChanges := false

	if !plan.KeyCollection.Equal(state.KeyCollection) {
		writeData["key_collection"] = plan.KeyCollection.ValueString()
		hasChanges = true
	}
	if !plan.ServiceAccountFile.Equal(state.ServiceAccountFile) {
		writeData["service_account_file"] = plan.ServiceAccountFile.ValueString()
		hasChanges = true
	}
	if !plan.Project.Equal(state.Project) {
		writeData["project"] = plan.Project.ValueString()
		hasChanges = true
	}
	if !plan.Location.Equal(state.Location) {
		writeData["location"] = plan.Location.ValueString()
		hasChanges = true
	}

	if hasChanges {
		if _, err := cli.Logical().WriteWithContext(ctx, apiPath, writeData); err != nil {
			resp.Diagnostics.AddError("Error updating GCP Cloud KMS provider", fmt.Sprintf("Error updating GCP Cloud KMS provider at %s: %s", apiPath, err))
			return
		}
	}

	r.read(ctx, cli, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

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

	apiPath := data.ID.ValueString()
	if _, err := cli.Logical().DeleteWithContext(ctx, apiPath); err != nil {
		resp.Diagnostics.AddError("Error deleting GCP Cloud KMS provider", fmt.Sprintf("Error deleting GCP Cloud KMS provider at %s: %s", apiPath, err))
		return
	}
}
