// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

var _ resource.Resource = &AWSKMSResource{}
var _ resource.ResourceWithImportState = &AWSKMSResource{}

type AWSKMSResource struct {
	client *api.Client
}

type AWSKMSResourceModel struct {
	ID            types.String `tfsdk:"id"`
	Path          types.String `tfsdk:"path"`
	Name          types.String `tfsdk:"name"`
	KeyCollection types.String `tfsdk:"key_collection"`
	Credentials   types.Map    `tfsdk:"credentials"`
	AccessKey     types.String `tfsdk:"access_key"`
	SecretKey     types.String `tfsdk:"secret_key"`
	Region        types.String `tfsdk:"region"`
	UUID          types.String `tfsdk:"uuid"`
}

func NewAWSKMSResource() resource.Resource {
	return &AWSKMSResource{}
}

func (r *AWSKMSResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_keymgmt_aws_kms"
}

func (r *AWSKMSResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an AWS KMS provider for Vault Key Management",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldPath: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Path where the Key Management secrets engine is mounted",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldName: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the AWS KMS provider",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"key_collection": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "AWS region where keys are stored (e.g., us-east-1)",
			},
			"credentials": schema.MapAttribute{
				Optional:            true,
				Sensitive:           true,
				ElementType:         types.StringType,
				MarkdownDescription: "Map containing access_key and secret_key for AWS authentication",
			},
			"access_key": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "AWS access key ID",
			},
			"secret_key": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "AWS secret access key",
			},
			"region": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "AWS region (alternative to key_collection)",
			},
			"uuid": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "UUID of the KMS provider",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *AWSKMSResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	providerMeta, ok := req.ProviderData.(interface{ Meta() interface{} })
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type", fmt.Sprintf("Expected provider metadata interface, got: %T", req.ProviderData))
		return
	}

	meta := providerMeta.Meta()
	client, ok := meta.(*api.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Meta Type", fmt.Sprintf("Expected *api.Client, got: %T", meta))
		return
	}

	r.client = client
}

func (r *AWSKMSResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data AWSKMSResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultPath := data.Path.ValueString()
	name := data.Name.ValueString()
	apiPath := buildKMSPath(vaultPath, name)

	writeData := map[string]interface{}{
		"provider":       "awskms",
		"key_collection": data.KeyCollection.ValueString(),
	}

	if !data.Credentials.IsNull() {
		var creds map[string]string
		resp.Diagnostics.Append(data.Credentials.ElementsAs(ctx, &creds, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		writeData["credentials"] = creds
	} else {
		// Use individual access_key and secret_key if provided
		creds := make(map[string]string)
		if !data.AccessKey.IsNull() {
			creds["access_key"] = data.AccessKey.ValueString()
		}
		if !data.SecretKey.IsNull() {
			creds["secret_key"] = data.SecretKey.ValueString()
		}
		if len(creds) > 0 {
			writeData["credentials"] = creds
		}
	}

	if !data.Region.IsNull() {
		writeData["region"] = data.Region.ValueString()
	}

	if _, err := r.client.Logical().Write(apiPath, writeData); err != nil {
		resp.Diagnostics.AddError("Error creating AWS KMS provider", fmt.Sprintf("Error creating AWS KMS provider at %s: %s", apiPath, err))
		return
	}

	data.ID = types.StringValue(apiPath)
	r.read(ctx, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AWSKMSResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data AWSKMSResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.read(ctx, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.ID.IsNull() {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AWSKMSResource) read(ctx context.Context, data *AWSKMSResourceModel, diags *diag.Diagnostics) {
	apiPath := data.ID.ValueString()
	vaultResp, err := r.client.Logical().Read(apiPath)
	if err != nil {
		diags.AddError("Error reading AWS KMS provider", fmt.Sprintf("Error reading AWS KMS provider at %s: %s", apiPath, err))
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
	if v, ok := vaultResp.Data["region"].(string); ok {
		data.Region = types.StringValue(v)
	}
}

func (r *AWSKMSResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state AWSKMSResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPath := plan.ID.ValueString()
	writeData := map[string]interface{}{
		"provider": "awskms",
	}
	hasChanges := false

	if !plan.KeyCollection.Equal(state.KeyCollection) {
		writeData["key_collection"] = plan.KeyCollection.ValueString()
		hasChanges = true
	}

	if !plan.Credentials.Equal(state.Credentials) {
		var creds map[string]string
		resp.Diagnostics.Append(plan.Credentials.ElementsAs(ctx, &creds, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		writeData["credentials"] = creds
		hasChanges = true
	} else if !plan.AccessKey.Equal(state.AccessKey) || !plan.SecretKey.Equal(state.SecretKey) {
		creds := make(map[string]string)
		if !plan.AccessKey.IsNull() {
			creds["access_key"] = plan.AccessKey.ValueString()
		}
		if !plan.SecretKey.IsNull() {
			creds["secret_key"] = plan.SecretKey.ValueString()
		}
		if len(creds) > 0 {
			writeData["credentials"] = creds
			hasChanges = true
		}
	}

	if !plan.Region.Equal(state.Region) {
		writeData["region"] = plan.Region.ValueString()
		hasChanges = true
	}

	if hasChanges {
		if _, err := r.client.Logical().Write(apiPath, writeData); err != nil {
			resp.Diagnostics.AddError("Error updating AWS KMS provider", fmt.Sprintf("Error updating AWS KMS provider at %s: %s", apiPath, err))
			return
		}
	}

	r.read(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *AWSKMSResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data AWSKMSResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiPath := data.ID.ValueString()
	if _, err := r.client.Logical().Delete(apiPath); err != nil {
		resp.Diagnostics.AddError("Error deleting AWS KMS provider", fmt.Sprintf("Error deleting AWS KMS provider at %s: %s", apiPath, err))
		return
	}
}

func (r *AWSKMSResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
