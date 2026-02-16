// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt

import (
	"context"

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

var _ resource.Resource = &AWSKMSResource{}
var _ resource.ResourceWithImportState = &AWSKMSResource{}

type AWSKMSResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

type AWSKMSResourceModel struct {
	base.BaseModelLegacy
	Path          types.String `tfsdk:"path"`
	Name          types.String `tfsdk:"name"`
	KeyCollection types.String `tfsdk:"key_collection"`
	Credentials   types.Map    `tfsdk:"credentials"`
	AccessKey     types.String `tfsdk:"access_key"`
	SecretKey     types.String `tfsdk:"secret_key"`
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
			consts.FieldKeyCollection: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "AWS region where keys are stored (e.g., us-east-1)",
			},
			consts.FieldCredentials: schema.MapAttribute{
				Optional:            true,
				Sensitive:           true,
				ElementType:         types.StringType,
				MarkdownDescription: "Map containing access_key and secret_key for AWS authentication",
			},
			consts.FieldAccessKey: schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "AWS access key ID",
			},
			consts.FieldSecretKey: schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "AWS secret access key",
			},
		},
	}
	base.MustAddLegacyBaseSchema(&resp.Schema)
}

func (r *AWSKMSResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data AWSKMSResourceModel
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
		"provider":       "awskms",
		"key_collection": data.KeyCollection.ValueString(),
	}

	if creds := buildAWSCredentialsMap(ctx, data.Credentials, data.AccessKey, data.SecretKey, &resp.Diagnostics); creds != nil {
		if resp.Diagnostics.HasError() {
			return
		}
		writeData["credentials"] = creds
	}

	if _, err := cli.Logical().WriteWithContext(ctx, apiPath, writeData); err != nil {
		resp.Diagnostics.AddError(errCreating("AWS KMS provider", apiPath, err))
		return
	}

	data.ID = types.StringValue(apiPath)
	r.read(ctx, cli, &data, &resp.Diagnostics)
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

func (r *AWSKMSResource) read(ctx context.Context, cli *api.Client, data *AWSKMSResourceModel, diags *diag.Diagnostics) {
	apiPath := data.ID.ValueString()
	vaultResp, err := cli.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		diags.AddError(errReading("AWS KMS provider", apiPath, err))
		return
	}

	if vaultResp == nil {
		data.ID = types.StringNull()
		return
	}

	mountPath, kmsName, err := parseKMSPath(apiPath)
	if err != nil {
		diags.AddError(errInvalidPathStructure, err.Error())
		return
	}

	data.Path = types.StringValue(mountPath)
	data.Name = types.StringValue(kmsName)

	if v, ok := vaultResp.Data["key_collection"].(string); ok {
		data.KeyCollection = types.StringValue(v)
	}
}

func (r *AWSKMSResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state AWSKMSResourceModel
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
		"provider": ProviderAWSKMS,
	}
	hasChanges := false

	if !plan.KeyCollection.Equal(state.KeyCollection) {
		writeData["key_collection"] = plan.KeyCollection.ValueString()
		hasChanges = true
	}

	if !plan.Credentials.Equal(state.Credentials) || !plan.AccessKey.Equal(state.AccessKey) || !plan.SecretKey.Equal(state.SecretKey) {
		if creds := buildAWSCredentialsMap(ctx, plan.Credentials, plan.AccessKey, plan.SecretKey, &resp.Diagnostics); creds != nil {
			if resp.Diagnostics.HasError() {
				return
			}
			writeData["credentials"] = creds
			hasChanges = true
		}
	}

	if hasChanges {
		if _, err := cli.Logical().WriteWithContext(ctx, apiPath, writeData); err != nil {
			resp.Diagnostics.AddError(errUpdating("AWS KMS provider", apiPath, err))
			return
		}
	}

	r.read(ctx, cli, &plan, &resp.Diagnostics)
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

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	apiPath := data.ID.ValueString()
	if _, err := cli.Logical().DeleteWithContext(ctx, apiPath); err != nil {
		resp.Diagnostics.AddError(errDeleting("AWS KMS provider", apiPath, err))
		return
	}
}
