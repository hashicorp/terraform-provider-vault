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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

var _ resource.Resource = &AWSKMSResource{}
var _ resource.ResourceWithImportState = &AWSKMSResource{}

type AWSKMSResource struct {
	base.ResourceWithConfigure
}

type AWSKMSResourceModel struct {
	base.BaseModel
	Mount                types.String `tfsdk:"mount"`
	Name                 types.String `tfsdk:"name"`
	KeyCollection        types.String `tfsdk:"key_collection"`
	CredentialsWO        types.Map    `tfsdk:"credentials_wo"`
	CredentialsWOVersion types.Int64  `tfsdk:"credentials_wo_version"`
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
			consts.FieldMount: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Path of the Key Management secrets engine mount. Must match the `path` of a [`vault_mount`](mount.html) resource with `type = \"keymgmt\"`. Use `vault_mount.<name>.path` here.",
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
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldCredentialsWO: schema.MapAttribute{
				Optional:            true,
				Sensitive:           true,
				WriteOnly:           true,
				ElementType:         types.StringType,
				MarkdownDescription: "Map of AWS credentials passed directly to the Vault API (e.g., `access_key`, `secret_key`). This field is write-only and will not be stored in state. If not provided, Vault uses the AWS SDK credential chain.",
			},
			consts.FieldCredentialsWOVersion: schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "Version counter for the write-only `credentials` field. Increment this value whenever you update `credentials` to trigger the change.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
		},
	}
	base.MustAddBaseSchema(&resp.Schema)
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

	vaultPath := data.Mount.ValueString()
	name := data.Name.ValueString()
	apiPath := BuildKMSPath(vaultPath, name)

	writeData := map[string]interface{}{
		"provider":       ProviderAWSKMS,
		"key_collection": data.KeyCollection.ValueString(),
	}

	// Read write-only credentials from Config (the only place write-only values are accessible)
	var configModel AWSKMSResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &configModel)...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.CredentialsWO = configModel.CredentialsWO

	if !data.CredentialsWO.IsNull() && !data.CredentialsWO.IsUnknown() {
		var creds map[string]string
		resp.Diagnostics.Append(data.CredentialsWO.ElementsAs(ctx, &creds, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		writeData["credentials"] = creds
	}

	if _, err := cli.Logical().WriteWithContext(ctx, apiPath, writeData); err != nil {
		resp.Diagnostics.AddError(ErrCreating(ResourceTypeAWSKMS, apiPath, err))
		return
	}

	// Read back the state from Vault
	vaultResp, err := cli.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		resp.Diagnostics.AddError(ErrReading(ResourceTypeAWSKMS, apiPath, err))
		return
	}

	if vaultResp == nil {
		resp.Diagnostics.AddError(
			"Unexpected error after creating AWS KMS provider",
			fmt.Sprintf("AWS KMS provider not found at path %q immediately after creation", apiPath),
		)
		return
	}

	// Parse response data
	r.parseAWSKMSResponse(vaultResp.Data, &data)

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

	// Build API path and read from Vault
	apiPath := BuildKMSPath(data.Mount.ValueString(), data.Name.ValueString())
	vaultResp, err := cli.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		resp.Diagnostics.AddError(ErrReading(ResourceTypeAWSKMS, apiPath, err))
		return
	}

	if vaultResp == nil {
		tflog.Warn(ctx, "AWS KMS provider not found, removing from state", map[string]interface{}{
			"path": apiPath,
		})
		resp.State.RemoveResource(ctx)
		return
	}

	// Parse response data
	r.parseAWSKMSResponse(vaultResp.Data, &data)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
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

	apiPath := BuildKMSPath(plan.Mount.ValueString(), plan.Name.ValueString())
	writeData := map[string]interface{}{
		"provider": ProviderAWSKMS,
	}
	hasChanges := false

	if !plan.CredentialsWOVersion.Equal(state.CredentialsWOVersion) {
		// Read write-only credentials from Config (the only place write-only values are accessible)
		var configModel AWSKMSResourceModel
		resp.Diagnostics.Append(req.Config.Get(ctx, &configModel)...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.CredentialsWO = configModel.CredentialsWO

		if !plan.CredentialsWO.IsNull() && !plan.CredentialsWO.IsUnknown() {
			var creds map[string]string
			resp.Diagnostics.Append(plan.CredentialsWO.ElementsAs(ctx, &creds, false)...)
			if resp.Diagnostics.HasError() {
				return
			}
			writeData["credentials"] = creds
		}
		hasChanges = true
	}

	if hasChanges {
		if _, err := cli.Logical().WriteWithContext(ctx, apiPath, writeData); err != nil {
			resp.Diagnostics.AddError(ErrUpdating(ResourceTypeAWSKMS, apiPath, err))
			return
		}
	}

	// Read back the state from Vault
	vaultResp, err := cli.Logical().ReadWithContext(ctx, apiPath)
	if err != nil {
		resp.Diagnostics.AddError(ErrReading(ResourceTypeAWSKMS, apiPath, err))
		return
	}

	if vaultResp == nil {
		resp.Diagnostics.AddError(
			"Unexpected error after updating AWS KMS provider",
			fmt.Sprintf("AWS KMS provider not found at path %q immediately after update", apiPath),
		)
		return
	}

	// Parse response data
	r.parseAWSKMSResponse(vaultResp.Data, &plan)

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

	apiPath := BuildKMSPath(data.Mount.ValueString(), data.Name.ValueString())
	if _, err := cli.Logical().DeleteWithContext(ctx, apiPath); err != nil {
		resp.Diagnostics.AddError(ErrDeleting(ResourceTypeAWSKMS, apiPath, err))
		return
	}
}

func (r *AWSKMSResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if req.ID == "" {
		resp.Diagnostics.AddError(
			"Empty Import ID",
			"Import ID cannot be empty. Expected format: <mount>/kms/<name>",
		)
		return
	}

	mount, name, err := ParseKMSPath(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Unable to parse import ID: %s\n\nExpected format: <mount>/kms/<name>\nExample: keymgmt/kms/my-aws-kms\n\nError: %s", req.ID, err.Error()),
		)
		return
	}

	if mount == "" || name == "" {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Import ID contains empty fields. Expected format: <mount>/kms/<name>\nExample: keymgmt/kms/my-aws-kms\n\nParsed mount: %q, name: %q", mount, name),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mount)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), name)...)

	if ns := os.Getenv(consts.EnvVarVaultNamespaceImport); ns != "" {
		tflog.Debug(ctx, fmt.Sprintf("Setting namespace from %s: %s", consts.EnvVarVaultNamespaceImport, ns))
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...)
	}
}

func (r *AWSKMSResource) parseAWSKMSResponse(responseData map[string]interface{}, data *AWSKMSResourceModel) {
	if v, ok := responseData["key_collection"].(string); ok {
		data.KeyCollection = types.StringValue(v)
	}
}
