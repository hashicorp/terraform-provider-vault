// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

var _ resource.Resource = &ReplicateKeyResource{}
var _ resource.ResourceWithImportState = &ReplicateKeyResource{}

type ReplicateKeyResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

type ReplicateKeyResourceModel struct {
	base.BaseModelLegacy
	Path    types.String `tfsdk:"path"`
	KMSName types.String `tfsdk:"kms_name"`
	KeyName types.String `tfsdk:"key_name"`
}

func NewReplicateKeyResource() resource.Resource {
	return &ReplicateKeyResource{}
}

func (r *ReplicateKeyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_keymgmt_replicate_key"
}

func (r *ReplicateKeyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Replicates a Key Management key to configured regions (AWS KMS only)",

		Attributes: map[string]schema.Attribute{
			consts.FieldPath: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Path where the Key Management secrets engine is mounted",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldKMSName: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the KMS provider",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldKeyName: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the key to replicate",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
	}
	base.MustAddLegacyBaseSchema(&resp.Schema)
}

func (r *ReplicateKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ReplicateKeyResourceModel
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
	kmsName := data.KMSName.ValueString()
	keyName := data.KeyName.ValueString()

	kmsPath := strings.Trim(vaultPath, "/") + "/kms/" + kmsName
	kmsResp, err := cli.Logical().ReadWithContext(ctx, kmsPath)
	if err != nil {
		resp.Diagnostics.AddError("Error reading KMS provider", fmt.Sprintf("Error reading KMS provider at %s: %s", kmsPath, err))
		return
	}

	if kmsResp == nil {
		resp.Diagnostics.AddError("KMS provider not found", fmt.Sprintf("KMS provider %s not found at %s", kmsName, kmsPath))
		return
	}

	kmsProvider := ""
	if v, ok := kmsResp.Data["provider"].(string); ok {
		kmsProvider = v
	}

	if kmsProvider != "awskms" {
		resp.Diagnostics.AddError("Invalid KMS provider", fmt.Sprintf("Key replication is only supported for AWS KMS providers. Current provider: %s", kmsProvider))
		return
	}

	keyPath := strings.Trim(vaultPath, "/") + "/key/" + keyName
	keyResp, err := cli.Logical().ReadWithContext(ctx, keyPath)
	if err != nil {
		resp.Diagnostics.AddError("Error reading Key Management key", fmt.Sprintf("Error reading Key Management key at %s: %s", keyPath, err))
		return
	}

	if keyResp == nil {
		resp.Diagnostics.AddError("Key not found", fmt.Sprintf("Key %s not found at %s", keyName, keyPath))
		return
	}

	hasReplicaRegions := false
	if v, ok := keyResp.Data["replica_regions"].([]interface{}); ok && len(v) > 0 {
		hasReplicaRegions = true
	}

	if !hasReplicaRegions {
		resp.Diagnostics.AddError("No replica regions configured", fmt.Sprintf("Cannot replicate key %s: replica_regions must be configured in vault_keymgmt_key resource before replication", keyName))
		return
	}

	apiPath := buildReplicateKeyPath(vaultPath, kmsName, keyName)
	if _, err := cli.Logical().WriteWithContext(ctx, apiPath, map[string]interface{}{}); err != nil {
		resp.Diagnostics.AddError("Error replicating Key Management key", fmt.Sprintf("Error replicating key at %s: %s", apiPath, err))
		return
	}

	data.ID = types.StringValue(apiPath)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ReplicateKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ReplicateKeyResourceModel
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
	parts := strings.Split(strings.Trim(apiPath, "/"), "/")
	kmsIndex, keyIndex := -1, -1
	for i, part := range parts {
		if part == "kms" {
			kmsIndex = i
		} else if part == "key" && i > kmsIndex {
			keyIndex = i
		}
	}

	if kmsIndex == -1 || keyIndex == -1 || kmsIndex+1 >= len(parts) || keyIndex+1 >= len(parts) {
		resp.Diagnostics.AddError("Invalid path structure", fmt.Sprintf("Invalid replication path structure: %s", apiPath))
		return
	}

	data.Path = types.StringValue(strings.Join(parts[:kmsIndex], "/"))
	data.KMSName = types.StringValue(parts[kmsIndex+1])
	data.KeyName = types.StringValue(parts[keyIndex+1])

	distPath := strings.Join(parts[:len(parts)-1], "/")
	vaultResp, err := cli.Logical().ReadWithContext(ctx, distPath)
	if err != nil {
		resp.Diagnostics.AddError("Error reading Key Management key distribution", fmt.Sprintf("Error reading key distribution at %s: %s", distPath, err))
		return
	}

	if vaultResp == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ReplicateKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update not supported", "Replication resource does not support updates")
}

func (r *ReplicateKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Replication is not a physical resource that can be deleted
	// Removing it from Terraform state is sufficient
}

func buildReplicateKeyPath(mountPath, kmsName, keyName string) string {
	return strings.Trim(mountPath, "/") + "/kms/" + kmsName + "/key/" + keyName + "/replicate"
}
