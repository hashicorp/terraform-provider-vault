// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	vaultapi "github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var _ resource.Resource = &ReplicateKeyResource{}
var _ resource.ResourceWithImportState = &ReplicateKeyResource{}

type ReplicateKeyResource struct {
	base.ResourceWithConfigure
}

type ReplicateKeyResourceModel struct {
	base.BaseModel
	Mount   types.String `tfsdk:"mount"`
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
			consts.FieldMount: schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Path of the Key Management secrets engine mount. Must match the `path` of a `vault_mount` " +
					"resource with `type = \"keymgmt\"`. Use `vault_mount.keymgmt.path` here.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldKMSName: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Specifies the name of the AWS KMS provider.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldKeyName: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Specifies the name of the key to replicate.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
	}
	base.MustAddBaseSchema(&resp.Schema)
}

func (r *ReplicateKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ReplicateKeyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	kmsPath := data.KMSPath()

	// Check Vault version
	if err := checkVaultVersion(r.Meta()); err != nil {
		resp.Diagnostics.AddError(ErrReading(ResourceTypeKMSProvider, kmsPath, err))
		return
	}

	cli, ok := r.getVaultClient(ctx, data.Namespace.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}

	kmsResp, err := cli.Logical().ReadWithContext(ctx, kmsPath)
	if err != nil {
		resp.Diagnostics.AddError(ErrReading(ResourceTypeKMSProvider, kmsPath, err))
		return
	}

	if kmsResp == nil {
		resp.Diagnostics.AddError("KMS provider not found", fmt.Sprintf("KMS provider %s not found at %s", data.KMSName.ValueString(), kmsPath))
		return
	}

	kmsProvider := ""
	if v, ok := kmsResp.Data[consts.FieldProvider].(string); ok {
		kmsProvider = v
	}

	if kmsProvider != ProviderAWSKMS {
		resp.Diagnostics.AddError("Invalid KMS provider", fmt.Sprintf("Key replication is only supported for AWS KMS providers. Current provider: %s", kmsProvider))
		return
	}

	replicatePath := data.ReplicatePath()
	if _, err := cli.Logical().WriteWithContext(ctx, replicatePath, map[string]interface{}{}); err != nil {
		resp.Diagnostics.AddError("Error replicating Key Management key", fmt.Sprintf("Error replicating key at %s: %s", replicatePath, err))
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ReplicateKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ReplicateKeyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, ok := r.getVaultClient(ctx, data.Namespace.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}

	// Build base path to check if distribution exists
	basePath := data.DistributePath()
	vaultResp, err := cli.Logical().ReadWithContext(ctx, basePath)
	if err != nil {
		resp.Diagnostics.AddError(ErrReading(ResourceTypeKeyDistribution, basePath, err))
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

func (r *ReplicateKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Validate import ID is not empty
	if req.ID == "" {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			"Import identifier cannot be empty. Expected format: '<mount_path>/kms/<kms_name>/key/<key_name>/replicate', "+
				"namespace can be specified using the env var "+consts.EnvVarVaultNamespaceImport,
		)
		return
	}

	// Parse the import ID - expect format: <mount_path>/kms/<kms_name>/key/<key_name>/replicate
	importID := req.ID
	// Ensure the path ends with "replicate"
	parts := strings.Split(strings.Trim(importID, "/"), "/")
	if len(parts) == 0 || parts[len(parts)-1] != "replicate" {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			fmt.Sprintf("The import identifier %q must end with /replicate. Expected format: '<mount_path>/kms/<kms_name>/key/<key_name>/replicate', "+
				"namespace can be specified using the env var %s", importID, consts.EnvVarVaultNamespaceImport),
		)
		return
	}

	// Remove the "replicate" suffix to parse the base path
	parts = parts[:len(parts)-1]
	basePath := strings.Join(parts, "/")
	mountPath, kmsName, keyName, err := ParseDistributeKeyPath(basePath)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			fmt.Sprintf("The import identifier %q is not valid: %s. Expected format: '<mount_path>/kms/<kms_name>/key/<key_name>/replicate', "+
				"namespace can be specified using the env var %s", importID, err.Error(), consts.EnvVarVaultNamespaceImport),
		)
		return
	}

	// Set the individual fields in state
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mountPath)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldKMSName), kmsName)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldKeyName), keyName)...)

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

// KMSPath returns the Vault API path for the KMS provider.
func (m *ReplicateKeyResourceModel) KMSPath() string {
	return BuildKMSPath(m.Mount.ValueString(), m.KMSName.ValueString())
}

// ReplicatePath returns the Vault API path for key replication.
func (m *ReplicateKeyResourceModel) ReplicatePath() string {
	return BuildReplicateKeyPath(m.Mount.ValueString(), m.KMSName.ValueString(), m.KeyName.ValueString())
}

// DistributePath returns the Vault API path for the key distribution (used to verify replication exists).
func (m *ReplicateKeyResourceModel) DistributePath() string {
	return BuildDistributeKeyPath(m.Mount.ValueString(), m.KMSName.ValueString(), m.KeyName.ValueString())
}

// getVaultClient returns a Vault client for the given namespace, adding a diagnostic on error.
func (r *ReplicateKeyResource) getVaultClient(ctx context.Context, namespace string, diags *diag.Diagnostics) (*vaultapi.Client, bool) {
	cli, err := client.GetClient(ctx, r.Meta(), namespace)
	if err != nil {
		diags.AddError(errutil.ClientConfigureErr(err))
		return nil, false
	}
	return cli, true
}

func checkVaultVersion(meta *provider.ProviderMeta) error {
	minVersion := provider.VaultVersion200
	currentVersion := meta.GetVaultVersion()

	if !meta.IsAPISupported(minVersion) {
		return fmt.Errorf("Key replication requires Vault %s or higher; current version: %s",
			minVersion, currentVersion)
	}

	return nil
}
