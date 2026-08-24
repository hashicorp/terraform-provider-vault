// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package identity

import (
	"context"
	"fmt"
	"os"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const fieldMemberTPMIDs = "member_tpm_ids"

var _ resource.ResourceWithImportState = &IdentityTPMGroupResource{}

func NewIdentityTPMGroupResource() resource.Resource {
	return &IdentityTPMGroupResource{}
}

type IdentityTPMGroupResource struct {
	base.ResourceWithConfigure
}

type IdentityTPMGroupModel struct {
	base.BaseModel

	Name         types.String `tfsdk:"name"`
	MemberTPMIDs types.Set    `tfsdk:"member_tpm_ids"`
	Metadata     types.Map    `tfsdk:"metadata"`
	TPMGroupID   types.String `tfsdk:"tpm_group_id"`
}

type identityTPMGroupAPIModel struct {
	Name         string            `json:"name" mapstructure:"name"`
	MemberTPMIDs []string          `json:"member_tpm_ids" mapstructure:"member_tpm_ids"`
	Metadata     map[string]string `json:"metadata" mapstructure:"metadata"`
	TPMGroupID   string            `json:"id" mapstructure:"id"`
}

func (r *IdentityTPMGroupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_identity_tpm_group"
}

func (r *IdentityTPMGroupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldName: schema.StringAttribute{
				Required:    true,
				Description: "Name of the TPM group.",
			},
			fieldMemberTPMIDs: schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Set of TPM IDs that are members of this TPM group.",
			},
			consts.FieldMetadata: schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Metadata to associate with the TPM group.",
			},
			"tpm_group_id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "The unique ID Vault assigns to this TPM group.",
			},
		},
	}

	base.MustAddBaseSchema(&resp.Schema)
}

func (r *IdentityTPMGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data IdentityTPMGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check if Vault version supports TMP auth (requires 2.2.0+)
	if !r.Meta().IsAPISupported(provider.VaultVersion220) {
		resp.Diagnostics.AddError(
			"Feature Not Supported",
			fmt.Sprintf("TPM group requires Vault version %s or later. Current Vault version: %s", provider.VaultVersion220, r.Meta().GetVaultVersion().String()),
		)
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	requestBody, diags := r.getAPIModel(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create uses the collection path with name in the body; read/update/delete use /name/{name}.
	if _, err := vaultClient.Logical().WriteWithContext(ctx, "identity/tpmgroup", requestBody); err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	secret, err := vaultClient.Logical().ReadWithContext(ctx, r.path(&data))
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if secret == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	resp.Diagnostics.Append(r.populateDataModelFromAPI(ctx, &data, secret)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *IdentityTPMGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data IdentityTPMGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	secret, err := vaultClient.Logical().ReadWithContext(ctx, r.path(&data))
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if secret == nil {
		tflog.Warn(ctx, "TPM group not found, removing from state")
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(r.populateDataModelFromAPI(ctx, &data, secret)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *IdentityTPMGroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data IdentityTPMGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var stateData IdentityTPMGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &stateData)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if data.TPMGroupID.IsNull() || data.TPMGroupID.IsUnknown() {
		data.TPMGroupID = stateData.TPMGroupID
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	requestBody, diags := r.getAPIModel(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resourcePath := r.path(&data)
	if _, err := vaultClient.Logical().WriteWithContext(ctx, resourcePath, requestBody); err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}

	secret, err := vaultClient.Logical().ReadWithContext(ctx, resourcePath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if secret == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	resp.Diagnostics.Append(r.populateDataModelFromAPI(ctx, &data, secret)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *IdentityTPMGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data IdentityTPMGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	if _, err := vaultClient.Logical().DeleteWithContext(ctx, r.path(&data)); err != nil {
		if util.Is404(err) {
			return
		}
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
	}
}

func (r *IdentityTPMGroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	name := req.ID
	if name == "" {
		resp.Diagnostics.AddError("Invalid import identifier", "import identifier cannot be empty")
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), name)...)

	ns := os.Getenv(consts.EnvVarVaultNamespaceImport)
	if ns != "" {
		tflog.Info(
			ctx,
			fmt.Sprintf("Environment variable %s set, attempting TF state import", consts.EnvVarVaultNamespaceImport),
			map[string]any{consts.FieldNamespace: ns},
		)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...)
	}
}

func (r *IdentityTPMGroupResource) path(data *IdentityTPMGroupModel) string {
	if !data.TPMGroupID.IsNull() && !data.TPMGroupID.IsUnknown() && data.TPMGroupID.ValueString() != "" {
		return fmt.Sprintf("identity/tpmgroup/id/%s", data.TPMGroupID.ValueString())
	}
	return fmt.Sprintf("identity/tpmgroup/name/%s", data.Name.ValueString())
}

func (r *IdentityTPMGroupResource) getAPIModel(ctx context.Context, data *IdentityTPMGroupModel) (map[string]any, diag.Diagnostics) {
	apiModel := identityTPMGroupAPIModel{
		Name: data.Name.ValueString(),
	}

	var memberTPMIDs []string
	if diags := data.MemberTPMIDs.ElementsAs(ctx, &memberTPMIDs, false); diags.HasError() {
		return nil, diags
	}
	apiModel.MemberTPMIDs = memberTPMIDs
	if !data.Metadata.IsNull() && !data.Metadata.IsUnknown() {
		var metadata map[string]string
		if diags := data.Metadata.ElementsAs(ctx, &metadata, false); diags.HasError() {
			return nil, diags
		}
		apiModel.Metadata = metadata
	}

	var requestBody map[string]any
	if err := mapstructure.Decode(apiModel, &requestBody); err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("Failed to decode TPM group API model to map", err.Error()),
		}
	}

	if len(memberTPMIDs) == 0 {
		delete(requestBody, fieldMemberTPMIDs)
	}
	if data.Metadata.IsNull() || data.Metadata.IsUnknown() {
		delete(requestBody, consts.FieldMetadata)
	}

	return requestBody, nil
}

func (r *IdentityTPMGroupResource) populateDataModelFromAPI(ctx context.Context, data *IdentityTPMGroupModel, resp *api.Secret) diag.Diagnostics {
	if resp == nil || resp.Data == nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Missing data in API response", "The API response or response data was nil."),
		}
	}

	var readResp identityTPMGroupAPIModel
	if err := model.ToAPIModel(resp.Data, &readResp); err != nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Unable to translate Vault response data", err.Error()),
		}
	}

	data.Name = types.StringValue(readResp.Name)
	data.TPMGroupID = types.StringValue(readResp.TPMGroupID)

	if len(readResp.MemberTPMIDs) == 0 {
		data.MemberTPMIDs = types.SetNull(types.StringType)
	} else {
		memberTPMIDs, diags := types.SetValueFrom(ctx, types.StringType, readResp.MemberTPMIDs)
		if diags.HasError() {
			return diags
		}
		data.MemberTPMIDs = memberTPMIDs
	}
	if len(readResp.Metadata) == 0 {
		data.Metadata = types.MapNull(types.StringType)
	} else {
		metadata, diags := types.MapValueFrom(ctx, types.StringType, readResp.Metadata)
		if diags.HasError() {
			return diags
		}
		data.Metadata = metadata
	}

	return nil
}
