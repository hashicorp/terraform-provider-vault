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
	"github.com/hashicorp/terraform-provider-vault/util"
)

const fieldTPMEKPublicKey = "tpm_ek_public_key"

var _ resource.ResourceWithImportState = &IdentityTPMResource{}

func NewIdentityTPMResource() resource.Resource {
	return &IdentityTPMResource{}
}

type IdentityTPMResource struct {
	base.ResourceWithConfigure
}

type IdentityTPMModel struct {
	base.BaseModel

	Name           types.String `tfsdk:"name"`
	TPMEKPublicKey types.String `tfsdk:"tpm_ek_public_key"`
	Disabled       types.Bool   `tfsdk:"disabled"`
	TPMID          types.String `tfsdk:"tpm_id"`
}

type identityTPMAPIModel struct {
	Name           string `json:"name" mapstructure:"name"`
	TPMEKPublicKey string `json:"tpm_ek_public_key" mapstructure:"tpm_ek_public_key"`
	Disabled       bool   `json:"disabled" mapstructure:"disabled"`
	TPMID          string `json:"id" mapstructure:"id"`
}

func (r *IdentityTPMResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_identity_tpm"
}

func (r *IdentityTPMResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldName: schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "Name of the TPM record.",
			},
			fieldTPMEKPublicKey: schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "PEM-encoded TPM Endorsement Key (EK) public key.",
			},
			"disabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether the TPM is disabled.",
			},
			"tpm_id": schema.StringAttribute{
				Computed:    true,
				Description: "The unique ID Vault assigns to this TPM record (SHA256 of the EK public key).",
			},
		},
	}

	base.MustAddBaseSchema(&resp.Schema)
}

func (r *IdentityTPMResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data IdentityTPMModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
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

	resourcePath := r.path(&data)
	if _, err := vaultClient.Logical().WriteWithContext(ctx, resourcePath, requestBody); err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
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

func (r *IdentityTPMResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data IdentityTPMModel
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
		tflog.Warn(ctx, "TPM record not found, removing from state")
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(r.populateDataModelFromAPI(ctx, &data, secret)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *IdentityTPMResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data IdentityTPMModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
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

func (r *IdentityTPMResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data IdentityTPMModel
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

func (r *IdentityTPMResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
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

func (r *IdentityTPMResource) path(data *IdentityTPMModel) string {
	return fmt.Sprintf("identity/tpm/name/%s", data.Name.ValueString())
}

func (r *IdentityTPMResource) populateDataModelFromAPI(_ context.Context, data *IdentityTPMModel, resp *api.Secret) diag.Diagnostics {
	if resp == nil || resp.Data == nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Missing data in API response", "The API response or response data was nil."),
		}
	}

	var readResp identityTPMAPIModel
	if err := model.ToAPIModel(resp.Data, &readResp); err != nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Unable to translate Vault response data", err.Error()),
		}
	}

	data.Name = types.StringValue(readResp.Name)
	data.TPMEKPublicKey = types.StringValue(readResp.TPMEKPublicKey)
	data.Disabled = types.BoolValue(readResp.Disabled)
	data.TPMID = types.StringValue(readResp.TPMID)

	return nil
}

func (r *IdentityTPMResource) getAPIModel(ctx context.Context, data *IdentityTPMModel) (map[string]any, diag.Diagnostics) {
	apiModel := identityTPMAPIModel{
		Name:           data.Name.ValueString(),
		TPMEKPublicKey: data.TPMEKPublicKey.ValueString(),
	}

	if !data.Disabled.IsNull() && !data.Disabled.IsUnknown() {
		apiModel.Disabled = data.Disabled.ValueBool()
	}

	var requestBody map[string]any
	if err := mapstructure.Decode(apiModel, &requestBody); err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("Failed to decode TPM API model to map", err.Error()),
		}
	}

	if data.Disabled.IsNull() || data.Disabled.IsUnknown() {
		delete(requestBody, "disabled")
	}

	return requestBody, nil
}
