// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package tpm

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
)

var tpmBackendConfigRegexp = regexp.MustCompile(`^auth/(.+)/config$`)

var _ resource.ResourceWithImportState = &TPMAuthBackendConfigResource{}

func NewTPMAuthBackendConfigResource() resource.Resource {
	return &TPMAuthBackendConfigResource{}
}

type TPMAuthBackendConfigResource struct {
	base.ResourceWithConfigure
}

type TPMAuthBackendConfigModel struct {
	base.BaseModel

	Mount   types.String `tfsdk:"mount"`
	CertTTL types.String `tfsdk:"cert_ttl"`
}

type tpmAuthBackendConfigAPIModel struct {
	CertTTL string `json:"cert_ttl" mapstructure:"cert_ttl"`
}

func (r *TPMAuthBackendConfigResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tpm_auth_backend_config"
}

func (r *TPMAuthBackendConfigResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				Required:    true,
				Description: "Path of the enabled TPM auth backend mount to configure.",
			},
			consts.FieldCertTTL: schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Certificate TTL for the TPM auth backend.",
			},
		},
	}

	base.MustAddBaseSchema(&resp.Schema)
}

func (r *TPMAuthBackendConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data TPMAuthBackendConfigModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	requestBody, diags := r.getAPIModel(&data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	configPath := r.path(&data)
	configResp, err := vaultClient.Logical().WriteWithContext(ctx, configPath, requestBody)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}
	if configResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	resp.Diagnostics.Append(r.populateDataModelFromAPI(ctx, &data, configResp)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *TPMAuthBackendConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data TPMAuthBackendConfigModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	configResp, err := vaultClient.Logical().ReadWithContext(ctx, r.path(&data))
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if configResp == nil {
		tflog.Warn(ctx, "TPM auth backend config not found, removing from state")
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(r.populateDataModelFromAPI(ctx, &data, configResp)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *TPMAuthBackendConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data TPMAuthBackendConfigModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	requestBody, diags := r.getAPIModel(&data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	configPath := r.path(&data)
	configResp, err := vaultClient.Logical().WriteWithContext(ctx, configPath, requestBody)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}
	if configResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	resp.Diagnostics.Append(r.populateDataModelFromAPI(ctx, &data, configResp)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *TPMAuthBackendConfigResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {
	// API does not support delete, so just remove from state.
}

func (r *TPMAuthBackendConfigResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	mount, err := extractTPMAuthBackendConfigMount(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import identifier", fmt.Sprintf("Expected format: auth/<mount>/config. Got: %q. Error: %s", req.ID, err))
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mount)...)

	ns := os.Getenv(consts.EnvVarVaultNamespaceImport)
	if ns != "" {
		tflog.Info(ctx,
			fmt.Sprintf("Environment variable %s set, attempting TF state import", consts.EnvVarVaultNamespaceImport),
			map[string]any{consts.FieldNamespace: ns},
		)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...)
	}
}

func extractTPMAuthBackendConfigMount(importID string) (string, error) {
	importID = strings.Trim(importID, "/")
	if importID == "" {
		return "", fmt.Errorf("import identifier cannot be empty")
	}

	matches := tpmBackendConfigRegexp.FindStringSubmatch("auth/" + strings.TrimPrefix(importID, "auth/"))
	if len(matches) != 2 {
		return "", fmt.Errorf("must be of the form auth/<mount>/config")
	}

	return matches[1], nil
}

func (r *TPMAuthBackendConfigResource) path(data *TPMAuthBackendConfigModel) string {
	return fmt.Sprintf("auth/%s/config", strings.Trim(data.Mount.ValueString(), "/"))
}

func (r *TPMAuthBackendConfigResource) getAPIModel(data *TPMAuthBackendConfigModel) (map[string]any, diag.Diagnostics) {
	apiModel := tpmAuthBackendConfigAPIModel{CertTTL: data.CertTTL.ValueString()}

	var requestBody map[string]any
	if err := mapstructure.Decode(apiModel, &requestBody); err != nil {
		return nil, diag.Diagnostics{diag.NewErrorDiagnostic("Failed to decode TPM auth backend config API model to map", err.Error())}
	}

	if data.CertTTL.IsNull() || data.CertTTL.IsUnknown() || data.CertTTL.ValueString() == "" {
		delete(requestBody, consts.FieldCertTTL)
	}

	return requestBody, nil
}

func (r *TPMAuthBackendConfigResource) populateDataModelFromAPI(ctx context.Context, data *TPMAuthBackendConfigModel, resp *api.Secret) diag.Diagnostics {
	if resp == nil || resp.Data == nil {
		return diag.Diagnostics{diag.NewErrorDiagnostic("Missing data in API response", "The API response or response data was nil.")}
	}

	var readResp tpmAuthBackendConfigAPIModel
	if err := model.ToAPIModel(resp.Data, &readResp); err != nil {
		return diag.Diagnostics{diag.NewErrorDiagnostic("Unable to translate Vault response data", err.Error())}
	}

	if readResp.CertTTL == "" {
		if data.CertTTL.IsNull() || data.CertTTL.IsUnknown() {
			data.CertTTL = types.StringNull()
		}
	} else {
		data.CertTTL = types.StringValue(readResp.CertTTL)
	}

	return nil
}
