// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package tpm

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

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
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
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

	Mount          types.String `tfsdk:"mount"`
	CALifetime     types.String `tfsdk:"ca_lifetime"`
	CASoftExpiry   types.String `tfsdk:"ca_soft_expiry"`
	DefaultCertTTL types.String `tfsdk:"default_cert_ttl"`
}

type tpmAuthBackendConfigAPIModel struct {
	CALifetime     string `json:"ca_lifetime" mapstructure:"ca_lifetime"`
	CASoftExpiry   string `json:"ca_soft_expiry" mapstructure:"ca_soft_expiry"`
	DefaultCertTTL string `json:"default_cert_ttl" mapstructure:"default_cert_ttl"`
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
			consts.FieldCALifetime: schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "How long each CA is valid once it becomes active.",
			},
			consts.FieldCASoftExpiry: schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "How long before hard expiry the active CA stops signing new certificates.",
			},
			consts.FieldDefaultCertTTL: schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Default lifetime for issued client certificates.",
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

	// Check if Vault version supports TPM auth (requires 2.2.0+)
	if !r.Meta().IsAPISupported(provider.VaultVersion220) {
		resp.Diagnostics.AddError(
			"Feature Not Supported",
			fmt.Sprintf("TPM auth backend requires Vault version %s or later. Current Vault version: %s", provider.VaultVersion220, r.Meta().GetVaultVersion().String()),
		)
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
	apiModel := tpmAuthBackendConfigAPIModel{
		CALifetime:     data.CALifetime.ValueString(),
		CASoftExpiry:   data.CASoftExpiry.ValueString(),
		DefaultCertTTL: data.DefaultCertTTL.ValueString(),
	}

	var requestBody map[string]any
	if err := mapstructure.Decode(apiModel, &requestBody); err != nil {
		return nil, diag.Diagnostics{diag.NewErrorDiagnostic("Failed to decode TPM auth backend config API model to map", err.Error())}
	}

	if data.CALifetime.IsNull() || data.CALifetime.IsUnknown() || data.CALifetime.ValueString() == "" {
		delete(requestBody, consts.FieldCALifetime)
	}
	if data.CASoftExpiry.IsNull() || data.CASoftExpiry.IsUnknown() || data.CASoftExpiry.ValueString() == "" {
		delete(requestBody, consts.FieldCASoftExpiry)
	}
	if data.DefaultCertTTL.IsNull() || data.DefaultCertTTL.IsUnknown() || data.DefaultCertTTL.ValueString() == "" {
		delete(requestBody, consts.FieldDefaultCertTTL)
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

	data.CALifetime = resolveDurationFieldState(data.CALifetime, readResp.CALifetime)
	data.CASoftExpiry = resolveDurationFieldState(data.CASoftExpiry, readResp.CASoftExpiry)
	data.DefaultCertTTL = resolveDurationFieldState(data.DefaultCertTTL, readResp.DefaultCertTTL)

	return nil
}

func resolveDurationFieldState(current types.String, fromAPI string) types.String {
	if fromAPI == "" {
		if current.IsNull() || current.IsUnknown() {
			return types.StringNull()
		}
		return current
	}

	if !current.IsNull() && !current.IsUnknown() && equivalentDurationString(current.ValueString(), fromAPI) {
		return current
	}

	return types.StringValue(fromAPI)
}

func equivalentDurationString(a, b string) bool {
	if a == b {
		return true
	}

	da, err := time.ParseDuration(a)
	if err != nil {
		return false
	}

	db, err := time.ParseDuration(b)
	if err != nil {
		return false
	}

	return da == db
}
