// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudfoundry

import (
	"context"
	"fmt"
	"os"
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
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const (
	cfConfigPath = "config"
)

// Ensure the implementation satisfies the resource.ResourceWithImportState interface.
var _ resource.ResourceWithImportState = &CFAuthBackendConfigResource{}

// NewCFAuthBackendConfigResource returns the implementation for this resource.
func NewCFAuthBackendConfigResource() resource.Resource {
	return &CFAuthBackendConfigResource{}
}

// CFAuthBackendConfigResource implements the Terraform Plugin Framework resource.
type CFAuthBackendConfigResource struct {
	base.ResourceWithConfigure
}

// CFAuthBackendConfigModel describes the Terraform resource data model.
type CFAuthBackendConfigModel struct {
	base.BaseModel

	Mount                    types.String `tfsdk:"mount"`
	IdentityCACertificates   types.Set    `tfsdk:"identity_ca_certificates"`
	CFApiAddr                types.String `tfsdk:"cf_api_addr"`
	CFUsername               types.String `tfsdk:"cf_username"`
	CFPasswordWO             types.String `tfsdk:"cf_password_wo"`
	CFPasswordWOVersion      types.Int64  `tfsdk:"cf_password_wo_version"`
	CFApiTrustedCertificates types.Set    `tfsdk:"cf_api_trusted_certificates"`
	LoginMaxSecsNotBefore    types.Int64  `tfsdk:"login_max_seconds_not_before"`
	LoginMaxSecsNotAfter     types.Int64  `tfsdk:"login_max_seconds_not_after"`
	CFTimeout                types.Int64  `tfsdk:"cf_timeout"`
}

// CFConfigAPIModel describes the Vault API data model.
type CFConfigAPIModel struct {
	IdentityCACertificates   []string `json:"identity_ca_certificates" mapstructure:"identity_ca_certificates"`
	CFApiAddr                string   `json:"cf_api_addr" mapstructure:"cf_api_addr"`
	CFUsername               string   `json:"cf_username" mapstructure:"cf_username"`
	CFPassword               string   `json:"cf_password" mapstructure:"cf_password"`
	CFApiTrustedCertificates []string `json:"cf_api_trusted_certificates" mapstructure:"cf_api_trusted_certificates"`
	LoginMaxSecsNotBefore    int64    `json:"login_max_seconds_not_before,omitempty" mapstructure:"login_max_seconds_not_before,omitempty"`
	LoginMaxSecsNotAfter     int64    `json:"login_max_seconds_not_after,omitempty" mapstructure:"login_max_seconds_not_after,omitempty"`
	CFTimeout                int64    `json:"cf_timeout,omitempty" mapstructure:"cf_timeout"`
}

func (r *CFAuthBackendConfigResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cf_auth_backend_config"
}

func (r *CFAuthBackendConfigResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the configuration for the CloudFoundry (CF) auth method in Vault.",
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Mount path for the CF auth engine in Vault.",
				Required:            true,
			},
			consts.FieldIdentityCACertificates: schema.SetAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "The root CA certificate(s) to be used for verifying that the `CF_INSTANCE_CERT` presented for logging in was issued by the proper authority.",
				Required:            true,
			},
			consts.FieldCFApiAddr: schema.StringAttribute{
				MarkdownDescription: "CF's full API address, used for verifying that a given `CF_INSTANCE_CERT` shows an application ID, space ID, and organization ID that presently exist.",
				Required:            true,
			},
			consts.FieldCFUsername: schema.StringAttribute{
				MarkdownDescription: "The username for authenticating to the CF API.",
				Required:            true,
			},
			consts.FieldCFPasswordWO: schema.StringAttribute{
				MarkdownDescription: "The password for authenticating to the CF API. This attribute is write-only and is never stored in Terraform state.",
				Required:            true,
				Sensitive:           true,
				WriteOnly:           true,
			},
			consts.FieldCFPasswordWOVersion: schema.Int64Attribute{
				MarkdownDescription: "Version counter for 'cf_password_wo'. Increment this value to trigger an update when only the write-only password changes.",
				Required:            true,
			},
			consts.FieldCFApiTrustedCertificates: schema.SetAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "The certificate(s) presented by the CF API. Configures Vault to trust these certificates when making API calls.",
				Optional:            true,
			},
			consts.FieldLoginMaxSecsNotBefore: schema.Int64Attribute{
				MarkdownDescription: "The maximum number of seconds in the past when a signature could have been created. " +
					"Defaults to `300`. This field is `Computed`: if removed from config, " +
					"Vault retains the previously set value.",
				Optional: true,
				Computed: true,
			},
			consts.FieldLoginMaxSecsNotAfter: schema.Int64Attribute{
				MarkdownDescription: "The maximum number of seconds in the future when a signature could have been created. " +
					"Defaults to `60`. This field is `Computed`: if removed from config, " +
					"Vault retains the previously set value.",
				Optional: true,
				Computed: true,
			},
			consts.FieldCFTimeout: schema.Int64Attribute{
				MarkdownDescription: "The timeout for the CF API in seconds. " +
					"Defaults to `0` (no timeout). Removing this field from config resets the value to `0` in Vault.",
				Optional: true,
			},
		},
	}

	base.MustAddBaseSchema(&resp.Schema)
}

func (r *CFAuthBackendConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data CFAuthBackendConfigModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read write-only cf_password_wo directly from config (not stored in state).
	// On create, always send the password if provided.
	var cfPasswordWO types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root(consts.FieldCFPasswordWO), &cfPasswordWO)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var cfPassword *string
	if !cfPasswordWO.IsNull() && !cfPasswordWO.IsUnknown() {
		v := cfPasswordWO.ValueString()
		cfPassword = &v
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultRequest, diagErr := r.getAPIModel(ctx, &data, cfPassword)
	if diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	mountPath := r.path(data.Mount.ValueString())
	if _, err := vaultClient.Logical().WriteWithContext(ctx, mountPath, vaultRequest); err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	if diagErr := r.readAndPopulate(ctx, vaultClient, &data); diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CFAuthBackendConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data CFAuthBackendConfigModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	cfgResp, err := vaultClient.Logical().ReadWithContext(ctx, r.path(data.Mount.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if cfgResp == nil {
		tflog.Warn(ctx, "CF auth backend config not found, removing from state")
		resp.State.RemoveResource(ctx)
		return
	}

	if diagErr := r.populateDataModelFromAPI(ctx, &data, cfgResp); diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CFAuthBackendConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data CFAuthBackendConfigModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Always read and send the password from config on updates.
	// The password is sent on every update regardless of version changes.
	var cfPasswordWO types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root(consts.FieldCFPasswordWO), &cfPasswordWO)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var cfPassword *string
	if !cfPasswordWO.IsNull() && !cfPasswordWO.IsUnknown() {
		v := cfPasswordWO.ValueString()
		cfPassword = &v
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultRequest, diagErr := r.getAPIModel(ctx, &data, cfPassword)
	if diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	mountPath := r.path(data.Mount.ValueString())
	if _, err := vaultClient.Logical().WriteWithContext(ctx, mountPath, vaultRequest); err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}

	if diagErr := r.readAndPopulate(ctx, vaultClient, &data); diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *CFAuthBackendConfigResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data CFAuthBackendConfigModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	if _, err := vaultClient.Logical().DeleteWithContext(ctx, r.path(data.Mount.ValueString())); err != nil {
		if util.Is404(err) {
			return
		}
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
	}
}

func (r *CFAuthBackendConfigResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	mount, err := extractCFConfigMountFromID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			fmt.Sprintf("The import identifier %q is not valid: %s", req.ID, err.Error()),
		)
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

func (r *CFAuthBackendConfigResource) path(mount string) string {
	return fmt.Sprintf("auth/%s/%s", mount, cfConfigPath)
}

func (r *CFAuthBackendConfigResource) readAndPopulate(ctx context.Context, vaultClient *api.Client, data *CFAuthBackendConfigModel) diag.Diagnostics {
	cfgResp, err := vaultClient.Logical().ReadWithContext(ctx, r.path(data.Mount.ValueString()))
	if err != nil {
		return diag.Diagnostics{diag.NewErrorDiagnostic(errutil.VaultReadErr(err))}
	}
	if cfgResp == nil {
		return diag.Diagnostics{diag.NewErrorDiagnostic(errutil.VaultReadResponseNil())}
	}

	return r.populateDataModelFromAPI(ctx, data, cfgResp)
}

func (r *CFAuthBackendConfigResource) getAPIModel(ctx context.Context, data *CFAuthBackendConfigModel, cfPassword *string) (map[string]any, diag.Diagnostics) {
	apiModel := CFConfigAPIModel{
		CFApiAddr:             data.CFApiAddr.ValueString(),
		CFUsername:            data.CFUsername.ValueString(),
		LoginMaxSecsNotBefore: data.LoginMaxSecsNotBefore.ValueInt64(),
		LoginMaxSecsNotAfter:  data.LoginMaxSecsNotAfter.ValueInt64(),
	}
	// cf_timeout is only functional on Vault 1.19.4+; a bug causing it to be
	// ignored was fixed in that release. Only include it in the request when
	// the connected Vault supports it.
	if r.Meta() != nil && r.Meta().IsAPISupported(provider.VaultVersion1194) {
		apiModel.CFTimeout = data.CFTimeout.ValueInt64()
	}
	if cfPassword != nil {
		apiModel.CFPassword = *cfPassword
	}

	var identityCACerts []string
	if diagErr := data.IdentityCACertificates.ElementsAs(ctx, &identityCACerts, false); diagErr.HasError() {
		return nil, diagErr
	}
	apiModel.IdentityCACertificates = identityCACerts

	var trustedCerts []string
	if diagErr := data.CFApiTrustedCertificates.ElementsAs(ctx, &trustedCerts, false); diagErr.HasError() {
		return nil, diagErr
	}
	apiModel.CFApiTrustedCertificates = trustedCerts

	var vaultRequest map[string]any
	if err := mapstructure.Decode(apiModel, &vaultRequest); err != nil {
		return nil, diag.Diagnostics{
			diag.NewErrorDiagnostic("Failed to decode CF config API model to map", err.Error()),
		}
	}

	return vaultRequest, nil
}

func (r *CFAuthBackendConfigResource) populateDataModelFromAPI(ctx context.Context, data *CFAuthBackendConfigModel, resp *api.Secret) diag.Diagnostics {
	if resp == nil || resp.Data == nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Missing data in API response", "The API response or response data was nil."),
		}
	}

	var readResp CFConfigAPIModel
	if err := model.ToAPIModel(resp.Data, &readResp); err != nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("Unable to translate Vault response data", err.Error()),
		}
	}

	data.CFApiAddr = types.StringValue(readResp.CFApiAddr)
	data.CFUsername = types.StringValue(readResp.CFUsername)

	// cf_password_wo is write-only and never returned by Vault; leave it untouched in state.
	// cf_password_wo_version is managed by Terraform and persisted in state automatically.

	if readResp.LoginMaxSecsNotBefore != 0 {
		data.LoginMaxSecsNotBefore = types.Int64Value(readResp.LoginMaxSecsNotBefore)
	} else {
		data.LoginMaxSecsNotBefore = types.Int64Null()
	}
	if readResp.LoginMaxSecsNotAfter != 0 {
		data.LoginMaxSecsNotAfter = types.Int64Value(readResp.LoginMaxSecsNotAfter)
	} else {
		data.LoginMaxSecsNotAfter = types.Int64Null()
	}
	// cf_timeout is only functional on Vault 1.19.4+ (bug fix); leave state
	// unchanged on older servers to avoid a provider-inconsistency error.
	if r.Meta() != nil && r.Meta().IsAPISupported(provider.VaultVersion1194) {
		if readResp.CFTimeout != 0 {
			data.CFTimeout = types.Int64Value(readResp.CFTimeout)
		} else {
			data.CFTimeout = types.Int64Null()
		}
	}

	// identity_ca_certificates: Vault strips trailing whitespace from PEM certs.
	// If the existing data value (from plan/state) matches Vault's response when
	// both are trimmed, keep the existing value so the user's original formatting
	// (e.g. trailing newline from file()) is preserved and never causes a diff.
	var diags diag.Diagnostics
	data.IdentityCACertificates, diags = reconcileCertSet(ctx, readResp.IdentityCACertificates, data.IdentityCACertificates)
	if diags.HasError() {
		return diags
	}

	// cf_api_trusted_certificates: same reconciliation.
	if len(readResp.CFApiTrustedCertificates) == 0 {
		data.CFApiTrustedCertificates = types.SetNull(types.StringType)
	} else {
		data.CFApiTrustedCertificates, diags = reconcileCertSet(ctx, readResp.CFApiTrustedCertificates, data.CFApiTrustedCertificates)
		if diags.HasError() {
			return diags
		}
	}

	return diag.Diagnostics{}
}

// reconcileCertSet compares vaultCerts (as returned by Vault, possibly trimmed)
// against current (the existing plan/state value). If the two sets are equal
// when both sides are whitespace-trimmed, current is returned unchanged — this
// preserves the user's original cert formatting (e.g. a trailing newline from
// file()) so that Vault's cosmetic stripping never produces a plan/state diff.
// If the sets differ semantically (a cert was actually added, removed, or
// replaced), the trimmed Vault values are returned instead.
func reconcileCertSet(ctx context.Context, vaultCerts []string, current types.Set) (types.Set, diag.Diagnostics) {
	// Trim the Vault certs.
	trimmed := make([]string, len(vaultCerts))
	for i, c := range vaultCerts {
		trimmed[i] = strings.TrimSpace(c)
	}

	// Only compare if current state exists.
	if !current.IsNull() && !current.IsUnknown() {
		// Extract current cert strings and trim them for comparison only.
		var currentRaw []string
		if diags := current.ElementsAs(ctx, &currentRaw, false); diags.HasError() {
			return types.SetNull(types.StringType), diags
		}
		trimmedCurrent := make([]string, len(currentRaw))
		for i, c := range currentRaw {
			trimmedCurrent[i] = strings.TrimSpace(c)
		}

		// Compare the two trimmed sets. If they contain the same elements, the certs
		// haven't actually changed — return current as-is to preserve formatting.
		if stringSetsEqual(trimmed, trimmedCurrent) {
			return current, nil
		}
	}

	// Default: no prior state OR content changed - use trimmed Vault values.
	v, diags := types.SetValueFrom(ctx, types.StringType, trimmed)
	return v, diags
}

// stringSetsEqual returns true when a and b contain the same strings,
// regardless of order.
func stringSetsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		if seen[s] == 0 {
			return false
		}
		seen[s]--
	}
	return true
}

func extractCFConfigMountFromID(id string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("import identifier cannot be empty")
	}

	id = strings.Trim(id, "/")

	// Expected format: auth/<mount>/config
	if !strings.HasPrefix(id, "auth/") || !strings.HasSuffix(id, "/config") {
		return "", fmt.Errorf("import identifier must be of the form 'auth/<mount>/config', "+
			"namespace can be specified using the env var %s", consts.EnvVarVaultNamespaceImport)
	}

	// Extract mount: remove "auth/" prefix and "/config" suffix
	mount := strings.TrimPrefix(id, "auth/")
	mount = strings.TrimSuffix(mount, "/config")
	mount = strings.TrimSpace(mount)

	if mount == "" {
		return "", fmt.Errorf("mount cannot be empty")
	}

	return mount, nil
}
