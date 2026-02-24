// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudfoundry

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

const (
	cfConfigPath = "config"
)

var cfConfigBackendRegexp = regexp.MustCompile(`^auth/(.+)/config$`)

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
	IdentityCACertificates   types.List   `tfsdk:"identity_ca_certificates"`
	CFApiAddr                types.String `tfsdk:"cf_api_addr"`
	CFUsername               types.String `tfsdk:"cf_username"`
	CFPasswordWO             types.String `tfsdk:"cf_password_wo"`
	CFPasswordWOVersion      types.Int64  `tfsdk:"cf_password_wo_version"`
	CFApiTrustedCertificates types.List   `tfsdk:"cf_api_trusted_certificates"`
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
	LoginMaxSecsNotBefore    int64    `json:"login_max_seconds_not_before" mapstructure:"login_max_seconds_not_before"`
	LoginMaxSecsNotAfter     int64    `json:"login_max_seconds_not_after" mapstructure:"login_max_seconds_not_after"`
	CFTimeout                int64    `json:"cf_timeout" mapstructure:"cf_timeout"`
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
			"identity_ca_certificates": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "The root CA certificate(s) to be used for verifying that the `CF_INSTANCE_CERT` presented for logging in was issued by the proper authority.",
				Required:            true,
			},
			"cf_api_addr": schema.StringAttribute{
				MarkdownDescription: "CF's full API address, used for verifying that a given `CF_INSTANCE_CERT` shows an application ID, space ID, and organization ID that presently exist.",
				Required:            true,
			},
			"cf_username": schema.StringAttribute{
				MarkdownDescription: "The username for authenticating to the CF API.",
				Required:            true,
			},
			"cf_password_wo": schema.StringAttribute{
				MarkdownDescription: "The password for authenticating to the CF API. This is a write-only field and will not be read back from Vault.",
				Required:            true,
				Sensitive:           true,
				WriteOnly:           true,
			},
			"cf_password_wo_version": schema.Int64Attribute{
				MarkdownDescription: "A version counter for the write-only `cf_password_wo` field. Incrementing this value triggers an update to the password.",
				Required:            true,
			},
			"cf_api_trusted_certificates": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "The certificate(s) presented by the CF API. Configures Vault to trust these certificates when making API calls.",
				Optional:            true,
			},
			"login_max_seconds_not_before": schema.Int64Attribute{
				MarkdownDescription: "The maximum number of seconds in the past when a signature could have been created.",
				Optional:            true,
				Computed:            true,
			},
			"login_max_seconds_not_after": schema.Int64Attribute{
				MarkdownDescription: "The maximum number of seconds in the future when a signature could have been created.",
				Optional:            true,
				Computed:            true,
			},
			"cf_timeout": schema.Int64Attribute{
				MarkdownDescription: "The timeout for the CF API in seconds. If not set, defaults to 0 (no timeout).",
				Optional:            true,
				Computed:            true,
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
	var cfPasswordWO types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("cf_password_wo"), &cfPasswordWO)...)
	if resp.Diagnostics.HasError() {
		return
	}
	v := cfPasswordWO.ValueString()

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultRequest, diagErr := r.getAPIModel(ctx, &data, &v)
	if diagErr.HasError() {
		resp.Diagnostics.Append(diagErr...)
		return
	}

	mountPath := r.path(data.Mount.ValueString())
	tflog.Debug(ctx, "Writing CF auth backend config", map[string]any{"vaultRequest": vaultRequest})
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
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
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

	// Read prior state to detect whether cf_password_wo_version has changed.
	var priorState CFAuthBackendConfigModel
	resp.Diagnostics.Append(req.State.Get(ctx, &priorState)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var cfPassword *string
	if !data.CFPasswordWOVersion.Equal(priorState.CFPasswordWOVersion) {
		// Version bumped — read the write-only value from config and send it to Vault.
		var cfPasswordWO types.String
		resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("cf_password_wo"), &cfPasswordWO)...)
		if resp.Diagnostics.HasError() {
			return
		}
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

	if _, err := vaultClient.Logical().Delete(r.path(data.Mount.ValueString())); err != nil {
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
		CFTimeout:             data.CFTimeout.ValueInt64(),
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
	// cf_password_wo_version is preserved as-is from state since it is managed by the practitioner.

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

	if readResp.CFTimeout != 0 {
		data.CFTimeout = types.Int64Value(readResp.CFTimeout)
	} else {
		data.CFTimeout = types.Int64Null()
	}

	identityCACerts, listErr := types.ListValueFrom(ctx, types.StringType, readResp.IdentityCACertificates)
	if listErr.HasError() {
		return listErr
	}
	data.IdentityCACertificates = identityCACerts

	if len(readResp.CFApiTrustedCertificates) == 0 {
		data.CFApiTrustedCertificates = types.ListNull(types.StringType)
	} else {
		trustedCerts, listErr := types.ListValueFrom(ctx, types.StringType, readResp.CFApiTrustedCertificates)
		if listErr.HasError() {
			return listErr
		}
		data.CFApiTrustedCertificates = trustedCerts
	}

	return diag.Diagnostics{}
}

func extractCFConfigMountFromID(id string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("import identifier cannot be empty")
	}
	id = strings.Trim(id, "/")

	if !cfConfigBackendRegexp.MatchString(id) {
		return "", fmt.Errorf("import identifier must be of the form 'auth/<mount>/config', "+
			"namespace can be specified using the env var %s", consts.EnvVarVaultNamespaceImport)
	}

	matches := cfConfigBackendRegexp.FindStringSubmatch(id)
	if len(matches) != 2 {
		return "", fmt.Errorf("import identifier must be of the form 'auth/<mount>/config', "+
			"namespace can be specified using the env var %s", consts.EnvVarVaultNamespaceImport)
	}

	mount := strings.TrimSpace(matches[1])
	if mount == "" {
		return "", fmt.Errorf("mount cannot be empty")
	}

	return mount, nil
}
