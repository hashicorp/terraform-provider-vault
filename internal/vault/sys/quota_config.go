// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
)

const quotaConfigPath = "/sys/quotas/config"

var _ resource.ResourceWithConfigure = &QuotaConfigResource{}
var _ resource.ResourceWithImportState = &QuotaConfigResource{}

// NewQuotaConfigResource returns the implementation for this resource.
func NewQuotaConfigResource() resource.Resource {
	return &QuotaConfigResource{}
}

// QuotaConfigResource manages the fixed /sys/quotas/config endpoint.
//
// Note: this resource keeps base `namespace` support because Vault Enterprise
// allows `/sys/quotas/config` to be called from the root or administrative
// namespace. That support is intentionally asymmetric: administrative
// namespaces can read the config and update the boolean fields, but exemption
// paths remain effectively root-managed. Terraform delete semantics therefore
// stay root-only for this resource. Vault does not expose a native delete
// operation for `/sys/quotas/config`, and a namespaced instance cannot reset the
// root-managed exemption fields back to defaults.
type QuotaConfigResource struct {
	base.ResourceWithConfigure
}

// QuotaConfigModel describes the Terraform resource data model.
type QuotaConfigModel struct {
	base.BaseModel

	RateLimitExemptPaths           types.Set  `tfsdk:"rate_limit_exempt_paths"`
	AbsoluteRateLimitExemptPaths   types.Set  `tfsdk:"absolute_rate_limit_exempt_paths"`
	EnableRateLimitAuditLogging    types.Bool `tfsdk:"enable_rate_limit_audit_logging"`
	EnableRateLimitResponseHeaders types.Bool `tfsdk:"enable_rate_limit_response_headers"`
}

// QuotaConfigAPIModel describes the Vault API data model.
type QuotaConfigAPIModel struct {
	RateLimitExemptPaths           []string `json:"rate_limit_exempt_paths" mapstructure:"rate_limit_exempt_paths"`
	AbsoluteRateLimitExemptPaths   []string `json:"absolute_rate_limit_exempt_paths" mapstructure:"absolute_rate_limit_exempt_paths"`
	EnableRateLimitAuditLogging    bool     `json:"enable_rate_limit_audit_logging" mapstructure:"enable_rate_limit_audit_logging"`
	EnableRateLimitResponseHeaders bool     `json:"enable_rate_limit_response_headers" mapstructure:"enable_rate_limit_response_headers"`
}

func (r *QuotaConfigResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_quota_config"
}

func (r *QuotaConfigResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Provides a resource to manage the singleton Vault quotas configuration at `/sys/quotas/config`.",
		Attributes: map[string]schema.Attribute{
			consts.FieldRateLimitExemptPaths: schema.SetAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Paths exempt from rate limit quotas relative to the current namespace context. This endpoint is only callable from the root or an administrative namespace, and exemption updates are effectively root-managed. Order is not significant.",
			},
			consts.FieldAbsoluteRateLimitExemptPaths: schema.SetAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Absolute paths exempt from all rate limit quotas, qualified from the root of the namespace hierarchy. This field is effectively root-managed; administrative namespaces can read returned values but cannot reliably manage them. Order is not significant.",
			},
			consts.FieldEnableRateLimitAuditLogging: schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Enables audit logging for requests rejected by rate limit quotas.",
			},
			consts.FieldEnableRateLimitResponseHeaders: schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Enables rate limit response headers on HTTP responses.",
			},
		},
	}

	base.MustAddBaseSchema(&resp.Schema)
}

func (r *QuotaConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data QuotaConfigModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultRequest, diags := r.getWriteRequest(ctx, req.Config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if _, err := vaultClient.Logical().WriteWithContext(ctx, quotaConfigPath, vaultRequest); err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	resp.Diagnostics.Append(r.readState(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *QuotaConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data QuotaConfigModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.readState(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *QuotaConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data QuotaConfigModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultRequest, diags := r.getWriteRequest(ctx, req.Config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if _, err := vaultClient.Logical().WriteWithContext(ctx, quotaConfigPath, vaultRequest); err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}

	resp.Diagnostics.Append(r.readState(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *QuotaConfigResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data QuotaConfigModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if ns := strings.TrimSpace(data.Namespace.ValueString()); ns != "" {
		resp.Diagnostics.AddError(
			"Unable to Delete Resource",
			"Deleting a namespaced vault_quota_config resource is not supported. Vault does not expose a delete operation for /sys/quotas/config, and administrative namespaces cannot reset the root-managed exemption fields. Use the root namespace to reset the quota config to defaults before removing this resource from state.",
		)
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	if _, err := vaultClient.Logical().WriteWithContext(ctx, quotaConfigPath, quotaConfigDefaults()); err != nil {
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
		return
	}

	// Returning without errors removes the resource from state.
}

func (r *QuotaConfigResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	normalizedID := strings.Trim(req.ID, "/")
	if normalizedID != "sys/quotas/config" && normalizedID != "config" {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			fmt.Sprintf("The import identifier %q is not valid. Use %q.", req.ID, "sys/quotas/config"),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), types.StringNull())...)

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

func (r *QuotaConfigResource) readState(ctx context.Context, data *QuotaConfigModel) diag.Diagnostics {
	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		summary, detail := errutil.ClientConfigureErr(err)
		return diag.Diagnostics{diag.NewErrorDiagnostic(summary, detail)}
	}

	quotaResp, err := vaultClient.Logical().ReadWithContext(ctx, quotaConfigPath)
	if err != nil {
		summary, detail := errutil.VaultReadErr(err)
		return diag.Diagnostics{diag.NewErrorDiagnostic(summary, detail)}
	}
	if quotaResp == nil {
		summary, detail := errutil.VaultReadResponseNil()
		return diag.Diagnostics{diag.NewErrorDiagnostic(summary, detail)}
	}

	var readResp QuotaConfigAPIModel
	if err := model.ToAPIModel(quotaResp.Data, &readResp); err != nil {
		return diag.Diagnostics{diag.NewErrorDiagnostic("Unable to translate Vault response data", err.Error())}
	}

	if readResp.RateLimitExemptPaths == nil {
		readResp.RateLimitExemptPaths = []string{}
	}
	if readResp.AbsoluteRateLimitExemptPaths == nil {
		readResp.AbsoluteRateLimitExemptPaths = []string{}
	}

	var diags diag.Diagnostics
	data.RateLimitExemptPaths, diags = types.SetValueFrom(ctx, types.StringType, readResp.RateLimitExemptPaths)
	if diags.HasError() {
		return diags
	}

	data.AbsoluteRateLimitExemptPaths, diags = types.SetValueFrom(ctx, types.StringType, readResp.AbsoluteRateLimitExemptPaths)
	if diags.HasError() {
		return diags
	}

	data.EnableRateLimitAuditLogging = types.BoolValue(readResp.EnableRateLimitAuditLogging)
	data.EnableRateLimitResponseHeaders = types.BoolValue(readResp.EnableRateLimitResponseHeaders)

	return nil
}

func (r *QuotaConfigResource) getWriteRequest(ctx context.Context, config tfsdk.Config) (map[string]any, diag.Diagnostics) {
	// Only send attributes that are explicitly configured in Terraform.
	// This avoids provider-side clearing of optional fields, but it does not
	// override Vault runtime behavior. In particular, admin-namespace writes to
	// /sys/quotas/config may still cause Vault itself to return omitted exempt-path
	// fields as empty lists on subsequent reads.
	rateLimitExemptPaths, rateLimitExemptPathsSet, diags := getStringSetConfig(ctx, config, consts.FieldRateLimitExemptPaths)
	if diags.HasError() {
		return nil, diags
	}

	absoluteRateLimitExemptPaths, absoluteRateLimitExemptPathsSet, diags := getStringSetConfig(ctx, config, consts.FieldAbsoluteRateLimitExemptPaths)
	if diags.HasError() {
		return nil, diags
	}

	enableRateLimitAuditLogging, enableRateLimitAuditLoggingSet, diags := getBoolConfig(ctx, config, consts.FieldEnableRateLimitAuditLogging)
	if diags.HasError() {
		return nil, diags
	}

	enableRateLimitResponseHeaders, enableRateLimitResponseHeadersSet, diags := getBoolConfig(ctx, config, consts.FieldEnableRateLimitResponseHeaders)
	if diags.HasError() {
		return nil, diags
	}

	request := map[string]any{}

	if rateLimitExemptPathsSet {
		request[consts.FieldRateLimitExemptPaths] = rateLimitExemptPaths
	}

	if absoluteRateLimitExemptPathsSet {
		request[consts.FieldAbsoluteRateLimitExemptPaths] = absoluteRateLimitExemptPaths
	}

	if enableRateLimitAuditLoggingSet {
		request[consts.FieldEnableRateLimitAuditLogging] = enableRateLimitAuditLogging
	}

	if enableRateLimitResponseHeadersSet {
		request[consts.FieldEnableRateLimitResponseHeaders] = enableRateLimitResponseHeaders
	}

	return request, nil
}

func getStringSetConfig(ctx context.Context, config tfsdk.Config, attributeName string) ([]string, bool, diag.Diagnostics) {
	var attr types.Set
	diags := config.GetAttribute(ctx, path.Root(attributeName), &attr)
	if diags.HasError() {
		return nil, false, diags
	}

	if attr.IsNull() || attr.IsUnknown() {
		return nil, false, nil
	}

	var result []string
	diags.Append(attr.ElementsAs(ctx, &result, false)...)
	if diags.HasError() {
		return nil, false, diags
	}

	return result, true, nil
}

func getBoolConfig(ctx context.Context, config tfsdk.Config, attributeName string) (bool, bool, diag.Diagnostics) {
	var attr types.Bool
	diags := config.GetAttribute(ctx, path.Root(attributeName), &attr)
	if diags.HasError() {
		return false, false, diags
	}

	if attr.IsNull() || attr.IsUnknown() {
		return false, false, nil
	}

	return attr.ValueBool(), true, nil
}

func quotaConfigDefaults() map[string]any {
	return map[string]any{
		consts.FieldRateLimitExemptPaths:           []string{},
		consts.FieldAbsoluteRateLimitExemptPaths:   []string{},
		consts.FieldEnableRateLimitAuditLogging:    false,
		consts.FieldEnableRateLimitResponseHeaders: false,
	}
}
