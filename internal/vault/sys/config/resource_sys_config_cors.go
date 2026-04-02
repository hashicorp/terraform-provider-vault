// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
)

// Standard Vault headers that are automatically included by Vault
// These match the StdAllowedHeaders from vault/cors.go
var standardVaultHeaders = map[string]bool{
	"Content-Type":                  true,
	"X-Requested-With":              true,
	"X-Vault-AWS-IAM-Server-ID":     true,
	"X-Vault-MFA":                   true,
	"X-Vault-No-Request-Forwarding": true,
	"X-Vault-Wrap-Format":           true,
	"X-Vault-Wrap-TTL":              true,
	"X-Vault-Policy-Override":       true,
	"Authorization":                 true,
	"X-Vault-Token":                 true,
}

// filterStandardHeaders removes standard Vault headers from the list,
// returning only custom headers that were explicitly configured by the user.
// This is necessary because Vault automatically prepends standard headers
// to any custom headers provided during configuration.
func filterStandardHeaders(headers []string) []string {
	var customHeaders []string
	for _, header := range headers {
		if !standardVaultHeaders[header] {
			customHeaders = append(customHeaders, header)
		}
	}
	return customHeaders
}

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &SysConfigCORSResource{}

// Ensure the implementation satisfies the resource.ResourceWithImportState interface
var _ resource.ResourceWithImportState = &SysConfigCORSResource{}

// NewSysConfigCORSResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewSysConfigCORSResource() resource.Resource {
	return &SysConfigCORSResource{}
}

// SysConfigCORSResource implements the methods that define this resource
type SysConfigCORSResource struct {
	base.ResourceWithConfigure
}

// SysConfigCORSModel describes the Terraform resource data model to match the
// resource schema.
type SysConfigCORSModel struct {
	// fields specific to this resource
	ID             types.String `tfsdk:"id"`
	Enabled        types.Bool   `tfsdk:"enabled"`
	AllowedOrigins types.Set    `tfsdk:"allowed_origins"`
	AllowedHeaders types.Set    `tfsdk:"allowed_headers"`
}

// SysConfigCORSAPIModel describes the Vault API data model.
type SysConfigCORSAPIModel struct {
	Enabled        bool     `json:"enabled" mapstructure:"enabled"`
	AllowedOrigins []string `json:"allowed_origins" mapstructure:"allowed_origins"`
	AllowedHeaders []string `json:"allowed_headers" mapstructure:"allowed_headers"`
}

// Metadata defines the resource name as it would appear in Terraform configurations
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources#metadata-method
func (r *SysConfigCORSResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_sys_config_cors"
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources#schema-method
func (r *SysConfigCORSResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldID: schema.StringAttribute{
				MarkdownDescription: "The ID of the CORS configuration. Always set to `sys/config/cors`.",
				Computed:            true,
			},
			consts.FieldEnabled: schema.BoolAttribute{
				MarkdownDescription: "(Computed) Whether CORS is currently enabled. Vault automatically sets this to true when allowed_origins is configured. To disable CORS, delete this resource.",
				Computed:            true,
			},
			consts.FieldAllowedOrigins: schema.SetAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Set of origins permitted to make cross-origin requests. Use `*` as the only value to allow all origins.",
				Required:            true,
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
				},
			},
			consts.FieldAllowedHeaders: schema.SetAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Set of additional custom headers allowed on cross-origin requests. Vault automatically includes standard headers (Content-Type, X-Requested-With, X-Vault-AWS-IAM-Server-ID, X-Vault-MFA, X-Vault-No-Request-Forwarding, X-Vault-Wrap-Format, X-Vault-Wrap-TTL, X-Vault-Policy-Override, Authorization, X-Vault-Token), so only specify custom headers here.",
				Optional:            true,
			},
		},
		MarkdownDescription: "Manages the CORS configuration for Vault, controlling which origins can make cross-origin requests and which headers are allowed. This resource requires `sudo` capability and must be called from the root namespace.",
	}
}

func (r *SysConfigCORSResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data SysConfigCORSModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Write configuration to Vault
	if err := r.writeConfigToVault(ctx, &data, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	// Set the ID for the resource
	data.ID = types.StringValue(r.path())

	// Read back the configuration to populate computed fields like 'enabled'
	if err := r.readCORSConfig(ctx, &data, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *SysConfigCORSResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data SysConfigCORSModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Write configuration to Vault
	if err := r.writeConfigToVault(ctx, &data, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}

	// Set the ID for the resource
	data.ID = types.StringValue(r.path())

	// Read back the configuration to populate computed fields like 'enabled'
	if err := r.readCORSConfig(ctx, &data, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *SysConfigCORSResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data SysConfigCORSModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	err := r.readCORSConfig(ctx, &data, &resp.Diagnostics)
	if err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultReadErr(err),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *SysConfigCORSResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data SysConfigCORSModel

	// Read Terraform state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	client, err := client.GetClient(ctx, r.Meta(), "")
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	path := r.path()

	_, err = client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultDeleteErr(err),
		)
		return
	}

}

func (r *SysConfigCORSResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), r.path())...)
}

func (r *SysConfigCORSResource) path() string {
	return "sys/config/cors"
}

// writeConfigToVault is a helper function that writes the CORS configuration to Vault.
// This is used by both Create and Update operations to avoid code duplication.
func (r *SysConfigCORSResource) writeConfigToVault(ctx context.Context, data *SysConfigCORSModel, diags *diag.Diagnostics) error {
	client, err := client.GetClient(ctx, r.Meta(), "")
	if err != nil {
		return err
	}

	path := r.path()

	var allowedOrigins []string
	diags.Append(data.AllowedOrigins.ElementsAs(ctx, &allowedOrigins, false)...)
	if diags.HasError() {
		return nil
	}

	var allowedHeaders []string
	diags.Append(data.AllowedHeaders.ElementsAs(ctx, &allowedHeaders, false)...)
	if diags.HasError() {
		return nil
	}

	vaultRequest := map[string]interface{}{
		consts.FieldAllowedOrigins: allowedOrigins,
		consts.FieldAllowedHeaders: allowedHeaders,
	}

	// vault returns a nil response on success
	_, err = client.Logical().WriteWithContext(ctx, path, vaultRequest)
	return err
}

// readCORSConfig is a helper function that reads the CORS configuration from Vault
// and populates the model. This is used by Create, Update, and Read operations.
func (r *SysConfigCORSResource) readCORSConfig(ctx context.Context, data *SysConfigCORSModel, diags *diag.Diagnostics) error {
	client, err := client.GetClient(ctx, r.Meta(), "")
	if err != nil {
		return err
	}

	path := r.path()
	corsResp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return err
	}

	// Set the ID
	data.ID = types.StringValue(r.path())

	var readResp SysConfigCORSAPIModel
	err = model.ToAPIModel(corsResp.Data, &readResp)
	if err != nil {
		return err
	}

	data.Enabled = types.BoolValue(readResp.Enabled)

	// Convert allowed_origins to Set
	if len(readResp.AllowedOrigins) > 0 {
		allowedOrigins, d := types.SetValueFrom(ctx, types.StringType, readResp.AllowedOrigins)
		diags.Append(d...)
		if diags.HasError() {
			return nil
		}
		data.AllowedOrigins = allowedOrigins
	} else {
		data.AllowedOrigins = types.SetNull(types.StringType)
	}

	// Convert allowed_headers to Set, filtering out standard headers
	// Vault automatically prepends standard headers, but we only want to track
	// the custom headers that the user explicitly configured
	customHeaders := filterStandardHeaders(readResp.AllowedHeaders)

	if len(customHeaders) > 0 {
		// User configured custom headers, set them in state
		allowedHeaders, d := types.SetValueFrom(ctx, types.StringType, customHeaders)
		diags.Append(d...)
		if diags.HasError() {
			return nil
		}
		data.AllowedHeaders = allowedHeaders
	} else if !data.AllowedHeaders.IsNull() {
		// No custom headers from Vault, but user explicitly configured allowed_headers
		// (even if empty), so preserve it as empty set
		data.AllowedHeaders = types.SetValueMust(types.StringType, []attr.Value{})
	} else {
		// No custom headers and user didn't configure allowed_headers, set to null
		data.AllowedHeaders = types.SetNull(types.StringType)
	}

	return nil
}
