// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
)

// Ensure the implementation satisfies the datasource.DataSourceWithConfigure interface
var _ datasource.DataSourceWithConfigure = &SysConfigCORSDataSource{}

// NewSysConfigCORSDataSource returns the implementation for this data source to be
// imported by the Terraform Plugin Framework provider
func NewSysConfigCORSDataSource() datasource.DataSource {
	return &SysConfigCORSDataSource{}
}

// SysConfigCORSDataSource implements the methods that define this data source
type SysConfigCORSDataSource struct {
	base.DataSourceWithConfigure
}

// SysConfigCORSDataSourceModel describes the Terraform data source data model to match the
// data source schema.
type SysConfigCORSDataSourceModel struct {
	// fields specific to this data source
	Enabled        types.Bool `tfsdk:"enabled"`
	AllowedOrigins types.Set  `tfsdk:"allowed_origins"`
	AllowedHeaders types.Set  `tfsdk:"allowed_headers"`
}

// Metadata defines the data source name as it would appear in Terraform configurations
//
// https://developer.hashicorp.com/terraform/plugin/framework/data-sources#metadata-method
func (d *SysConfigCORSDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_sys_config_cors"
}

// Schema defines this data source's schema which is the data that is available in
// the data source's configuration and state
//
// https://developer.hashicorp.com/terraform/plugin/framework/data-sources#schema-method
func (d *SysConfigCORSDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldEnabled: schema.BoolAttribute{
				MarkdownDescription: "Whether CORS is currently enabled.",
				Computed:            true,
			},
			consts.FieldAllowedOrigins: schema.SetAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Set of origins permitted to make cross-origin requests.",
				Computed:            true,
			},
			consts.FieldAllowedHeaders: schema.SetAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Set of additional custom headers allowed on cross-origin requests. This only includes custom headers that were explicitly configured, not the standard Vault headers that are automatically included.",
				Computed:            true,
			},
		},
		MarkdownDescription: "Reads the current CORS configuration from Vault. This data source reads from the root namespace only.",
	}
}

func (d *SysConfigCORSDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data SysConfigCORSDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	client, err := client.GetClient(ctx, d.Meta(), "")
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	corsResp, err := client.Logical().ReadWithContext(ctx, "sys/config/cors")
	if err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultReadErr(err),
		)
		return
	}

	var readResp SysConfigCORSAPIModel
	err = model.ToAPIModel(corsResp.Data, &readResp)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	data.Enabled = types.BoolValue(readResp.Enabled)

	// Convert allowed_origins to Set
	if len(readResp.AllowedOrigins) > 0 {
		allowedOrigins, diags := types.SetValueFrom(ctx, types.StringType, readResp.AllowedOrigins)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		data.AllowedOrigins = allowedOrigins
	} else {
		data.AllowedOrigins = types.SetNull(types.StringType)
	}

	// Convert allowed_headers to Set, filtering out standard headers
	// Vault automatically prepends standard headers, but we only want to show
	// the custom headers that were explicitly configured
	if len(readResp.AllowedHeaders) > 0 {
		customHeaders := filterStandardHeaders(readResp.AllowedHeaders)
		if len(customHeaders) > 0 {
			allowedHeaders, diags := types.SetValueFrom(ctx, types.StringType, customHeaders)
			resp.Diagnostics.Append(diags...)
			if resp.Diagnostics.HasError() {
				return
			}
			data.AllowedHeaders = allowedHeaders
		} else {
			// If only standard headers are present, set to null since no custom headers were configured
			data.AllowedHeaders = types.SetNull(types.StringType)
		}
	} else {
		data.AllowedHeaders = types.SetNull(types.StringType)
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
