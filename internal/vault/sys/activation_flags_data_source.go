// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

var _ datasource.DataSource = &ActivationFlagsDataSource{}
var _ datasource.DataSourceWithConfigure = &ActivationFlagsDataSource{}

// NewActivationFlagsDataSource returns the implementation for this data source
func NewActivationFlagsDataSource() datasource.DataSource {
	return &ActivationFlagsDataSource{}
}

// ActivationFlagsDataSource implements the data source
type ActivationFlagsDataSource struct {
	base.DataSourceWithConfigure
}

// ActivationFlagsDataSourceModel describes the Terraform data source data model
type ActivationFlagsDataSourceModel struct {
	base.BaseModel

	ID               types.String `tfsdk:"id"`
	ActivatedFlags   types.List   `tfsdk:"activated_flags"`
	UnactivatedFlags types.List   `tfsdk:"unactivated_flags"`
}

// Metadata defines the data source name
func (d *ActivationFlagsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_activation_flags"
}

// Schema defines the data source schema
func (d *ActivationFlagsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldActivatedFlags: schema.ListAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "List of activated feature flags.",
			},
			consts.FieldUnactivatedFlags: schema.ListAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "List of unactivated feature flags.",
			},
			consts.FieldID: schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Unique identifier for this data source.",
			},
			consts.FieldNamespace: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Target namespace. (requires Enterprise)",
			},
		},
		MarkdownDescription: "Reads activation flags from Vault.",
	}
}

// Read is called when the data source is refreshed
func (d *ActivationFlagsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data ActivationFlagsDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, d.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultResp, err := cli.Logical().ReadWithContext(ctx, activationFlagsPath)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Activation Flags",
			"Error reading activation flags from Vault: "+err.Error(),
		)
		return
	}

	if vaultResp == nil {
		resp.Diagnostics.AddError(
			"No Activation Flags Found",
			"No activation flags found at "+activationFlagsPath,
		)
		return
	}

	resp.Diagnostics.Append(populateActivationFlagsDataSourceModel(ctx, &data, vaultResp.Data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func populateActivationFlagsDataSourceModel(ctx context.Context, data *ActivationFlagsDataSourceModel, vaultData map[string]interface{}) diag.Diagnostics {
	var diagnostics diag.Diagnostics

	activatedFlags, unactivatedFlags, err := decodeActivationFlagsResponse(vaultData)
	if err != nil {
		diagnostics.AddError(
			"Error Reading Activation Flags",
			err.Error(),
		)
		return diagnostics
	}

	sort.Strings(activatedFlags)
	sort.Strings(unactivatedFlags)

	data.ActivatedFlags, diagnostics = listValueFromStrings(ctx, activatedFlags, diagnostics)
	if diagnostics.HasError() {
		return diagnostics
	}

	data.UnactivatedFlags, diagnostics = listValueFromStrings(ctx, unactivatedFlags, diagnostics)
	if diagnostics.HasError() {
		return diagnostics
	}

	data.ID = types.StringValue(activationFlagsPath)

	return diagnostics
}

func decodeActivationFlagsResponse(vaultData map[string]interface{}) ([]string, []string, error) {
	activatedFlags, err := getActivationFlagsFromResponse(vaultData, activationFlagsAPIActivatedField)
	if err != nil {
		return nil, nil, err
	}

	unactivatedFlags, err := getActivationFlagsFromResponse(vaultData, activationFlagsAPIUnactivatedField)
	if err != nil {
		return nil, nil, err
	}

	return activatedFlags, unactivatedFlags, nil
}

func listValueFromStrings(ctx context.Context, values []string, diagnostics diag.Diagnostics) (types.List, diag.Diagnostics) {
	listValue, diags := types.ListValueFrom(ctx, types.StringType, values)
	diagnostics.Append(diags...)
	return listValue, diagnostics
}
