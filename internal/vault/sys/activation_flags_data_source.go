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
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
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
	ID               types.String `tfsdk:"id"`
	ActivatedFlags   types.Set    `tfsdk:"activated_flags"`
	UnactivatedFlags types.Set    `tfsdk:"unactivated_flags"`
}

// Metadata defines the data source name
func (d *ActivationFlagsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_activation_flags"
}

// Schema defines the data source schema
func (d *ActivationFlagsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldActivatedFlags: schema.SetAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "List of activated feature flags.",
			},
			consts.FieldUnactivatedFlags: schema.SetAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "List of unactivated feature flags.",
			},
			consts.FieldID: schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Unique identifier for this data source.",
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

	cli, err := client.GetClient(ctx, d.Meta(), "")
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	if !provider.IsAPISupported(d.Meta(), provider.VaultVersion116) {
		resp.Diagnostics.AddError("Unsupported Vault Version", "activation flags require Vault 1.16 or later")
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

	data.ActivatedFlags, diagnostics = setValueFromStrings(ctx, activatedFlags, diagnostics)
	if diagnostics.HasError() {
		return diagnostics
	}

	data.UnactivatedFlags, diagnostics = setValueFromStrings(ctx, unactivatedFlags, diagnostics)
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

func setValueFromStrings(ctx context.Context, values []string, diagnostics diag.Diagnostics) (types.Set, diag.Diagnostics) {
	setValue, diags := types.SetValueFrom(ctx, types.StringType, values)
	diagnostics.Append(diags...)
	return setValue, diagnostics
}
