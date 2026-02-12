// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/vault/api"
)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ ephemeral.EphemeralResource = &GenericEphemeralSecretResource{}

// NewGenericEphemeralSecretResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
var NewGenericEphemeralSecretResource = func() ephemeral.EphemeralResource {
	return &GenericEphemeralSecretResource{}
}

// GenericEphemeralSecretResource implements the methods that define this resource
type GenericEphemeralSecretResource struct {
	base.EphemeralResourceWithConfigure
}

// GenericEphemeralSecretModel describes the Terraform resource data model to match the
// resource schema.
type GenericEphemeralSecretModel struct {
	// common fields to all ephemeral resources
	base.BaseModelEphemeral

	// fields specific to this resource
	Path               types.String `tfsdk:"path"`
	Version            types.Int32  `tfsdk:"version"`
	WithLeaseStartTime types.Bool   `tfsdk:"with_lease_start_time"`
	DataJSON           types.String `tfsdk:"data_json"`
	Data               types.Map    `tfsdk:"data"`
	LeaseID            types.String `tfsdk:"lease_id"`
	LeaseDuration      types.Int64  `tfsdk:"lease_duration"`
	LeaseStartTime     types.String `tfsdk:"lease_start_time"`
	LeaseRenewable     types.Bool   `tfsdk:"lease_renewable"`
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
// https://developer.hashicorp.com/terraform/plugin/framework/resources#schema-method
func (r *GenericEphemeralSecretResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldPath: schema.StringAttribute{
				MarkdownDescription: "Full path from which a secret will be read.",
				Required:            true,
			},
			consts.FieldVersion: schema.Int32Attribute{
				Optional:            true,
				MarkdownDescription: "Version of the secret to retrieve. Use -1 for latest version.",
			},
			consts.FieldWithLeaseStartTime: schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "If set to true, stores 'lease_start_time' in the result.",
			},
			consts.FieldDataJSON: schema.StringAttribute{
				MarkdownDescription: "JSON-encoded secret data read from Vault.",
				Computed:            true,
				Sensitive:           true,
			},
			consts.FieldData: schema.MapAttribute{
				MarkdownDescription: "Map of strings read from Vault.",
				ElementType:         types.StringType,
				Computed:            true,
				Sensitive:           true,
			},
			consts.FieldLeaseID: schema.StringAttribute{
				MarkdownDescription: "Lease identifier assigned by vault.",
				Computed:            true,
			},
			consts.FieldLeaseDuration: schema.Int64Attribute{
				MarkdownDescription: "Lease duration in seconds.",
				Computed:            true,
			},
			consts.FieldLeaseStartTime: schema.StringAttribute{
				MarkdownDescription: "Time at which the lease was read, using the clock of the system where Terraform was running.",
				Computed:            true,
			},
			consts.FieldLeaseRenewable: schema.BoolAttribute{
				MarkdownDescription: "True if the duration of this lease can be extended through renewal.",
				Computed:            true,
			},
		},
		MarkdownDescription: "Provides an ephemeral resource to read a generic secret from Vault.",
	}

	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

// Metadata sets the full name for this resource
func (r *GenericEphemeralSecretResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_generic_secret"
}

func (r *GenericEphemeralSecretResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data GenericEphemeralSecretModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	c, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	path := data.Path.ValueString()

	// Read the secret, handling both versioned and non-versioned secrets
	var secretResp *api.Secret
	if !data.Version.IsNull() && data.Version.ValueInt32() > 0 {
		v := data.Version.ValueInt32()
		queryParams := map[string][]string{
			"version": {strconv.Itoa(int(v))},
		}
		secretResp, err = c.Logical().ReadWithDataWithContext(ctx, path, queryParams)
	} else {
		secretResp, err = c.Logical().ReadWithContext(ctx, path)
	}

	if err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultReadErr(err),
		)
		return
	}

	if secretResp == nil {
		resp.Diagnostics.AddError(
			errutil.VaultReadResponseNil(),
		)
		return
	}

	// Extract the actual data from the response
	// For KV v2, the data is nested: response.Data["data"] contains the actual secret
	// For KV v1 and other engines, the data is directly in response.Data
	var secData map[string]interface{}
	if nestedData, ok := secretResp.Data["data"].(map[string]interface{}); ok {
		// KV v2 format: data is nested under "data" key
		secData = nestedData
	} else {
		// KV v1 or other engines: data is directly in Data
		secData = secretResp.Data
	}

	// Process secret data
	dataMap := make(map[string]string)
	for k, v := range secData {
		if vs, ok := v.(string); ok {
			dataMap[k] = vs
		} else {
			// Serialize non-string values to JSON
			vBytes, err := json.Marshal(v)
			if err != nil {
				resp.Diagnostics.AddError("Error marshalling secret value", err.Error())
				return
			}
			dataMap[k] = string(vBytes)
		}
	}

	mapValue, diag := types.MapValueFrom(ctx, types.StringType, dataMap)
	resp.Diagnostics.Append(diag...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Data = mapValue

	// Marshal entire data to JSON (use the extracted secData, not the raw response)
	jsonData, err := json.Marshal(secData)
	if err != nil {
		resp.Diagnostics.AddError("Error marshalling data to JSON", err.Error())
		return
	}
	data.DataJSON = types.StringValue(string(jsonData))

	// Set lease information
	data.LeaseID = types.StringValue(secretResp.LeaseID)
	data.LeaseDuration = types.Int64Value(int64(secretResp.LeaseDuration))
	data.LeaseRenewable = types.BoolValue(secretResp.Renewable)

	// Set lease_start_time if with_lease_start_time is true
	if !data.WithLeaseStartTime.IsNull() && data.WithLeaseStartTime.ValueBool() {
		data.LeaseStartTime = types.StringValue(time.Now().UTC().Format(time.RFC3339))
	}

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
