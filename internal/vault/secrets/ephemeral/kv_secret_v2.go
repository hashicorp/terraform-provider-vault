// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/vault/api"
	"strconv"
)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ ephemeral.EphemeralResource = &KVV2EphemeralSecretResource{}

// NewKVV2EphemeralSecretResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
var NewKVV2EphemeralSecretResource = func() ephemeral.EphemeralResource {
	return &KVV2EphemeralSecretResource{}
}

// KVV2EphemeralSecretResource implements the methods that define this resource
type KVV2EphemeralSecretResource struct {
	base.EphemeralResourceWithConfigure
}

// KVV2EphemeralSecretModel describes the Terraform resource data model to match the
// resource schema.
type KVV2EphemeralSecretModel struct {
	// common fields to all ephemeral resources
	base.BaseModelEphemeral

	// fields specific to this resource
	Mount          types.String `tfsdk:"mount"`
	Name           types.String `tfsdk:"name"`
	Version        types.Int32  `tfsdk:"version"`
	DataJSON       types.String `tfsdk:"data_json"`
	Data           types.Map    `tfsdk:"data"`
	CustomMetadata types.Map    `tfsdk:"custom_metadata"`
	CreatedTime    types.String `tfsdk:"created_time"`
	DeletionTime   types.String `tfsdk:"deletion_time"`
	Destroyed      types.Bool   `tfsdk:"destroyed"`
}

// KVV2EphemeralSecretAPIModel describes the Vault API data model.
type KVV2EphemeralSecretAPIModel struct {
	Data     map[string]interface{} `json:"data" mapstructure:"data"`
	Metadata Metadata               `json:"metadata" mapstructure:"metadata"`
}

type Metadata struct {
	CustomMetadata map[string]interface{} `json:"custom_metadata" mapstructure:"custom_metadata"`
	CreatedTime    string                 `json:"created_time" mapstructure:"created_time"`
	DeletionTime   string                 `json:"deletion_time" mapstructure:"deletion_time"`
	Destroyed      bool                   `json:"destroyed" mapstructure:"destroyed"`
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources#schema-method
func (r *KVV2EphemeralSecretResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Mount path for the KVV2 engine in Vault.",
				Required:            true,
			},
			consts.FieldName: schema.StringAttribute{
				MarkdownDescription: "Full name of the secret.",
				Required:            true,
			},
			consts.FieldVersion: schema.Int32Attribute{
				Optional:            true,
				MarkdownDescription: "Version of the secret to retrieve.",
			},
			consts.FieldDataJSON: schema.StringAttribute{
				MarkdownDescription: "JSON-encoded secret data read from Vault.",
				Computed:            true,
			},
			consts.FieldData: schema.MapAttribute{
				MarkdownDescription: "Map of strings read from Vault.",
				ElementType:         types.StringType,
				Computed:            true,
			},
			consts.FieldCreatedTime: schema.StringAttribute{
				MarkdownDescription: "Time at which the secret was created.",
				Computed:            true,
			},
			consts.FieldDeletionTime: schema.StringAttribute{
				MarkdownDescription: "Deletion time for the secret.",
				Computed:            true,
			},
			consts.FieldDestroyed: schema.BoolAttribute{
				MarkdownDescription: "Indicates whether the secret has been destroyed.",
				Computed:            true,
			},
			consts.FieldCustomMetadata: schema.MapAttribute{
				MarkdownDescription: "Custom metadata for the secret.",
				ElementType:         types.StringType,
				Computed:            true,
			},
		},
		MarkdownDescription: "Provides an ephemeral resource to read a KVV2 Secret from Vault.",
	}

	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

// Metadata sets the full name for this resource
func (r *KVV2EphemeralSecretResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_kv_secret_v2"
}

func (r *KVV2EphemeralSecretResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data KVV2EphemeralSecretModel
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

	// read the name from the id field to support the import command
	path := r.path(data.Mount.ValueString(), data.Name.ValueString())

	var secretResp *api.Secret
	if !data.Version.IsNull() {
		v := data.Version.ValueInt32()

		d := map[string][]string{
			"version": {strconv.Itoa(int(v))},
		}
		secretResp, err = c.Logical().ReadWithDataWithContext(ctx, path, d)
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

	var readResp KVV2EphemeralSecretAPIModel
	err = model.ToAPIModel(secretResp.Data, &readResp)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	data.CreatedTime = types.StringValue(readResp.Metadata.CreatedTime)
	data.DeletionTime = types.StringValue(readResp.Metadata.DeletionTime)
	data.Destroyed = types.BoolValue(readResp.Metadata.Destroyed)

	secretData, diag := types.MapValueFrom(ctx, types.StringType, readResp.Data)
	resp.Diagnostics.Append(diag...)
	data.Data = secretData

	jsonData, err := json.Marshal(data.Data)
	if err != nil {
		resp.Diagnostics.AddError("Error marshalling data to JSON", err.Error())
	}

	data.DataJSON = types.StringValue(string(jsonData))

	secretCustomMetadata, diag := types.MapValueFrom(ctx, types.StringType, readResp.Metadata.CustomMetadata)
	resp.Diagnostics.Append(diag...)
	data.CustomMetadata = secretCustomMetadata

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}

func (r *KVV2EphemeralSecretResource) path(mount, name string) string {
	return fmt.Sprintf("%s/data/%s", mount, name)
}
