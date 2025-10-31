// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets

import (
	"context"
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
)

const fieldCombinedRoleMetadata = "combined_role_metadata"

var _ ephemeral.EphemeralResource = &AzureStaticCredsEphemeralSecretResource{}

var NewAzureStaticCredsEphemeralSecretResource = func() ephemeral.EphemeralResource {
	return &AzureStaticCredsEphemeralSecretResource{}
}

type AzureStaticCredsEphemeralSecretResource struct {
	base.EphemeralResourceWithConfigure
}

type AzureStaticCredsEphemeralSecretModel struct {
	base.BaseModelEphemeral

	Backend  types.String `tfsdk:"backend"`
	Role     types.String `tfsdk:"role"`
	Metadata types.Map    `tfsdk:"metadata"`

	ClientID             types.String `tfsdk:"client_id"`
	ClientSecret         types.String `tfsdk:"client_secret"`
	SecretID             types.String `tfsdk:"secret_id"`
	Expiration           types.String `tfsdk:"expiration"`
	CombinedRoleMetadata types.Map    `tfsdk:"combined_role_metadata"`
}

type AzureStaticCredsAPIModel struct {
	ClientID     string            `json:"client_id" mapstructure:"client_id"`
	ClientSecret string            `json:"client_secret" mapstructure:"client_secret"`
	SecretID     string            `json:"secret_id" mapstructure:"secret_id"`
	Metadata     map[string]string `json:"metadata" mapstructure:"metadata"`
	Expiration   any               `json:"expiration" mapstructure:"expiration"`
}

func (r *AzureStaticCredsEphemeralSecretResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldBackend: schema.StringAttribute{
				MarkdownDescription: "Azure Secret Backend to read credentials from.",
				Required:            true,
			},
			consts.FieldRole: schema.StringAttribute{
				MarkdownDescription: "Static role name to fetch credentials for.",
				Required:            true,
			},

			consts.FieldMetadata: schema.MapAttribute{
				MarkdownDescription: "Metadata to pass along with the read request.",
				ElementType:         types.StringType,
				Optional:            true,
			},
			consts.FieldClientID: schema.StringAttribute{
				MarkdownDescription: "Client ID of the Azure application.",
				Computed:            true,
			},
			consts.FieldClientSecret: schema.StringAttribute{
				MarkdownDescription: "Client secret of the Azure application.",
				Computed:            true,
				Sensitive:           true,
			},
			consts.FieldSecretID: schema.StringAttribute{
				MarkdownDescription: "Secret ID of the Azure application.",
				Computed:            true,
			},
			consts.FieldExpiration: schema.StringAttribute{
				MarkdownDescription: "Credential expiration time (RFC3339).",
				Computed:            true,
			},
			fieldCombinedRoleMetadata: schema.MapAttribute{
				MarkdownDescription: "Merged metadata returned by Vault (role + request metadata; role takes precedence).",
				ElementType:         types.StringType,
				Computed:            true,
			},
		},
		MarkdownDescription: "Ephemeral: reads Azure static credentials from `/<backend>/static-creds/<role>`. " +
			"`metadata` is input-only and sent with the request; `combined_role_metadata` is the merged map returned by Vault.",
	}
	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

func (r *AzureStaticCredsEphemeralSecretResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_static_credentials"
}

func (r *AzureStaticCredsEphemeralSecretResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data AzureStaticCredsEphemeralSecretModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	c, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	path := fmt.Sprintf("%s/static-creds/%s", data.Backend.ValueString(), data.Role.ValueString())

	var readData map[string][]string
	if !data.Metadata.IsNull() && !data.Metadata.IsUnknown() {
		var inMeta map[string]string
		if md := data.Metadata.ElementsAs(ctx, &inMeta, false); md.HasError() {
			resp.Diagnostics.Append(md...)
			return
		}
		if len(inMeta) > 0 {
			kvPairs := make([]string, 0, len(inMeta))
			for k, v := range inMeta {
				kvPairs = append(kvPairs, fmt.Sprintf("%s=%s", k, v))
			}
			readData = map[string][]string{"metadata": kvPairs}
		}
	}

	var sec *api.Secret
	if readData != nil {
		sec, err = c.Logical().ReadWithData(path, readData)
	} else {
		sec, err = c.Logical().Read(path)
	}
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if sec == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	var apiResp AzureStaticCredsAPIModel
	if err := model.ToAPIModel(sec.Data, &apiResp); err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	data.ClientID = types.StringValue(apiResp.ClientID)
	data.ClientSecret = types.StringValue(apiResp.ClientSecret)
	data.SecretID = types.StringValue(apiResp.SecretID)
	data.Expiration = types.StringValue(apiResp.Expiration.(string))
	metaVal, md := types.MapValueFrom(ctx, types.StringType, apiResp.Metadata)
	resp.Diagnostics.Append(md...)
	data.CombinedRoleMetadata = metaVal

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
