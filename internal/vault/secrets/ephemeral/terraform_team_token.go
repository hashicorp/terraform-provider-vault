// Copyright (c) HashiCorp, Inc.
// SPDX-License-IDentifier: MPL-2.0

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
)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ ephemeral.EphemeralResource = &TerraformTeamTokenEphemeralSecretResource{}

// NewTerraformTeamTokenEphemeralSecretResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
var NewTerraformTeamTokenEphemeralSecretResource = func() ephemeral.EphemeralResource {
	return &TerraformTeamTokenEphemeralSecretResource{}
}

// TerraformTeamTokenEphemeralSecretResource implements the methods that define this resource
type TerraformTeamTokenEphemeralSecretResource struct {
	base.EphemeralResourceWithConfigure
}

// TerraformTeamTokenEphemeralSecretModel describes the Terraform resource data model to match the
// resource schema.
type TerraformTeamTokenEphemeralSecretModel struct {
	// common fields to all ephemeral resources
	base.BaseModelEphemeral

	// fields specific to this resource
	Mount         types.String `tfsdk:"mount"`
	RoleName      types.String `tfsdk:"role_name"`
	Token         types.String `tfsdk:"token"`
	RevokeOnClose types.Bool   `tfsdk:"revoke_on_close"`
}

// TerraformTeamTokenEphemeralSecretAPIModel describes the Vault API data model.
type TerraformTeamTokenEphemeralSecretAPIModel struct {
	Token string `json:"token" mapstructure:"token"`
}

type PrivateData struct {
	LeaseID       string `json:"lease_id"`
	RevokeOnClose bool   `json:"revoke_on_close"`
	Namespace     string `json:"namespace,omitempty"` // Optional, used for namespaced resources
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources#schema-method
func (r *TerraformTeamTokenEphemeralSecretResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldRoleName: schema.StringAttribute{
				MarkdownDescription: "Specifies the name of the role to create credentials against. Must be `credential_type=\"team\"`",
				Required:            true,
			},
			"revoke_on_close": schema.BoolAttribute{
				MarkdownDescription: "If set to `true`, the token will be revoked when the provider is closed. This behavior may be different for plan/apply using `terraform.applying`. If `false` the token will live past the terraform run relevant to the MaxTTL. Defaults to `true`.",
				Optional:            true,
			},
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Mount path for the Terraform engine in Vault. Default is `terraform`.",
				Optional:            true,
			},
			consts.FieldToken: schema.StringAttribute{
				MarkdownDescription: "Token requested from Vault.",
				Computed:            true,
			},
		},
		MarkdownDescription: "Provides an ephemeral resource to read a Terraform Team Token from Vault.",
	}

	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

// Metadata sets the full name for this resource
func (r *TerraformTeamTokenEphemeralSecretResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_terraform_team_token"
}

func (r *TerraformTeamTokenEphemeralSecretResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data TerraformTeamTokenEphemeralSecretModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if data.Mount.IsNull() || data.Mount.ValueString() == "" {
		data.Mount = types.StringValue("terraform")
	}
	if data.RevokeOnClose.IsNull() {
		data.RevokeOnClose = types.BoolValue(true)
	}

	c, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	path := r.path(data.Mount.ValueString(), data.RoleName.ValueString())

	secretResp, err := c.Logical().ReadWithContext(ctx, path)
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

	var readResp TerraformTeamTokenEphemeralSecretAPIModel
	err = model.ToAPIModel(secretResp.Data, &readResp)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// TODO set default values for
	// RevokeOnClose
	// Mount

	data.Token = types.StringValue(readResp.Token)
	privateData, _ := json.Marshal(PrivateData{
		LeaseID:       secretResp.LeaseID,
		RevokeOnClose: data.RevokeOnClose.ValueBool(),
		Namespace:     data.Namespace.ValueString()})
	resp.Private.SetKey(ctx, "private_data", privateData)

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}

func (r *TerraformTeamTokenEphemeralSecretResource) path(mount, roleName string) string {
	return fmt.Sprintf("/%s/creds/%s", mount, roleName)
}

func (e *TerraformTeamTokenEphemeralSecretResource) Close(ctx context.Context, req ephemeral.CloseRequest, resp *ephemeral.CloseResponse) {
	privateBytes, diags := req.Private.GetKey(ctx, "private_data")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Unmarshal private data (error handling omitted for brevity).
	var privateData PrivateData
	json.Unmarshal(privateBytes, &privateData)
	if privateData.RevokeOnClose {
		c, err := client.GetClient(ctx, e.Meta(), privateData.Namespace)
		if err != nil {
			resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
			return
		}
		if privateData.LeaseID != "" {
			// Revoke the token using the LeaseID
			err = c.Sys().RevokeWithContext(ctx, privateData.LeaseID)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error revoking token",
					err.Error(),
				)
				return
			}
		} else {
			resp.Diagnostics.AddWarning(
				"RevokeOnClose is set but no LeaseID found",
				"Token will not be revoked as no LeaseID was provided.",
			)
		}
	}

	// Perform external call to close/clean up "thing" data
}
