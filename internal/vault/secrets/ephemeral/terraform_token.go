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
var _ ephemeral.EphemeralResource = &TerraformTokenEphemeralSecretResource{}

// NewTerraformTokenEphemeralSecretResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
var NewTerraformTokenEphemeralSecretResource = func() ephemeral.EphemeralResource {
	return &TerraformTokenEphemeralSecretResource{}
}

// TerraformTokenEphemeralSecretResource implements the methods that define this resource
type TerraformTokenEphemeralSecretResource struct {
	base.EphemeralResourceWithConfigure
}

// TerraformTokenEphemeralSecretModel describes the Terraform resource data model to match the
// resource schema.
type TerraformTokenEphemeralSecretModel struct {
	// common fields to all ephemeral resources
	base.BaseModelEphemeral

	// fields specific to this resource
	Mount    types.String `tfsdk:"mount"`
	RoleName types.String `tfsdk:"role_name"`
	Token    types.String `tfsdk:"token"`
}

// TerraformTokenEphemeralSecretAPIModel describes the Vault API data model.
type TerraformTokenEphemeralSecretAPIModel struct {
	Token string `json:"token" mapstructure:"token"`
}

type PrivateData struct {
	LeaseID   string `json:"lease_id"`
	Namespace string `json:"namespace,omitempty"` // Optional, used for namespaced resources
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources#schema-method
func (r *TerraformTokenEphemeralSecretResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldRoleName: schema.StringAttribute{
				MarkdownDescription: "Specifies the name of the role to create credentials against. Must be `credential_type=\"team\"`",
				Required:            true,
			},
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Mount path for the Terraform engine in Vault. Default is `terraform`.",
				Optional:            true,
				Computed:            true,
			},
			consts.FieldToken: schema.StringAttribute{
				MarkdownDescription: "Token requested from Vault.",
				Computed:            true,
			},
		},
		MarkdownDescription: "Provides an ephemeral resource to read a Terraform Token from Vault.",
	}

	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

// Metadata sets the full name for this resource
func (r *TerraformTokenEphemeralSecretResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_terraform_token"
}

func (r *TerraformTokenEphemeralSecretResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data TerraformTokenEphemeralSecretModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Default values for optional fields
	if data.Mount.IsNull() || data.Mount.ValueString() == "" {
		data.Mount = types.StringValue("terraform")
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

	var readResp TerraformTokenEphemeralSecretAPIModel
	err = model.ToAPIModel(secretResp.Data, &readResp)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	data.Token = types.StringValue(readResp.Token)
	privateData, _ := json.Marshal(PrivateData{
		LeaseID:   secretResp.LeaseID,
		Namespace: data.Namespace.ValueString()})
	resp.Private.SetKey(ctx, "private_data", privateData)

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}

func (r *TerraformTokenEphemeralSecretResource) path(mount, roleName string) string {
	return fmt.Sprintf("/%s/creds/%s", mount, roleName)
}

func (e *TerraformTokenEphemeralSecretResource) Close(ctx context.Context, req ephemeral.CloseRequest, resp *ephemeral.CloseResponse) {
	privateBytes, diags := req.Private.GetKey(ctx, "private_data")
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var privateData PrivateData
	json.Unmarshal(privateBytes, &privateData)
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
		resp.Diagnostics.AddError(
			"Token will not be revoked as no LeaseID was provided. This is a problem with the provider.",
			"Token will not be revoked as no LeaseID was provided. This is a problem with the provider.",
		)
	}
}
