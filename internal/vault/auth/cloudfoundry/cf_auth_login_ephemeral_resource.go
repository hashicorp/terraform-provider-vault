// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudfoundry

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
)

const (
	cfLoginPath = "login"
)

// Ensure the implementation satisfies the ephemeral.EphemeralResource interface.
var _ ephemeral.EphemeralResource = &CFAuthLoginEphemeralResource{}

// NewCFAuthLoginEphemeralResource returns the implementation for this ephemeral resource.
func NewCFAuthLoginEphemeralResource() ephemeral.EphemeralResource {
	return &CFAuthLoginEphemeralResource{}
}

// CFAuthLoginEphemeralResource implements the Terraform Plugin Framework ephemeral resource.
type CFAuthLoginEphemeralResource struct {
	base.EphemeralResourceWithConfigure
}

// CFAuthLoginEphemeralModel describes the Terraform resource data model.
type CFAuthLoginEphemeralModel struct {
	base.BaseModelEphemeral

	Mount          types.String `tfsdk:"mount"`
	Role           types.String `tfsdk:"role"`
	CFInstanceCert types.String `tfsdk:"cf_instance_cert"`
	SigningTime    types.String `tfsdk:"signing_time"`
	Signature      types.String `tfsdk:"signature"`

	// Computed outputs
	ClientToken   types.String `tfsdk:"client_token"`
	Accessor      types.String `tfsdk:"accessor"`
	Policies      types.List   `tfsdk:"policies"`
	LeaseDuration types.Int64  `tfsdk:"lease_duration"`
	Renewable     types.Bool   `tfsdk:"renewable"`
}

func (r *CFAuthLoginEphemeralResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cf_auth_login"
}

func (r *CFAuthLoginEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Provides an ephemeral resource to log in to Vault using the CloudFoundry (CF) auth method.",
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Mount path for the CF auth engine in Vault.",
				Optional:            true,
				Computed:            true,
			},
			consts.FieldRole: schema.StringAttribute{
				MarkdownDescription: "Name of the CF auth role to log in with.",
				Required:            true,
			},
			consts.FieldCFInstanceCert: schema.StringAttribute{
				MarkdownDescription: "The full body of the file available at the path denoted by `CF_INSTANCE_CERT`.",
				Required:            true,
				Sensitive:           true,
			},
			consts.FieldSigningTime: schema.StringAttribute{
				MarkdownDescription: "The date and time used to construct the signature (e.g. `2006-01-02T15:04:05Z`).",
				Required:            true,
			},
			consts.FieldSignature: schema.StringAttribute{
				MarkdownDescription: "The RSA-PSS/SHA256 signature generated using `CF_INSTANCE_KEY` over the concatenation of signing_time, cf_instance_cert, and role.",
				Required:            true,
				Sensitive:           true,
			},
			consts.FieldClientToken: schema.StringAttribute{
				MarkdownDescription: "The Vault client token issued after a successful login.",
				Computed:            true,
				Sensitive:           true,
			},
			consts.FieldAccessor: schema.StringAttribute{
				MarkdownDescription: "The accessor for the client token.",
				Computed:            true,
			},
			consts.FieldPolicies: schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "The list of policies attached to the client token.",
				Computed:            true,
			},
			consts.FieldLeaseDuration: schema.Int64Attribute{
				MarkdownDescription: "The lease duration of the client token in seconds.",
				Computed:            true,
			},
			consts.FieldRenewable: schema.BoolAttribute{
				MarkdownDescription: "Whether the client token is renewable.",
				Computed:            true,
			},
		},
	}

	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

func (r *CFAuthLoginEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data CFAuthLoginEphemeralModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Default mount to "cf" if not provided.
	if data.Mount.IsNull() || data.Mount.IsUnknown() {
		data.Mount = types.StringValue("cf")
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	loginPath := fmt.Sprintf("auth/%s/%s", data.Mount.ValueString(), cfLoginPath)

	requestData := map[string]any{
		consts.FieldRole:           data.Role.ValueString(),
		consts.FieldCFInstanceCert: data.CFInstanceCert.ValueString(),
		consts.FieldSigningTime:    data.SigningTime.ValueString(),
		consts.FieldSignature:      data.Signature.ValueString(),
	}

	loginResp, err := vaultClient.Logical().WriteWithContext(ctx, loginPath, requestData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error logging in with CF auth method",
			fmt.Sprintf("Could not log in at path %s: %s", loginPath, err),
		)
		return
	}

	if loginResp == nil || loginResp.Auth == nil {
		resp.Diagnostics.AddError(
			"Empty auth response from Vault",
			fmt.Sprintf("No auth data returned when logging in at path %s", loginPath),
		)
		return
	}

	auth := loginResp.Auth

	data.ClientToken = types.StringValue(auth.ClientToken)
	data.Accessor = types.StringValue(auth.Accessor)
	data.LeaseDuration = types.Int64Value(int64(auth.LeaseDuration))
	data.Renewable = types.BoolValue(auth.Renewable)

	policies, listErr := types.ListValueFrom(ctx, types.StringType, auth.Policies)
	if listErr.HasError() {
		resp.Diagnostics.Append(listErr...)
		return
	}
	data.Policies = policies

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
