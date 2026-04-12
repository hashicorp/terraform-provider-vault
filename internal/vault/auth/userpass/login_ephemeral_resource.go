// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package userpass

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

const (
	userpassLoginPath       = "login"
	userpassPrivateDataKey  = "userpass_data"
	userpassAuthPathPattern = "auth/%s/%s/%s"
)

var _ ephemeral.EphemeralResource = &UserpassAuthLoginEphemeralResource{}
var _ ephemeral.EphemeralResourceWithClose = &UserpassAuthLoginEphemeralResource{}

// NewUserpassAuthLoginEphemeralResource returns the Userpass login ephemeral resource implementation.
func NewUserpassAuthLoginEphemeralResource() ephemeral.EphemeralResource {
	return &UserpassAuthLoginEphemeralResource{}
}

type UserpassAuthLoginEphemeralResource struct {
	base.EphemeralResourceWithConfigure
}

type userpassPrivateData struct {
	Accessor  string `json:"accessor"`
	Namespace string `json:"namespace"`
}

func getUserpassMount(mount types.String) string {
	if mount.IsNull() || mount.IsUnknown() {
		return consts.MountTypeUserpass
	}

	return mount.ValueString()
}

func getUserpassLoginPath(mount, username string) string {
	return fmt.Sprintf(userpassAuthPathPattern, mount, userpassLoginPath, username)
}

func marshalUserpassPrivateData(data userpassPrivateData) ([]byte, error) {
	return json.Marshal(data)
}

func unmarshalUserpassPrivateData(privateBytes []byte) (userpassPrivateData, error) {
	var privateData userpassPrivateData
	if err := json.Unmarshal(privateBytes, &privateData); err != nil {
		return userpassPrivateData{}, err
	}

	return privateData, nil
}

type UserpassAuthLoginEphemeralModel struct {
	base.BaseModelEphemeral

	Mount    types.String `tfsdk:"mount"`
	Username types.String `tfsdk:"username"`
	Password types.String `tfsdk:"password"`

	ClientToken   types.String `tfsdk:"client_token"`
	Accessor      types.String `tfsdk:"accessor"`
	Policies      types.List   `tfsdk:"policies"`
	LeaseDuration types.Int64  `tfsdk:"lease_duration"`
	Renewable     types.Bool   `tfsdk:"renewable"`
}

// Metadata sets the Terraform type name for this ephemeral resource.
func (r *UserpassAuthLoginEphemeralResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_userpass_auth_login"
}

// Schema defines input and computed attributes for Userpass login.
func (r *UserpassAuthLoginEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Provides an ephemeral resource to log in to Vault using the Userpass auth method.",
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "Mount path for the Userpass auth engine in Vault.",
				Required:            true,
			},
			consts.FieldUsername: schema.StringAttribute{
				MarkdownDescription: "Username to log in with.",
				Required:            true,
			},
			consts.FieldPassword: schema.StringAttribute{
				MarkdownDescription: "Password to log in with.",
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

// Open performs the login request and exposes token data for downstream ephemeral usage.
func (r *UserpassAuthLoginEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data UserpassAuthLoginEphemeralModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.Mount = types.StringValue(getUserpassMount(data.Mount))

	vaultClient, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	loginPath := getUserpassLoginPath(data.Mount.ValueString(), data.Username.ValueString())
	requestData := map[string]any{
		consts.FieldPassword: data.Password.ValueString(),
	}

	loginResp, err := vaultClient.Logical().WriteWithContext(ctx, loginPath, requestData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error logging in with Userpass auth method",
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

	if auth.Accessor != "" {
		privateDataJSON, err := marshalUserpassPrivateData(userpassPrivateData{
			Accessor:  auth.Accessor,
			Namespace: data.Namespace.ValueString(),
		})
		if err != nil {
			resp.Diagnostics.AddError(
				"Error encoding private data",
				err.Error(),
			)
			return
		}

		resp.Private.SetKey(ctx, userpassPrivateDataKey, privateDataJSON)
	}

	// Clear sensitive input fields before setting the result to prevent exposure
	data.Password = types.StringNull()

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}

func (r *UserpassAuthLoginEphemeralResource) Close(ctx context.Context, req ephemeral.CloseRequest, resp *ephemeral.CloseResponse) {
	privateBytes, diags := req.Private.GetKey(ctx, userpassPrivateDataKey)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(privateBytes) == 0 {
		return
	}

	privateData, err := unmarshalUserpassPrivateData(privateBytes)
	if err != nil {
		tflog.Warn(ctx, fmt.Sprintf("Failed to unmarshal private data: %v", err))
		return
	}

	if privateData.Accessor == "" {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), privateData.Namespace)
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	err = vaultClient.Auth().Token().RevokeAccessor(privateData.Accessor)
	if err != nil {
		tflog.Warn(ctx, fmt.Sprintf("Failed to revoke token with accessor %s: %v", privateData.Accessor, err))
		return
	}

	tflog.Info(ctx, fmt.Sprintf("Successfully revoked Userpass token with accessor: %s", privateData.Accessor))
}
