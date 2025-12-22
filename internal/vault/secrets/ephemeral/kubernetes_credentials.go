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
)

// Ensure the implementation satisfies the ephemeral.EphemeralResource interface
var _ ephemeral.EphemeralResource = &KubernetesServiceAccountTokenEphemeralResource{}

// NewKubernetesServiceAccountTokenEphemeralResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
var NewKubernetesServiceAccountTokenEphemeralResource = func() ephemeral.EphemeralResource {
	return &KubernetesServiceAccountTokenEphemeralResource{}
}

// KubernetesServiceAccountTokenEphemeralResource implements the methods that define this resource
type KubernetesServiceAccountTokenEphemeralResource struct {
	base.EphemeralResourceWithConfigure
}

// KubernetesServiceAccountTokenModel describes the Terraform resource data model to match the
// resource schema.
type KubernetesServiceAccountTokenModel struct {
	// common fields to all ephemeral resources
	base.BaseModelEphemeral

	// fields specific to this resource
	Backend                 types.String `tfsdk:"backend"`
	Role                    types.String `tfsdk:"role"`
	KubernetesNamespace     types.String `tfsdk:"kubernetes_namespace"`
	ClusterRoleBinding      types.Bool   `tfsdk:"cluster_role_binding"`
	TTL                     types.String `tfsdk:"ttl"`
	ServiceAccountName      types.String `tfsdk:"service_account_name"`
	ServiceAccountNamespace types.String `tfsdk:"service_account_namespace"`
	ServiceAccountToken     types.String `tfsdk:"service_account_token"`
	LeaseID                 types.String `tfsdk:"lease_id"`
	LeaseDuration           types.Int64  `tfsdk:"lease_duration"`
	LeaseRenewable          types.Bool   `tfsdk:"lease_renewable"`
}

// KubernetesServiceAccountTokenAPIModel describes the Vault API data model.
type KubernetesServiceAccountTokenAPIModel struct {
	ServiceAccountName      string `json:"service_account_name" mapstructure:"service_account_name"`
	ServiceAccountNamespace string `json:"service_account_namespace" mapstructure:"service_account_namespace"`
	ServiceAccountToken     string `json:"service_account_token" mapstructure:"service_account_token"`
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources#schema-method
func (r *KubernetesServiceAccountTokenEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldBackend: schema.StringAttribute{
				MarkdownDescription: "The Kubernetes secret backend to generate service account tokens from.",
				Required:            true,
			},
			consts.FieldRole: schema.StringAttribute{
				MarkdownDescription: "The name of the role.",
				Required:            true,
			},
			consts.FieldKubernetesNamespace: schema.StringAttribute{
				MarkdownDescription: "The name of the Kubernetes namespace in which to generate the credentials.",
				Required:            true,
			},
			consts.FieldClusterRoleBinding: schema.BoolAttribute{
				MarkdownDescription: "If true, generate a ClusterRoleBinding to grant permissions across the whole cluster instead of within a namespace.",
				Optional:            true,
			},
			consts.FieldTTL: schema.StringAttribute{
				MarkdownDescription: "The TTL of the generated Kubernetes service account token, specified in seconds or as a Go duration format string.",
				Optional:            true,
			},
			consts.FieldServiceAccountName: schema.StringAttribute{
				MarkdownDescription: "The name of the service account associated with the token.",
				Computed:            true,
			},
			consts.FieldServiceAccountNamespace: schema.StringAttribute{
				MarkdownDescription: "The Kubernetes namespace that the service account resides in.",
				Computed:            true,
			},
			consts.FieldServiceAccountToken: schema.StringAttribute{
				MarkdownDescription: "The Kubernetes service account token.",
				Computed:            true,
				Sensitive:           true,
			},
			consts.FieldLeaseID: schema.StringAttribute{
				MarkdownDescription: "The lease identifier assigned by Vault.",
				Computed:            true,
			},
			consts.FieldLeaseDuration: schema.Int64Attribute{
				MarkdownDescription: "The duration of the lease in seconds.",
				Computed:            true,
			},
			consts.FieldLeaseRenewable: schema.BoolAttribute{
				MarkdownDescription: "True if the duration of this lease can be extended through renewal.",
				Computed:            true,
			},
		},
		MarkdownDescription: "Provides an ephemeral resource to generate Kubernetes service account tokens from Vault.",
	}

	base.MustAddBaseEphemeralSchema(&resp.Schema)
}

// Metadata sets the full name for this resource
func (r *KubernetesServiceAccountTokenEphemeralResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_kubernetes_service_account_token"
}

func (r *KubernetesServiceAccountTokenEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data KubernetesServiceAccountTokenModel
	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	c, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Prepare the request data
	requestData := make(map[string]interface{})
	requestData[consts.FieldKubernetesNamespace] = data.KubernetesNamespace.ValueString()

	if !data.ClusterRoleBinding.IsNull() {
		requestData[consts.FieldClusterRoleBinding] = data.ClusterRoleBinding.ValueBool()
	}

	if !data.TTL.IsNull() {
		requestData[consts.FieldTTL] = data.TTL.ValueString()
	}

	path := r.path(data.Backend.ValueString(), data.Role.ValueString())

	secretResp, err := c.Logical().WriteWithContext(ctx, path, requestData)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to generate Kubernetes service account token",
			err.Error(),
		)
		return
	}

	if secretResp == nil {
		resp.Diagnostics.AddError(
			"Vault API returned no data",
			fmt.Sprintf("No role found at %q", path),
		)
		return
	}

	var readResp KubernetesServiceAccountTokenAPIModel
	err = model.ToAPIModel(secretResp.Data, &readResp)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	data.ServiceAccountName = types.StringValue(readResp.ServiceAccountName)
	data.ServiceAccountNamespace = types.StringValue(readResp.ServiceAccountNamespace)
	data.ServiceAccountToken = types.StringValue(readResp.ServiceAccountToken)
	data.LeaseID = types.StringValue(secretResp.LeaseID)
	data.LeaseDuration = types.Int64Value(int64(secretResp.LeaseDuration))
	data.LeaseRenewable = types.BoolValue(secretResp.Renewable)

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}

func (r *KubernetesServiceAccountTokenEphemeralResource) path(backend, role string) string {
	return fmt.Sprintf("%s/creds/%s", backend, role)
}
