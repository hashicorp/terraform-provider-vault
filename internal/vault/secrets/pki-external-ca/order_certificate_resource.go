// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki_external_ca

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
)

const certificateAffix = "certificate"

var certificateIDRe = regexp.MustCompile(`^([^/]+)/role/([^/]+)/order/([^/]+)/` + certificateAffix + `$`)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &PKIExternalCAOrderCertificateResource{}

// NewPKIExternalCAOrderCertificateResource returns the implementation for this resource
func NewPKIExternalCAOrderCertificateResource() resource.Resource {
	return &PKIExternalCAOrderCertificateResource{}
}

// PKIExternalCAOrderCertificateResource implements the methods that define this resource
type PKIExternalCAOrderCertificateResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

// PKIExternalCAOrderCertificateModel describes the Terraform resource data model
type PKIExternalCAOrderCertificateModel struct {
	base.BaseModel

	Mount    types.String `tfsdk:"mount"`
	RoleName types.String `tfsdk:"role_name"`
	OrderID  types.String `tfsdk:"order_id"`

	// Computed fields from certificate fetch
	Certificate  types.String `tfsdk:"certificate"`
	CAChain      types.List   `tfsdk:"ca_chain"`
	PrivateKey   types.String `tfsdk:"private_key"`
	SerialNumber types.String `tfsdk:"serial_number"`
}

// PKIExternalCAOrderCertificateAPIModel describes the Vault API data model for certificate fetch
type PKIExternalCAOrderCertificateAPIModel struct {
	Certificate  string   `json:"certificate" mapstructure:"certificate"`
	CAChain      []string `json:"ca_chain" mapstructure:"ca_chain"`
	PrivateKey   string   `json:"private_key" mapstructure:"private_key"`
	SerialNumber string   `json:"serial_number" mapstructure:"serial_number"`
}

func (r *PKIExternalCAOrderCertificateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pki_secret_backend_external_ca_order_certificate"
}

func (r *PKIExternalCAOrderCertificateResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "The path where the PKI External CA secret backend is mounted.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"role_name": schema.StringAttribute{
				MarkdownDescription: "Name of the role associated with the order.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"order_id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier for the ACME order.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"certificate": schema.StringAttribute{
				MarkdownDescription: "The PEM-encoded certificate.",
				Computed:            true,
			},
			"ca_chain": schema.ListAttribute{
				MarkdownDescription: "The PEM-encoded certificate chain.",
				ElementType:         types.StringType,
				Computed:            true,
			},
			"private_key": schema.StringAttribute{
				MarkdownDescription: "The PEM-encoded private key.",
				Computed:            true,
				Sensitive:           true,
			},
			"serial_number": schema.StringAttribute{
				MarkdownDescription: "The serial number of the issued certificate.",
				Computed:            true,
			},
		},
		MarkdownDescription: "Polls the order status endpoint until the order is completed, then fetches the certificate.",
	}
	base.MustAddBaseSchema(&resp.Schema)
}

// Create is called during the terraform apply command.
func (r *PKIExternalCAOrderCertificateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PKIExternalCAOrderCertificateModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check Vault version
	if err := checkVaultVersion(r.Meta()); err != nil {
		resp.Diagnostics.AddError("Vault Version Check Failed", err.Error())
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mount := data.Mount.ValueString()
	roleName := data.RoleName.ValueString()
	orderID := data.OrderID.ValueString()

	// Poll the order status endpoint until it reaches Completed
	if err := pollOrderStatus(ctx, cli, mount, roleName, orderID, 30, 2*time.Second, []string{"completed"}); err != nil {
		resp.Diagnostics.AddError(
			"Order status not awaiting-challenge-fulfillment",
			err.Error())
		return
	}

	// Fetch the certificate
	certPath := fmt.Sprintf("%s/role/%s/order/%s/fetch-cert", mount, roleName, orderID)
	certResp, err := cli.Logical().ReadWithContext(ctx, certPath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}

	if certResp == nil || certResp.Data == nil {
		resp.Diagnostics.AddError("Unexpected Response", "No data returned from fetch-cert endpoint")
		return
	}

	var apiModel PKIExternalCAOrderCertificateAPIModel
	err = model.ToAPIModel(certResp.Data, &apiModel)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Map values to Terraform model
	var diags diag.Diagnostics
	data.Certificate = types.StringValue(apiModel.Certificate)
	data.CAChain, diags = types.ListValueFrom(ctx, types.StringType, apiModel.CAChain)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.SerialNumber = types.StringValue(apiModel.SerialNumber)

	// Private key may or may not be present
	if apiModel.PrivateKey != "" {
		data.PrivateKey = types.StringValue(apiModel.PrivateKey)
	} else {
		data.PrivateKey = types.StringNull()
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during the terraform apply, terraform plan, and terraform refresh commands.
func (r *PKIExternalCAOrderCertificateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PKIExternalCAOrderCertificateModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mount := data.Mount.ValueString()
	roleName := data.RoleName.ValueString()
	orderID := data.OrderID.ValueString()

	// Try to fetch the certificate again
	certPath := fmt.Sprintf("%s/role/%s/order/%s/fetch-cert", mount, roleName, orderID)
	certResp, err := cli.Logical().ReadWithContext(ctx, certPath)
	if err != nil {
		// If we can't read it, just keep the existing state
		resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
		return
	}

	if certResp == nil || certResp.Data == nil {
		// Certificate might have expired or been removed, keep existing state
		resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
		return
	}

	var apiModel PKIExternalCAOrderCertificateAPIModel
	err = model.ToAPIModel(certResp.Data, &apiModel)
	if err != nil {
		// Keep existing state on error
		resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
		return
	}

	// Update the model with fresh data
	data.Certificate = types.StringValue(apiModel.Certificate)
	var diags diag.Diagnostics
	data.Certificate = types.StringValue(apiModel.Certificate)
	data.CAChain, diags = types.ListValueFrom(ctx, types.StringType, apiModel.CAChain)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.SerialNumber = types.StringValue(apiModel.SerialNumber)

	if apiModel.PrivateKey != "" {
		data.PrivateKey = types.StringValue(apiModel.PrivateKey)
	} else {
		data.PrivateKey = types.StringNull()
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PKIExternalCAOrderCertificateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// All fields require replacement, so this should never be called
	var data PKIExternalCAOrderCertificateModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PKIExternalCAOrderCertificateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Certificates cannot be revoked through this resource
	// Just remove from state
}

func (r *PKIExternalCAOrderCertificateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	matches := certificateIDRe.FindStringSubmatch(req.ID)
	if len(matches) != 4 {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Import ID must be in the format '<mount>/role/<role_name>/order/<order_id>/%s', got: %s",
				certificateAffix, req.ID),
		)
		return
	}

	mount := matches[1]
	roleName := matches[2]
	orderID := matches[3]

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mount)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("role_name"), roleName)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("order_id"), orderID)...)
}
