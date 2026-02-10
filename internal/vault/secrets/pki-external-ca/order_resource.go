// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki_external_ca

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
)

const orderAffix = "order"

var orderIDRe = regexp.MustCompile(`^([^/]+)/role/([^/]+)/` + orderAffix + `/([^/]+)$`)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &PKIExternalCAOrderResource{}

// NewPKIExternalCAOrderResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewPKIExternalCAOrderResource() resource.Resource {
	return &PKIExternalCAOrderResource{}
}

// PKIExternalCAOrderResource implements the methods that define this resource
type PKIExternalCAOrderResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

// PKIExternalCAOrderModel describes the Terraform resource data model to match the
// resource schema.
type PKIExternalCAOrderModel struct {
	base.BaseModelLegacy

	Mount       types.String `tfsdk:"mount"`
	RoleName    types.String `tfsdk:"role_name"`
	OrderID     types.String `tfsdk:"order_id"`
	Identifiers types.List   `tfsdk:"identifiers"`
	CSR         types.String `tfsdk:"csr"`

	// Computed fields from order status
	OrderStatus  types.String `tfsdk:"order_status"`
	CreationDate types.String `tfsdk:"creation_date"`
	NextWorkDate types.String `tfsdk:"next_work_date"`
	LastUpdate   types.String `tfsdk:"last_update"`
	LastError    types.String `tfsdk:"last_error"`
	SerialNumber types.String `tfsdk:"serial_number"`
	Expires      types.String `tfsdk:"expires"`
	Challenges   types.Map    `tfsdk:"challenges"`
}

// PKIExternalCAOrderAPIModel describes the Vault API data model for order status.
type PKIExternalCAOrderAPIModel struct {
	OrderStatus  string                         `json:"order_status" mapstructure:"order_status"`
	RoleName     string                         `json:"role_name" mapstructure:"role_name"`
	Identifiers  []string                       `json:"identifiers" mapstructure:"identifiers"`
	CreationDate string                         `json:"creation_date" mapstructure:"creation_date"`
	NextWorkDate string                         `json:"next_work_date" mapstructure:"next_work_date"`
	LastUpdate   string                         `json:"last_update" mapstructure:"last_update"`
	LastError    string                         `json:"last_error" mapstructure:"last_error"`
	SerialNumber string                         `json:"serial_number" mapstructure:"serial_number"`
	Expires      string                         `json:"expires" mapstructure:"expires"`
	CSR          string                         `json:"csr" mapstructure:"csr"`
	Challenges   map[string][]map[string]string `json:"challenges" mapstructure:"challenges"`
}

func (r *PKIExternalCAOrderResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pki_secret_backend_external_ca_order"
}

func (r *PKIExternalCAOrderResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				MarkdownDescription: "The path where the PKI External CA secret backend is mounted.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"role_name": schema.StringAttribute{
				MarkdownDescription: "Name of the role to create the order for.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"identifiers": schema.ListAttribute{
				MarkdownDescription: "List of identifiers (domain names) for the certificate order. Required if `csr` is not provided. Mutually exclusive with `csr`.",
				ElementType:         types.StringType,
				Optional:            true,
				Computed:            true,
				PlanModifiers:       []planmodifier.List{},
			},
			"csr": schema.StringAttribute{
				MarkdownDescription: "PEM-encoded Certificate Signing Request containing identifiers. Required if `identifiers` is not provided. Mutually exclusive with `identifiers`.",
				Optional:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"order_id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier for this ACME order.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"order_status": schema.StringAttribute{
				MarkdownDescription: "Current status of the order (e.g., new, submitted, completed, error).",
				Computed:            true,
			},
			"creation_date": schema.StringAttribute{
				MarkdownDescription: "The date and time the order was created in RFC3339 format.",
				Computed:            true,
			},
			"next_work_date": schema.StringAttribute{
				MarkdownDescription: "The next scheduled work date for this order in RFC3339 format.",
				Computed:            true,
			},
			"last_update": schema.StringAttribute{
				MarkdownDescription: "The date and time the order was last updated in RFC3339 format.",
				Computed:            true,
			},
			"last_error": schema.StringAttribute{
				MarkdownDescription: "The last error message encountered during order processing.",
				Computed:            true,
			},
			"serial_number": schema.StringAttribute{
				MarkdownDescription: "The serial number of the issued certificate (available when order is completed).",
				Computed:            true,
			},
			"expires": schema.StringAttribute{
				MarkdownDescription: "The expiration date of the order in RFC3339 format.",
				Computed:            true,
			},
			"challenges": schema.MapAttribute{
				MarkdownDescription: "Map of identifiers to their ACME challenges.",
				ElementType:         types.StringType,
				Computed:            true,
			},
		},
		MarkdownDescription: "Creates and manages ACME orders for certificate issuance via PKI External CA roles.",
	}
	base.MustAddLegacyBaseSchema(&resp.Schema)
}

// Create is called during the terraform apply command.
func (r *PKIExternalCAOrderResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PKIExternalCAOrderModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate that exactly one of identifiers or csr is provided
	hasIdentifiers := !data.Identifiers.IsNull() && !data.Identifiers.IsUnknown()
	hasCSR := !data.CSR.IsNull() && !data.CSR.IsUnknown() && data.CSR.ValueString() != ""

	if hasIdentifiers == hasCSR {
		resp.Diagnostics.AddError(
			"Invalid Configuration",
			"Exactly one of 'identifiers' or 'csr' must be provided",
		)
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mount := data.Mount.ValueString()
	roleName := data.RoleName.ValueString()
	path := fmt.Sprintf("%s/role/%s/new-order", mount, roleName)

	vaultRequest, diags := buildOrderVaultRequestFromModel(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	createResp, err := cli.Logical().WriteWithContext(ctx, path, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	if createResp == nil || createResp.Data == nil {
		resp.Diagnostics.AddError("Unexpected Response", "No data returned from Vault")
		return
	}

	orderID, ok := createResp.Data["order_id"].(string)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Response", "order_id not found in response")
		return
	}

	data.OrderID = types.StringValue(orderID)
	data.ID = types.StringValue(makeOrderID(mount, roleName, orderID))

	// Read the order status to populate computed fields
	resp.Diagnostics.Append(r.readOrderStatus(ctx, cli, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during the terraform apply, terraform plan, and terraform refresh commands.
func (r *PKIExternalCAOrderResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PKIExternalCAOrderModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	resp.Diagnostics.Append(r.readOrderStatus(ctx, cli, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PKIExternalCAOrderResource) readOrderStatus(ctx context.Context, cli *api.Client, data *PKIExternalCAOrderModel) diag.Diagnostics {
	var diags diag.Diagnostics

	mount := data.Mount.ValueString()
	roleName := data.RoleName.ValueString()
	orderID := data.OrderID.ValueString()
	path := fmt.Sprintf("%s/role/%s/order/%s/status", mount, roleName, orderID)

	readResp, err := cli.Logical().ReadWithContext(ctx, path)
	if err != nil {
		diags.AddError(errutil.VaultReadErr(err))
		return diags
	}
	if readResp == nil {
		// Order not found - this shouldn't happen in normal operation
		diags.AddError("Order Not Found", fmt.Sprintf("Order %s not found", orderID))
		return diags
	}

	var apiModel PKIExternalCAOrderAPIModel
	err = model.ToAPIModel(readResp.Data, &apiModel)
	if err != nil {
		diags.AddError("Unable to translate Vault response data", err.Error())
		return diags
	}

	// Map values back to Terraform model
	data.OrderStatus = types.StringValue(apiModel.OrderStatus)
	data.CreationDate = types.StringValue(apiModel.CreationDate)
	data.NextWorkDate = types.StringValue(apiModel.NextWorkDate)
	data.LastUpdate = types.StringValue(apiModel.LastUpdate)
	data.Expires = types.StringValue(apiModel.Expires)

	if apiModel.LastError != "" {
		data.LastError = types.StringValue(apiModel.LastError)
	} else {
		data.LastError = types.StringNull()
	}

	if apiModel.SerialNumber != "" {
		data.SerialNumber = types.StringValue(apiModel.SerialNumber)
	} else {
		data.SerialNumber = types.StringNull()
	}

	// Store CSR if present in response
	if apiModel.CSR != "" {
		data.CSR = types.StringValue(apiModel.CSR)
	}

	// Convert identifiers list
	if len(apiModel.Identifiers) > 0 {
		identifiersList, listDiags := types.ListValueFrom(ctx, types.StringType, apiModel.Identifiers)
		diags.Append(listDiags...)
		if diags.HasError() {
			return diags
		}
		data.Identifiers = identifiersList
	}

	// Convert challenges map - flatten to simple string representation
	if len(apiModel.Challenges) > 0 {
		challengesMap := make(map[string]attr.Value)
		for identifier, challenges := range apiModel.Challenges {
			// Create a simple string representation of challenges
			challengeStr := fmt.Sprintf("%d challenges", len(challenges))
			if len(challenges) > 0 {
				challengeStr = fmt.Sprintf("%s: %s", challenges[0]["challenge_type"], challenges[0]["challenge_status"])
			}
			challengesMap[identifier] = types.StringValue(challengeStr)
		}
		challengesMapValue, mapDiags := types.MapValue(types.StringType, challengesMap)
		diags.Append(mapDiags...)
		if diags.HasError() {
			return diags
		}
		data.Challenges = challengesMapValue
	} else {
		data.Challenges = types.MapNull(types.StringType)
	}

	return diags
}

func buildOrderVaultRequestFromModel(ctx context.Context, data *PKIExternalCAOrderModel) (map[string]any, diag.Diagnostics) {
	var diags diag.Diagnostics
	vaultRequest := map[string]any{}

	// Add identifiers if provided
	if !data.Identifiers.IsNull() && !data.Identifiers.IsUnknown() {
		var identifiers []string
		if identifiersDiags := data.Identifiers.ElementsAs(ctx, &identifiers, false); identifiersDiags.HasError() {
			diags.Append(identifiersDiags...)
			return nil, diags
		}
		vaultRequest["identifiers"] = identifiers
	}

	// Add CSR if provided
	if !data.CSR.IsNull() && !data.CSR.IsUnknown() && data.CSR.ValueString() != "" {
		vaultRequest["csr"] = data.CSR.ValueString()
	}

	return vaultRequest, diags
}

// Update is not supported for orders - they are immutable once created
func (r *PKIExternalCAOrderResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError(
		"Update Not Supported",
		"ACME orders cannot be updated once created. Any changes require creating a new order.",
	)
}

// Delete is not applicable for orders - they expire naturally
func (r *PKIExternalCAOrderResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Orders are not explicitly deleted; they expire naturally
	// Just remove from state
}

func (r *PKIExternalCAOrderResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	matches := orderIDRe.FindStringSubmatch(req.ID)
	if len(matches) != 4 {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Import ID must be in the format '<mount>/role/<role_name>/%s/<order_id>', got: %s", orderAffix, req.ID),
		)
		return
	}

	mount := matches[1]
	roleName := matches[2]
	orderID := matches[3]

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mount)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("role_name"), roleName)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("order_id"), orderID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldID), req.ID)...)
}

func makeOrderID(mount, roleName, orderID string) string {
	return fmt.Sprintf("%s/role/%s/%s/%s", mount, roleName, orderAffix, orderID)
}
