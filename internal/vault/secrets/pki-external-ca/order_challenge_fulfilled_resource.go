// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki_external_ca

import (
	"context"
	"fmt"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

const challengeFulfilledAffix = "fulfilled-challenge"

var challengeFulfilledIDRe = regexp.MustCompile(`^([^/]+)/role/([^/]+)/order/([^/]+)/` + challengeFulfilledAffix + `/([^/]+)/([^/]+)$`)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &PKIExternalCAOrderChallengeFulfilledResource{}

// NewPKIExternalCAOrderChallengeFulfilledResource returns the implementation for this resource
func NewPKIExternalCAOrderChallengeFulfilledResource() resource.Resource {
	return &PKIExternalCAOrderChallengeFulfilledResource{}
}

// PKIExternalCAOrderChallengeFulfilledResource implements the methods that define this resource
type PKIExternalCAOrderChallengeFulfilledResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

// PKIExternalCAOrderChallengeFulfilledModel describes the Terraform resource data model
type PKIExternalCAOrderChallengeFulfilledModel struct {
	base.BaseModelLegacy

	Backend       types.String `tfsdk:"backend"`
	RoleName      types.String `tfsdk:"role_name"`
	OrderID       types.String `tfsdk:"order_id"`
	ChallengeType types.String `tfsdk:"challenge_type"`
	Identifier    types.String `tfsdk:"identifier"`
}

func (r *PKIExternalCAOrderChallengeFulfilledResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pki_secret_backend_external_ca_order_challenge_fulfilled"
}

func (r *PKIExternalCAOrderChallengeFulfilledResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldBackend: schema.StringAttribute{
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
			"challenge_type": schema.StringAttribute{
				MarkdownDescription: "The type of ACME challenge that was fulfilled. Valid values are `http-01`, `dns-01`, `tls-alpn-01`.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf("http-01", "dns-01", "tls-alpn-01"),
				},
			},
			"identifier": schema.StringAttribute{
				MarkdownDescription: "The identifier (domain name) for which the challenge was fulfilled.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
		MarkdownDescription: "Marks an ACME challenge as fulfilled for a specific identifier in an order.",
	}
	base.MustAddLegacyBaseSchema(&resp.Schema)
}

// Create is called during the terraform apply command.
func (r *PKIExternalCAOrderChallengeFulfilledResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PKIExternalCAOrderChallengeFulfilledModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	backend := data.Backend.ValueString()
	roleName := data.RoleName.ValueString()
	orderID := data.OrderID.ValueString()
	challengeType := data.ChallengeType.ValueString()
	identifier := data.Identifier.ValueString()

	// Construct the path: role/<rolename>/order/<order-id>/fulfilled-challenge
	path := fmt.Sprintf("%s/role/%s/order/%s/fulfilled-challenge", backend, roleName, orderID)

	// Prepare request data with challenge type and identifier
	requestData := map[string]interface{}{
		"challenge_type": challengeType,
		"identifier":     identifier,
	}

	// Make the API call to mark the challenge as fulfilled
	_, err = cli.Logical().WriteWithContext(ctx, path, requestData)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	// Set the ID
	data.ID = types.StringValue(makeChallengeFulfilledID(backend, roleName, orderID, challengeType, identifier))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during the terraform apply, terraform plan, and terraform refresh commands.
func (r *PKIExternalCAOrderChallengeFulfilledResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PKIExternalCAOrderChallengeFulfilledModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// This resource doesn't have a read endpoint, so we just keep the state as-is
	// The resource represents an action (marking challenge as fulfilled) rather than a persistent object
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PKIExternalCAOrderChallengeFulfilledResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// All fields require replacement, so this should never be called
	var data PKIExternalCAOrderChallengeFulfilledModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PKIExternalCAOrderChallengeFulfilledResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// This resource represents an action that cannot be undone
	// Deletion just removes it from state without making any API calls
}

func (r *PKIExternalCAOrderChallengeFulfilledResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	matches := challengeFulfilledIDRe.FindStringSubmatch(req.ID)
	if len(matches) != 6 {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Import ID must be in the format '<backend>/role/<role_name>/order/<order_id>/%s/<challenge_type>/<identifier>', got: %s",
				challengeFulfilledAffix, req.ID),
		)
		return
	}

	backend := matches[1]
	roleName := matches[2]
	orderID := matches[3]
	challengeType := matches[4]
	identifier := matches[5]

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldBackend), backend)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("role_name"), roleName)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("order_id"), orderID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("challenge_type"), challengeType)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("identifier"), identifier)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldID), req.ID)...)
}

func makeChallengeFulfilledID(backend, roleName, orderID, challengeType, identifier string) string {
	return fmt.Sprintf("%s/role/%s/order/%s/%s/%s/%s", backend, roleName, orderID, challengeFulfilledAffix, challengeType, identifier)
}

// Made with Bob
