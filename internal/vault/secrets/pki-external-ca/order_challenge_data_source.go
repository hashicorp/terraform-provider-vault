// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki_external_ca

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
)

const (
	maxPollAttempts = 60
	pollInterval    = 2 * time.Second
)

// Ensure the implementation satisfies the datasource.DataSource interface
var _ datasource.DataSource = &PKIExternalCAOrderChallengeDataSource{}

// NewPKIExternalCAOrderChallengeDataSource returns the implementation for this data source
func NewPKIExternalCAOrderChallengeDataSource() datasource.DataSource {
	return &PKIExternalCAOrderChallengeDataSource{}
}

// PKIExternalCAOrderChallengeDataSource implements the data source
type PKIExternalCAOrderChallengeDataSource struct {
	base.DataSourceWithConfigure
}

// PKIExternalCAOrderChallengeModel describes the Terraform data source data model
type PKIExternalCAOrderChallengeModel struct {
	base.BaseModelLegacy

	Backend       types.String `tfsdk:"backend"`
	RoleName      types.String `tfsdk:"role_name"`
	OrderID       types.String `tfsdk:"order_id"`
	ChallengeType types.String `tfsdk:"challenge_type"`
	Identifier    types.String `tfsdk:"identifier"`

	// Computed fields
	Token   types.String `tfsdk:"token"`
	KeyAuth types.String `tfsdk:"key_authorization"`
	Status  types.String `tfsdk:"status"`
	Expires types.String `tfsdk:"expires"`
}

// PKIExternalCAOrderChallengeAPIModel describes the Vault API data model
type PKIExternalCAOrderChallengeAPIModel struct {
	Token   string `json:"challenge_token" mapstructure:"challenge_token"`
	KeyAuth string `json:"challenge_auth" mapstructure:"challenge_auth"`
	Status  string `json:"challenge_status" mapstructure:"challenge_status"`
	Expires string `json:"expires" mapstructure:"expires"`
}

func (d *PKIExternalCAOrderChallengeDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pki_secret_backend_external_ca_order_challenge"
}

func (d *PKIExternalCAOrderChallengeDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldBackend: schema.StringAttribute{
				MarkdownDescription: "The path where the PKI External CA secret backend is mounted.",
				Required:            true,
			},
			"role_name": schema.StringAttribute{
				MarkdownDescription: "Name of the role associated with the order.",
				Required:            true,
			},
			"order_id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier for the ACME order.",
				Required:            true,
			},
			"challenge_type": schema.StringAttribute{
				MarkdownDescription: "The type of ACME challenge to retrieve. Valid values are `http-01`, `dns-01`, `tls-alpn-01`.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("http-01", "dns-01", "tls-alpn-01"),
				},
			},
			"identifier": schema.StringAttribute{
				MarkdownDescription: "The identifier (domain name) for which to retrieve the challenge.",
				Required:            true,
			},
			"token": schema.StringAttribute{
				MarkdownDescription: "The challenge token provided by the ACME server.",
				Computed:            true,
			},
			"key_authorization": schema.StringAttribute{
				MarkdownDescription: "The key authorization string for the challenge.",
				Computed:            true,
				Sensitive:           true,
			},
			"status": schema.StringAttribute{
				MarkdownDescription: "The current status of the challenge (e.g., pending, valid, invalid).",
				Computed:            true,
			},
			"expires": schema.StringAttribute{
				MarkdownDescription: "Expiry time for the challenge.",
				Computed:            true,
			},
		},
		MarkdownDescription: "Retrieves ACME challenge details for a specific identifier in an order.",
	}

	// Manually add namespace field for data sources
	resp.Schema.Attributes[consts.FieldNamespace] = schema.StringAttribute{
		Optional:            true,
		MarkdownDescription: "Target namespace. (requires Enterprise)",
	}
	resp.Schema.Attributes[consts.FieldID] = schema.StringAttribute{
		Computed:            true,
		MarkdownDescription: "Unique identifier for this data source.",
	}
}

func (d *PKIExternalCAOrderChallengeDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data PKIExternalCAOrderChallengeModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, d.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	backend := data.Backend.ValueString()
	roleName := data.RoleName.ValueString()
	orderID := data.OrderID.ValueString()
	challengeType := data.ChallengeType.ValueString()
	identifier := data.Identifier.ValueString()

	// Poll the order status endpoint until it reaches AwaitingChallengeFulfillment
	statusPath := fmt.Sprintf("%s/role/%s/order/%s/status", backend, roleName, orderID)

	var orderStatus string
	for attempt := 0; attempt < maxPollAttempts; attempt++ {
		statusResp, err := cli.Logical().ReadWithContext(ctx, statusPath)
		if err != nil {
			resp.Diagnostics.AddError(errutil.VaultReadErr(err))
			return
		}

		if statusResp == nil || statusResp.Data == nil {
			resp.Diagnostics.AddError(
				"No Status Data Returned",
				fmt.Sprintf("No status data returned for order %s", orderID),
			)
			return
		}

		status, ok := statusResp.Data["order_status"].(string)
		if !ok {
			resp.Diagnostics.AddError(
				"Invalid Status Response",
				"order_status field not found or invalid in response",
			)
			return
		}

		orderStatus = status

		// Check for terminal error states
		switch orderStatus {
		case "error", "expired", "revoked", "completed":
			resp.Diagnostics.AddError(
				"Order in Terminal State",
				fmt.Sprintf("Order %s is in terminal state '%s' and cannot provide challenges", orderID, orderStatus),
			)
			return
		case "awaiting-challenge-fulfillment":
			// Ready to retrieve challenge
			goto retrieveChallenge
		}

		// Wait before next poll attempt
		if attempt < maxPollAttempts-1 {
			time.Sleep(pollInterval)
		}
	}

	// If we exhausted all attempts without reaching awaiting-challenge-fulfillment
	resp.Diagnostics.AddError(
		"Timeout Waiting for Order Status",
		fmt.Sprintf("Order %s did not reach awaiting-challenge-fulfillment status after %d attempts. Last status: %s",
			orderID, maxPollAttempts, orderStatus),
	)
	return

retrieveChallenge:
	// Construct the path: role/<rolename>/order/<order-id>/challenge
	challengePath := fmt.Sprintf("%s/role/%s/order/%s/challenge", backend, roleName, orderID)

	// Prepare request data with challenge type and identifier
	requestData := map[string][]string{
		"challenge_type": {challengeType},
		"identifier":     {identifier},
	}

	// Make the API call
	readResp, err := cli.Logical().ReadWithDataWithContext(ctx, challengePath, requestData)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}

	if readResp == nil || readResp.Data == nil {
		resp.Diagnostics.AddError(
			"No Data Returned",
			fmt.Sprintf("No challenge data returned for identifier %s with challenge type %s", identifier, challengeType),
		)
		return
	}

	var apiModel PKIExternalCAOrderChallengeAPIModel
	err = model.ToAPIModel(readResp.Data, &apiModel)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Map API response to Terraform model
	data.Expires = types.StringValue(apiModel.Expires)
	data.Token = types.StringValue(apiModel.Token)
	data.KeyAuth = types.StringValue(apiModel.KeyAuth)
	data.Status = types.StringValue(apiModel.Status)

	// Generate a unique ID for this data source read
	data.ID = types.StringValue(fmt.Sprintf("%s/%s/%s/%s/%s", backend, roleName, orderID, challengeType, identifier))

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Made with Bob
