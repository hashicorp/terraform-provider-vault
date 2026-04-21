// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &AgentRegistrationResource{}

// NewAgentRegistrationResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewAgentRegistrationResource() resource.Resource {
	return &AgentRegistrationResource{}
}

// AgentRegistrationResource implements the methods that define this resource
type AgentRegistrationResource struct {
	base.ResourceWithConfigure
}

// AgentRegistrationModel describes the Terraform resource data model to match the
// resource schema.
type AgentRegistrationModel struct {
	// common fields to all new resources
	base.BaseModel

	// fields specific to this resource
	ID                       types.String `tfsdk:"id"`
	DisplayName              types.String `tfsdk:"display_name"`
	EntityID                 types.String `tfsdk:"entity_id"`
	CeilingPolicyIdentifiers types.List   `tfsdk:"ceiling_policy_identifiers"`
	NoDefaultCeilingPolicy   types.Bool   `tfsdk:"no_default_ceiling_policy"`
	Description              types.String `tfsdk:"description"`
	CreationTime             types.String `tfsdk:"creation_time"`
	LastUpdatedTime          types.String `tfsdk:"last_updated_time"`
}

// AgentRegistrationAPIModel describes the Vault API data model.
type AgentRegistrationAPIModel struct {
	ID                       string   `json:"id" mapstructure:"id"`
	DisplayName              string   `json:"display_name" mapstructure:"display_name"`
	EntityID                 string   `json:"entity_id" mapstructure:"entity_id"`
	CeilingPolicyIdentifiers []string `json:"ceiling_policy_identifiers" mapstructure:"ceiling_policy_identifiers"`
	NoDefaultCeilingPolicy   bool     `json:"no_default_ceiling_policy" mapstructure:"no_default_ceiling_policy"`
	Description              string   `json:"description" mapstructure:"description"`
	CreationTime             string   `json:"creation_time" mapstructure:"creation_time"`
	LastUpdatedTime          string   `json:"last_updated_time" mapstructure:"last_updated_time"`
}

// Metadata defines the resource name as it would appear in Terraform configurations
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources#metadata-method
func (r *AgentRegistrationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_agent_registration"
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources#schema-method
func (r *AgentRegistrationResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldID: schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Unique identifier for the agent registration.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldDisplayName: schema.StringAttribute{
				MarkdownDescription: "Human-readable name for the agent registration.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldEntityID: schema.StringAttribute{
				MarkdownDescription: "Entity ID representing this agent. Each entity can only have one registration.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldCeilingPolicyIdentifiers: schema.ListAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "List of policy identifiers that define the authorization ceiling for this agent. Cannot include 'root' policy. Note: Vault automatically adds default policies (['default', 'default-ceiling']) unless no_default_ceiling_policy is true, but these are filtered out when reading the state to match your configuration.",
			},
			consts.FieldNoDefaultCeilingPolicy: schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "If true, opts out of automatically adding the default-ceiling policy to this agent registration.",
			},
			consts.FieldDescription: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Detailed description of the agent's purpose.",
			},
			consts.FieldCreationTime: schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Timestamp when the registration was created.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldLastUpdatedTime: schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Timestamp when the registration was last updated.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
		MarkdownDescription: "Manages Agent Registry registrations in Vault Enterprise. " +
			"The Agent Registry allows you to register agents with Vault and apply authorization ceilings to them.",
	}

	base.MustAddBaseSchema(&resp.Schema)
}

// Create is called during the terraform apply command.
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/create
func (r *AgentRegistrationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data AgentRegistrationModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Check if Enterprise is supported
	if !provider.IsEnterpriseSupported(r.Meta()) {
		resp.Diagnostics.AddError(
			"Enterprise Feature Required",
			"Agent Registry is only available in Vault Enterprise",
		)
		return
	}

	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultRequest := map[string]interface{}{
		consts.FieldDisplayName: data.DisplayName.ValueString(),
		consts.FieldEntityID:    data.EntityID.ValueString(),
	}

	// Add optional fields
	if !data.CeilingPolicyIdentifiers.IsNull() && !data.CeilingPolicyIdentifiers.IsUnknown() {
		var policies []string
		resp.Diagnostics.Append(data.CeilingPolicyIdentifiers.ElementsAs(ctx, &policies, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		vaultRequest[consts.FieldCeilingPolicyIdentifiers] = policies
	}

	if !data.NoDefaultCeilingPolicy.IsNull() && !data.NoDefaultCeilingPolicy.IsUnknown() {
		vaultRequest[consts.FieldNoDefaultCeilingPolicy] = data.NoDefaultCeilingPolicy.ValueBool()
	}

	if !data.Description.IsNull() && !data.Description.IsUnknown() {
		vaultRequest[consts.FieldDescription] = data.Description.ValueString()
	}

	path := r.registerPath()
	createResp, err := client.Logical().WriteWithContext(ctx, path, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultCreateErr(err),
		)
		return
	}

	if createResp == nil {
		resp.Diagnostics.AddError(
			"Unexpected nil response from Vault",
			"Expected response data from agent registration creation",
		)
		return
	}

	// Extract the ID from the response
	if id, ok := createResp.Data[consts.FieldID].(string); ok {
		data.ID = types.StringValue(id)
	} else {
		resp.Diagnostics.AddError(
			"Missing ID in response",
			"Agent registration creation did not return an ID",
		)
		return
	}

	// Read back the full registration to get computed fields (including timestamps)
	r.readFromVault(ctx, client, &data, &resp.Diagnostics, true)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during the terraform apply, terraform plan, and terraform
// refresh commands.
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/read
func (r *AgentRegistrationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data AgentRegistrationModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	r.readFromVault(ctx, client, &data, &resp.Diagnostics, true)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update is called during the terraform apply command
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/update
func (r *AgentRegistrationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state AgentRegistrationModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Preserve timestamps from state (they'll be updated by readFromVault)
	data := plan
	data.CreationTime = state.CreationTime
	data.LastUpdatedTime = state.LastUpdatedTime

	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	vaultRequest := map[string]interface{}{
		consts.FieldDisplayName: data.DisplayName.ValueString(),
		consts.FieldEntityID:    data.EntityID.ValueString(),
	}

	// Add optional fields
	if !data.CeilingPolicyIdentifiers.IsNull() && !data.CeilingPolicyIdentifiers.IsUnknown() {
		var policies []string
		resp.Diagnostics.Append(data.CeilingPolicyIdentifiers.ElementsAs(ctx, &policies, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		vaultRequest[consts.FieldCeilingPolicyIdentifiers] = policies
	}

	if !data.NoDefaultCeilingPolicy.IsNull() && !data.NoDefaultCeilingPolicy.IsUnknown() {
		vaultRequest[consts.FieldNoDefaultCeilingPolicy] = data.NoDefaultCeilingPolicy.ValueBool()
	}

	if !data.Description.IsNull() && !data.Description.IsUnknown() {
		vaultRequest[consts.FieldDescription] = data.Description.ValueString()
	}

	// Update by ID
	path := r.registrationByIDPath(data.ID.ValueString())
	_, err = client.Logical().WriteWithContext(ctx, path, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultUpdateErr(err),
		)
		return
	}

	// Read back the updated registration (don't update timestamps to avoid inconsistency)
	r.readFromVault(ctx, client, &data, &resp.Diagnostics, false)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Delete is called during the terraform apply command
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/delete
func (r *AgentRegistrationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data AgentRegistrationModel

	// Read Terraform state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Delete by ID
	path := r.registrationByIDPath(data.ID.ValueString())

	_, err = client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultDeleteErr(err),
		)
		return
	}

	// If the logic reaches here, it implicitly succeeded and will remove
	// the resource from state if there are no other errors.
}

// ImportState implements the resource.ResourceWithImportState interface.
func (r *AgentRegistrationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import by display_name, optionally with namespace prefix
	// Format: display_name or namespace/display_name
	displayName := req.ID
	namespace := ""

	// Check if ID contains namespace prefix
	if strings.Contains(req.ID, "/") {
		parts := strings.SplitN(req.ID, "/", 2)
		if len(parts) == 2 {
			namespace = parts[0]
			displayName = parts[1]
		}
	}

	var data AgentRegistrationModel
	data.DisplayName = types.StringValue(displayName)

	if namespace != "" {
		data.Namespace = types.StringValue(namespace)
	}

	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	r.readFromVault(ctx, client, &data, &resp.Diagnostics, true)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// readFromVault reads the agent registration from Vault and updates the model
// updateTimestamps controls whether to update creation_time and last_updated_time fields
func (r *AgentRegistrationResource) readFromVault(ctx context.Context, client *api.Client, data *AgentRegistrationModel, diags *diag.Diagnostics, updateTimestamps bool) {
	// Prefer reading by ID (more robust), fall back to display_name for import
	var path string
	if !data.ID.IsNull() && !data.ID.IsUnknown() && data.ID.ValueString() != "" {
		// Read by ID when available (after create, update, or refresh)
		path = r.registrationByIDPath(data.ID.ValueString())
	} else {
		// Read by display_name during import (when ID is not yet known)
		path = r.registrationByNamePath(data.DisplayName.ValueString())
	}

	readResp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		diags.AddError(
			errutil.VaultReadErr(err),
		)
		return
	}

	if readResp == nil {
		diags.AddError(
			errutil.VaultReadResponseNil(),
		)
		return
	}

	var apiModel AgentRegistrationAPIModel
	err = model.ToAPIModel(readResp.Data, &apiModel)
	if err != nil {
		diags.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Update model with API response
	data.ID = types.StringValue(apiModel.ID)
	data.DisplayName = types.StringValue(apiModel.DisplayName)
	data.EntityID = types.StringValue(apiModel.EntityID)

	if apiModel.Description != "" {
		data.Description = types.StringValue(apiModel.Description)
	}

	// Filter out default policies from ceiling_policy_identifiers
	// Similar to how vault_token resource filters out "default" policy
	filteredPolicies := make([]string, 0)
	for _, policy := range apiModel.CeilingPolicyIdentifiers {
		// Skip default policies that Vault automatically adds
		if policy == "default" || policy == "default-ceiling" {
			continue
		}
		filteredPolicies = append(filteredPolicies, policy)
	}

	// Always set ceiling_policy_identifiers to avoid type issues
	policies, d := types.ListValueFrom(ctx, types.StringType, filteredPolicies)
	diags.Append(d...)
	if !diags.HasError() {
		data.CeilingPolicyIdentifiers = policies
	}

	data.NoDefaultCeilingPolicy = types.BoolValue(apiModel.NoDefaultCeilingPolicy)

	// Only update timestamps during Create, Read, and Import (not during Update)
	// This prevents inconsistent state errors when last_updated_time changes during update
	if updateTimestamps {
		if apiModel.CreationTime != "" {
			data.CreationTime = types.StringValue(apiModel.CreationTime)
		}

		if apiModel.LastUpdatedTime != "" {
			data.LastUpdatedTime = types.StringValue(apiModel.LastUpdatedTime)
		}
	}
}

func (r *AgentRegistrationResource) registerPath() string {
	return "agent-registry/register"
}

func (r *AgentRegistrationResource) registrationByNamePath(name string) string {
	return fmt.Sprintf("agent-registry/registration/display-name/%s", name)
}

func (r *AgentRegistrationResource) registrationByIDPath(id string) string {
	return fmt.Sprintf("agent-registry/registration/id/%s", id)
}
