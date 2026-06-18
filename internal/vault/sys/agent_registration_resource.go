// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"net/url"
	"os"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
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
	ID                           types.String `tfsdk:"id"`
	DisplayName                  types.String `tfsdk:"display_name"`
	EntityID                     types.String `tfsdk:"entity_id"`
	CeilingPolicies              types.List   `tfsdk:"ceiling_policies"`
	NoDefaultCeilingPolicy       types.Bool   `tfsdk:"no_default_ceiling_policy"`
	Description                  types.String `tfsdk:"description"`
	CreationTime                 types.String `tfsdk:"creation_time"`
	LastUpdatedTime              types.String `tfsdk:"last_updated_time"`
	OptionalAuthorizationDetails types.Bool   `tfsdk:"optional_authorization_details"`
}

// AgentRegistrationAPIModel describes the Vault API data model.
type AgentRegistrationAPIModel struct {
	ID                           string   `json:"id" mapstructure:"id"`
	DisplayName                  string   `json:"display_name" mapstructure:"display_name"`
	EntityID                     string   `json:"entity_id" mapstructure:"entity_id"`
	CeilingPolicies              []string `json:"ceiling_policies" mapstructure:"ceiling_policies"`
	NoDefaultCeilingPolicy       bool     `json:"no_default_ceiling_policy" mapstructure:"no_default_ceiling_policy"`
	Description                  string   `json:"description" mapstructure:"description"`
	CreationTime                 string   `json:"creation_time" mapstructure:"creation_time"`
	LastUpdatedTime              string   `json:"last_updated_time" mapstructure:"last_updated_time"`
	OptionalAuthorizationDetails bool     `json:"optional_authorization_details" mapstructure:"optional_authorization_details"`
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
			consts.FieldCeilingPolicies: schema.ListAttribute{
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
			consts.FieldOptionalAuthorizationDetails: schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "When false, RAR (Rich Authorization Requests) is mandatory and authorization_details must be present in the token. When set to true, authorization_details in the JWT token are optional for this agent. This setting works in conjunction with the OAuth Resource Server profile's optional_authorization_details setting - RAR is optional if EITHER is true. Defaults to false.",
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
	if !data.CeilingPolicies.IsNull() && !data.CeilingPolicies.IsUnknown() {
		var policies []string
		resp.Diagnostics.Append(data.CeilingPolicies.ElementsAs(ctx, &policies, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		vaultRequest[consts.FieldCeilingPolicies] = policies
	}

	if !data.NoDefaultCeilingPolicy.IsNull() && !data.NoDefaultCeilingPolicy.IsUnknown() {
		vaultRequest[consts.FieldNoDefaultCeilingPolicy] = data.NoDefaultCeilingPolicy.ValueBool()
	}

	if !data.Description.IsNull() && !data.Description.IsUnknown() {
		vaultRequest[consts.FieldDescription] = data.Description.ValueString()
	}

	// RAR support
	if !data.OptionalAuthorizationDetails.IsNull() && !data.OptionalAuthorizationDetails.IsUnknown() {
		vaultRequest[consts.FieldOptionalAuthorizationDetails] = data.OptionalAuthorizationDetails.ValueBool()
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
	found := r.readFromVault(ctx, client, &data, &resp.Diagnostics, true)
	if resp.Diagnostics.HasError() {
		return
	}
	if !found {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
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

	found := r.readFromVault(ctx, client, &data, &resp.Diagnostics, true)
	if resp.Diagnostics.HasError() {
		return
	}

	if !found {
		tflog.Warn(ctx, "Agent Registry record not found, removing from state")
		resp.State.RemoveResource(ctx)
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
	if !data.CeilingPolicies.IsNull() && !data.CeilingPolicies.IsUnknown() {
		var policies []string
		resp.Diagnostics.Append(data.CeilingPolicies.ElementsAs(ctx, &policies, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		vaultRequest[consts.FieldCeilingPolicies] = policies
	}

	if !data.NoDefaultCeilingPolicy.IsNull() && !data.NoDefaultCeilingPolicy.IsUnknown() {
		vaultRequest[consts.FieldNoDefaultCeilingPolicy] = data.NoDefaultCeilingPolicy.ValueBool()
	}

	if !data.Description.IsNull() && !data.Description.IsUnknown() {
		vaultRequest[consts.FieldDescription] = data.Description.ValueString()
	}

	// RAR support
	if !data.OptionalAuthorizationDetails.IsNull() && !data.OptionalAuthorizationDetails.IsUnknown() {
		vaultRequest[consts.FieldOptionalAuthorizationDetails] = data.OptionalAuthorizationDetails.ValueBool()
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
	found := r.readFromVault(ctx, client, &data, &resp.Diagnostics, false)
	if resp.Diagnostics.HasError() {
		return
	}
	if !found {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
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
	var data AgentRegistrationModel

	// The import ID is the verbatim Vault identifier for the record: either its
	// UUID or its display_name. We detect which by attempting to parse it as a
	// UUID using the same go-uuid package Vault uses to generate the id.
	// readFromVault selects the read endpoint based on whether ID or
	// DisplayName is set.
	if importIDIsUUID(req.ID) {
		data.ID = types.StringValue(req.ID)
	} else {
		data.DisplayName = types.StringValue(req.ID)
	}

	// Namespace is supplied via the TERRAFORM_VAULT_NAMESPACE_IMPORT env var,
	// matching base.WithImportByID and the rest of the provider.
	if ns := os.Getenv(consts.EnvVarVaultNamespaceImport); ns != "" {
		data.Namespace = types.StringValue(ns)
	}

	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	found := r.readFromVault(ctx, client, &data, &resp.Diagnostics, true)
	if resp.Diagnostics.HasError() {
		return
	}
	if !found {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// readFromVault reads the agent registration from Vault into data. It reports
// whether the record was found: a nil/empty Vault response returns false
// without adding an error, so callers can decide whether a missing record is an
// error (create, update, and import read-back) or a signal to remove the
// resource from state (read). Genuine read or decode failures are recorded in
// diags and return false.
// updateTimestamps controls whether to update creation_time and last_updated_time fields
func (r *AgentRegistrationResource) readFromVault(ctx context.Context, client *api.Client, data *AgentRegistrationModel, diags *diag.Diagnostics, updateTimestamps bool) bool {
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
		return false
	}

	if readResp == nil || readResp.Data == nil {
		// The record does not exist in Vault. Report "not found" without an
		// error so the caller can decide how to handle it.
		return false
	}

	var apiModel AgentRegistrationAPIModel
	err = model.ToAPIModel(readResp.Data, &apiModel)
	if err != nil {
		diags.AddError("Unable to translate Vault response data", err.Error())
		return false
	}

	// Update model with API response
	data.ID = types.StringValue(apiModel.ID)
	data.DisplayName = types.StringValue(apiModel.DisplayName)
	data.EntityID = types.StringValue(apiModel.EntityID)

	if apiModel.Description != "" {
		data.Description = types.StringValue(apiModel.Description)
	}

	// Filter out default policies from ceiling_policies
	// Similar to how vault_token resource filters out "default" policy
	filteredPolicies := make([]string, 0)
	for _, policy := range apiModel.CeilingPolicies {
		// Skip default policies that Vault automatically adds
		if policy == "default" || policy == "default-ceiling" {
			continue
		}
		filteredPolicies = append(filteredPolicies, policy)
	}

	// Always set ceiling_policies to avoid type issues
	policies, d := types.ListValueFrom(ctx, types.StringType, filteredPolicies)
	diags.Append(d...)
	if !diags.HasError() {
		data.CeilingPolicies = policies
	}

	data.NoDefaultCeilingPolicy = types.BoolValue(apiModel.NoDefaultCeilingPolicy)

	// RAR support
	data.OptionalAuthorizationDetails = types.BoolValue(apiModel.OptionalAuthorizationDetails)

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

	return true
}

func (r *AgentRegistrationResource) registerPath() string {
	return "agent-registry/register"
}

func (r *AgentRegistrationResource) registrationByNamePath(name string) string {
	return "agent-registry/registration/display-name/" + url.PathEscape(name)
}

func (r *AgentRegistrationResource) registrationByIDPath(id string) string {
	return "agent-registry/registration/id/" + id
}

// importIDIsUUID reports whether an import ID should be treated as a record
// UUID (read by id) rather than a display_name (read by display_name). Vault
// generates record ids with go-uuid, so a successful parse identifies an id.
func importIDIsUUID(id string) bool {
	_, err := uuid.ParseUUID(id)
	return err == nil
}
