package sys

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

// ensure we our interface implementation is correct
var _ resource.ResourceWithConfigure = &PasswordPolicyResource{}

func NewPasswordPolicyResource() resource.Resource {
	return &PasswordPolicyResource{}
}

type PasswordPolicyResource struct {
	meta *provider.ProviderMeta
}

func (r *PasswordPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_password_policy_fw"
}

// PasswordPolicyModel describes the Terraform resource data model to match the
// resource schema.
type PasswordPolicyModel struct {
	Namespace types.String `tfsdk:"namespace"`

	Name   types.String `tfsdk:"name"`
	Policy types.String `tfsdk:"policy"`
}

// PasswordPolicyResourceAPIModel describes the Vault API data model.
type PasswordPolicyResourceAPIModel struct {
	Policy string `json:"policy" mapstructure:"policy"`
}

func (r *PasswordPolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	meta, ok := req.ProviderData.(*provider.ProviderMeta)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *provider.ProviderMeta, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	r.meta = meta
}

func (r *PasswordPolicyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				MarkdownDescription: "Name of the password policy.",
				Required:            true,
			},
			"policy": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The password policy document",
			},
		},
		MarkdownDescription: "Provides a resource to manage Password Policies.",
	}

	base.MustAddBaseSchema(&resp.Schema)
}

func (r *PasswordPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan PasswordPolicyModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	client, err := client.GetClient(ctx, r.meta, plan.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Configuring Resource Client", err.Error())
		return
	}

	data := map[string]interface{}{
		"policy": plan.Policy.ValueString(),
	}
	path := r.path(plan.Name.ValueString())
	// vault returns a nil response on success
	_, err = client.Logical().Write(path, data)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Create Resource",
			"An unexpected error occurred while attempting to create the resource. "+
				"Please retry the operation or report this issue to the provider developers.\n\n"+
				"HTTP Error: "+err.Error(),
		)

		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *PasswordPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state PasswordPolicyModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	client, err := client.GetClient(ctx, r.meta, state.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Configuring Resource Client", err.Error())
		return
	}

	// TODO: refactor the following read, marshal and unmarshal into a helper?
	path := r.path(state.Name.ValueString())
	policyResp, err := client.Logical().Read(path)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Read Resource from Vault",
			"An unexpected error occurred while attempting to read the resource. "+
				"Please retry the operation or report this issue to the provider developers.\n\n"+
				"HTTP Error: "+err.Error(),
		)

		return
	}
	if policyResp == nil {
		resp.Diagnostics.AddError(
			"Unable to Read Resource from Vault",
			"An unexpected error occurred while attempting to read the resource. "+
				"Please retry the operation or report this issue to the provider developers.\n\n"+
				"Vault response was nil",
		)

		return
	}

	jsonData, err := json.Marshal(policyResp.Data)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to marshal Vault response",
			"An unexpected error occurred while attempting to marshal the Vault response.\n\n"+
				"Error: "+err.Error(),
		)

		return
	}

	var readResp *PasswordPolicyResourceAPIModel
	err = json.Unmarshal(jsonData, &readResp)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to unmarshal data to API model",
			"An unexpected error occurred while attempting to unmarshal the data.\n\n"+
				"Error: "+err.Error(),
		)

		return
	}

	state.Policy = types.StringValue(readResp.Policy)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *PasswordPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan PasswordPolicyModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	client, err := client.GetClient(ctx, r.meta, plan.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Configuring Resource Client", err.Error())
		return
	}

	data := map[string]interface{}{
		"policy": plan.Policy.ValueString(),
	}
	path := r.path(plan.Name.ValueString())
	// vault returns a nil response on success
	_, err = client.Logical().Write(path, data)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Update Resource",
			"An unexpected error occurred while attempting to update the resource. "+
				"Please retry the operation or report this issue to the provider developers.\n\n"+
				"HTTP Error: "+err.Error(),
		)

		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *PasswordPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var plan PasswordPolicyModel

	// Read Terraform state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	client, err := client.GetClient(ctx, r.meta, plan.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error Configuring Resource Client", err.Error())
		return
	}

	path := r.path(plan.Name.ValueString())

	_, err = client.Logical().Delete(path)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Delete Resource",
			"An unexpected error occurred while attempting to delete the resource. "+
				"Please retry the operation or report this issue to the provider developers.\n\n"+
				"HTTP Error: "+err.Error(),
		)

		return
	}

	// If the logic reaches here, it implicitly succeeded and will remove
	// the resource from state if there are no other errors.
}

func (r *PasswordPolicyResource) path(name string) string {
	return fmt.Sprintf("/sys/policies/password/%s", name)
}
