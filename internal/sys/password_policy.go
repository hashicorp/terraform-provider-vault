package sys

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/vault/api"
)

func NewPasswordPolicyResource() resource.Resource {
	return &PasswordPolicyResource{}
}

type PasswordPolicyResource struct {
	client *api.Client
}

func (r *PasswordPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_password_policy"
}

// PasswordPolicyModel describes the Terraform resource data model to match the
// resource schema.
type PasswordPolicyModel struct {
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
	// TODO(JM): ensure this handles vault namespaces
	client, err := meta.GetClient()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Configuring Resource Client",
			err.Error(),
		)
		return
	}
	r.client = client
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
}

func (r *PasswordPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Error(ctx, "Create a password policy resource")
	var plan *PasswordPolicyModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	data := map[string]interface{}{
		"policy": plan.Policy.ValueString(),
	}
	tflog.Error(ctx, "data", data)
	path := fmt.Sprintf("/sys/policies/password/%s", plan.Name.ValueString())
	// vault returns a nil response on success
	_, err := r.client.Logical().Write(path, data)
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
	tflog.Error(ctx, "JMF READ a password policy resource")
	return
}

func (r *PasswordPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	return
}

func (r *PasswordPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	return
}
