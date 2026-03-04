// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/validators"
)

const (
	fieldName     = consts.FieldName
	fieldPolicies = consts.FieldPolicies
)

var kerberosGroupPathRegexp = regexp.MustCompile("^auth/(.+)/groups/(.+)$")

var (
	_ resource.Resource                = (*kerberosAuthBackendGroupResource)(nil)
	_ resource.ResourceWithConfigure   = (*kerberosAuthBackendGroupResource)(nil)
	_ resource.ResourceWithImportState = (*kerberosAuthBackendGroupResource)(nil)
)

// NewKerberosAuthBackendGroupResource is the constructor function
var NewKerberosAuthBackendGroupResource = func() resource.Resource {
	return &kerberosAuthBackendGroupResource{}
}

type kerberosAuthBackendGroupResource struct {
	base.ResourceWithConfigure
}

type kerberosAuthBackendGroupModel struct {
	base.BaseModel
	Mount    types.String `tfsdk:"mount"`
	Name     types.String `tfsdk:"name"`
	Policies types.Set    `tfsdk:"policies"`
}

func (r *kerberosAuthBackendGroupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_kerberos_auth_backend_group"
}

func (r *kerberosAuthBackendGroupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages LDAP group to Vault policy mappings for the Kerberos authentication method.",
		Attributes: map[string]schema.Attribute{
			fieldMount: schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("kerberos"),
				Description: "Path where the Kerberos auth method is mounted.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					validators.PathValidator(),
				},
			},
			fieldName: schema.StringAttribute{
				Required:    true,
				Description: "The name of the LDAP group.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			fieldPolicies: schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Set of Vault policies to associate with this group.",
			},
		},
	}

	base.MustAddBaseSchema(&resp.Schema)
}

func (r *kerberosAuthBackendGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan kerberosAuthBackendGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.writeGroup(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *kerberosAuthBackendGroupResource) writeGroup(ctx context.Context, plan *kerberosAuthBackendGroupModel) diag.Diagnostics {
	var diags diag.Diagnostics

	vaultClient, err := client.GetClient(ctx, r.Meta(), plan.Namespace.ValueString())
	if err != nil {
		diags.AddError("Error getting client", err.Error())
		return diags
	}

	mount := plan.Mount.ValueString()
	name := plan.Name.ValueString()
	groupPath := fmt.Sprintf("/auth/%s/groups/%s", mount, name)

	data := make(map[string]interface{})

	if !plan.Policies.IsNull() && !plan.Policies.IsUnknown() {
		var policies []string
		diags.Append(plan.Policies.ElementsAs(ctx, &policies, false)...)
		if diags.HasError() {
			return diags
		}
		data[fieldPolicies] = policies
	}

	log.Printf("[DEBUG] Writing Kerberos group to %q", groupPath)
	_, err = vaultClient.Logical().Write(groupPath, data)
	if err != nil {
		diags.AddError(
			fmt.Sprintf("Error writing Kerberos group to %q", groupPath),
			err.Error(),
		)
		return diags
	}

	// Read back the configuration
	diags.Append(r.read(ctx, plan)...)
	return diags
}

func (r *kerberosAuthBackendGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state kerberosAuthBackendGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.read(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *kerberosAuthBackendGroupResource) read(ctx context.Context, model *kerberosAuthBackendGroupModel) diag.Diagnostics {
	var diags diag.Diagnostics

	vaultClient, err := client.GetClient(ctx, r.Meta(), model.Namespace.ValueString())
	if err != nil {
		diags.AddError("Error getting client", err.Error())
		return diags
	}

	mount := model.Mount.ValueString()
	name := model.Name.ValueString()
	groupPath := fmt.Sprintf("/auth/%s/groups/%s", mount, name)

	log.Printf("[DEBUG] Reading Kerberos group from %q", groupPath)
	resp, err := vaultClient.Logical().ReadWithContext(ctx, groupPath)
	if err != nil {
		diags.AddError(
			fmt.Sprintf("Error reading Kerberos group from %q", groupPath),
			err.Error(),
		)
		return diags
	}

	if resp == nil {
		diags.AddError(
			"Kerberos group not found",
			fmt.Sprintf("No group found at %q", groupPath),
		)
		return diags
	}

	if !model.Policies.IsNull() {
		if v, ok := resp.Data[fieldPolicies]; ok {
			log.Printf("[DEBUG] Vault returned policies: %v (type: %T)", v, v)
			policies, err := types.SetValueFrom(ctx, types.StringType, v)
			if err.HasError() {
				diags.Append(err...)
				return diags
			}
			model.Policies = policies
		}
	}

	return diags
}

func (r *kerberosAuthBackendGroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan kerberosAuthBackendGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.writeGroup(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *kerberosAuthBackendGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state kerberosAuthBackendGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := client.GetClient(ctx, r.Meta(), state.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error getting client", err.Error())
		return
	}

	mount := state.Mount.ValueString()
	name := state.Name.ValueString()
	groupPath := fmt.Sprintf("/auth/%s/groups/%s", mount, name)

	log.Printf("[DEBUG] Deleting Kerberos group from %q", groupPath)
	_, err = vaultClient.Logical().Delete(groupPath)
	if err != nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Error deleting Kerberos group from %q", groupPath),
			err.Error(),
		)
		return
	}
}

func (r *kerberosAuthBackendGroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root(consts.FieldMount), req, resp)

	mount, name, err := extractKerberosGroupPathFromID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			fmt.Sprintf("The import identifier '%s' is not valid: %s", req.ID, err.Error()),
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(fieldMount), mount)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(fieldName), name)...)

	ns := os.Getenv(consts.EnvVarVaultNamespaceImport)
	if ns != "" {
		log.Printf("[DEBUG] Environment variable %s set, attempting TF state import with namespace: %s", consts.EnvVarVaultNamespaceImport, ns)
		resp.Diagnostics.Append(
			resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...,
		)
	}
}

// extractKerberosGroupPathFromID extracts the auth backend mount and group name from the import identifier provided
// by the terraform import CLI command.
func extractKerberosGroupPathFromID(id string) (string, string, error) {
	// Trim leading/trailing slashes and whitespace
	id = strings.TrimSpace(strings.Trim(id, "/"))

	if id == "" {
		return "", "", fmt.Errorf("Expected import ID format: auth/{mount}/groups/{name}")
	}

	// Extract mount and name using regex - FindStringSubmatch returns nil if no match
	matches := kerberosGroupPathRegexp.FindStringSubmatch(id)
	if len(matches) != 3 || matches[1] == "" || matches[2] == "" {
		return "", "", fmt.Errorf("Expected import ID format: auth/{mount}/groups/{name}")
	}

	return matches[1], matches[2], nil
}
