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
	fieldMount              = consts.FieldMount
	fieldKeytab             = consts.FieldKeytab
	fieldServiceAccount     = consts.FieldServiceAccount
	fieldRemoveInstanceName = consts.FieldRemoveInstanceName
	fieldAddGroupAliases    = consts.FieldAddGroupAliases
)

var kerberosConfigPathRegexp = regexp.MustCompile("^auth/(.+)/config$")

var (
	_ resource.Resource                = (*kerberosAuthBackendConfigResource)(nil)
	_ resource.ResourceWithConfigure   = (*kerberosAuthBackendConfigResource)(nil)
	_ resource.ResourceWithImportState = (*kerberosAuthBackendConfigResource)(nil)
)

// NewKerberosAuthBackendConfigResource is the constructor function
var NewKerberosAuthBackendConfigResource = func() resource.Resource {
	return &kerberosAuthBackendConfigResource{}
}

type kerberosAuthBackendConfigResource struct {
	base.ResourceWithConfigure
}

type kerberosAuthBackendConfigModel struct {
	base.BaseModel
	Mount              types.String `tfsdk:"mount"`
	Keytab             types.String `tfsdk:"keytab"`
	ServiceAccount     types.String `tfsdk:"service_account"`
	RemoveInstanceName types.Bool   `tfsdk:"remove_instance_name"`
	AddGroupAliases    types.Bool   `tfsdk:"add_group_aliases"`
}

func (r *kerberosAuthBackendConfigResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_kerberos_auth_backend_config"
}

func (r *kerberosAuthBackendConfigResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages the Kerberos authentication method configuration in Vault.\n\n" +
			"**Note:** Vault does not support deleting auth backend configurations via the API. " +
			"When this resource is destroyed or replaced (e.g., when changing the `mount`), " +
			"it is only removed from Terraform state. The configuration remains in Vault until " +
			"the auth mount itself is deleted.",
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
			fieldKeytab: schema.StringAttribute{
				Required:    true,
				WriteOnly:   true,
				Description: "Base64-encoded keytab file content (write-only). Must contain an entry matching service_account.",
			},
			fieldServiceAccount: schema.StringAttribute{
				Required:    true,
				Description: "The Kerberos service account associated with the keytab entry (e.g., 'vault_svc').",
			},
			fieldRemoveInstanceName: schema.BoolAttribute{
				Optional:    true,
				Description: "Removes instance names from Kerberos service principal names. Default: false.",
			},
			fieldAddGroupAliases: schema.BoolAttribute{
				Optional:    true,
				Description: "Adds group aliases during authentication. Default: false.",
			},
		},
	}

	base.MustAddBaseSchema(&resp.Schema)
}

func (r *kerberosAuthBackendConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan kerberosAuthBackendConfigModel
	var config kerberosAuthBackendConfigModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.writeConfig(ctx, &plan, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *kerberosAuthBackendConfigResource) writeConfig(ctx context.Context, plan *kerberosAuthBackendConfigModel, config *kerberosAuthBackendConfigModel) diag.Diagnostics {
	var diags diag.Diagnostics

	vaultClient, err := client.GetClient(ctx, r.Meta(), plan.Namespace.ValueString())
	if err != nil {
		diags.AddError("Error getting client", err.Error())
		return diags
	}

	mount := plan.Mount.ValueString()
	configPath := fmt.Sprintf("/auth/%s/config", mount)

	data := map[string]interface{}{
		fieldKeytab:         config.Keytab.ValueString(),
		fieldServiceAccount: config.ServiceAccount.ValueString(),
	}

	data[fieldRemoveInstanceName] = config.RemoveInstanceName.ValueBool()
	data[fieldAddGroupAliases] = config.AddGroupAliases.ValueBool()

	log.Printf("[DEBUG] Writing Kerberos auth backend config to %q", configPath)
	_, err = vaultClient.Logical().Write(configPath, data)
	if err != nil {
		diags.AddError(
			fmt.Sprintf("Error writing Kerberos auth backend config to %q", configPath),
			err.Error(),
		)
		return diags
	}

	// Read back the configuration
	diags.Append(r.read(ctx, plan)...)
	return diags
}

func (r *kerberosAuthBackendConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state kerberosAuthBackendConfigModel
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

func (r *kerberosAuthBackendConfigResource) read(ctx context.Context, model *kerberosAuthBackendConfigModel) diag.Diagnostics {
	var diags diag.Diagnostics

	vaultClient, err := client.GetClient(ctx, r.Meta(), model.Namespace.ValueString())
	if err != nil {
		diags.AddError("Error getting client", err.Error())
		return diags
	}

	mount := model.Mount.ValueString()
	configPath := fmt.Sprintf("/auth/%s/config", mount)

	log.Printf("[DEBUG] Reading Kerberos auth backend config from %q", configPath)
	resp, err := vaultClient.Logical().ReadWithContext(ctx, configPath)
	if err != nil {
		diags.AddError(
			fmt.Sprintf("Error reading Kerberos auth backend config from %q", configPath),
			err.Error(),
		)
		return diags
	}

	if resp == nil {
		diags.AddError(
			"Kerberos auth backend config not found",
			fmt.Sprintf("No configuration found at %q", configPath),
		)
		return diags
	}

	// Read service_account
	if v, ok := resp.Data[fieldServiceAccount].(string); ok {
		model.ServiceAccount = types.StringValue(v)
	}

	// Only update optional boolean fields if they were set in the config (not null)
	if !model.RemoveInstanceName.IsNull() {
		if v, ok := resp.Data[fieldRemoveInstanceName].(bool); ok {
			model.RemoveInstanceName = types.BoolValue(v)
		}
	}
	if !model.AddGroupAliases.IsNull() {
		if v, ok := resp.Data[fieldAddGroupAliases].(bool); ok {
			model.AddGroupAliases = types.BoolValue(v)
		}
	}

	return diags
}

func (r *kerberosAuthBackendConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan kerberosAuthBackendConfigModel
	var config kerberosAuthBackendConfigModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.writeConfig(ctx, &plan, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *kerberosAuthBackendConfigResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state kerberosAuthBackendConfigModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	mount := state.Mount.ValueString()
	configPath := fmt.Sprintf("/auth/%s/config", mount)

	// Configuration endpoints cannot be deleted from Vault, only the auth mount itself can be deleted.
	// This function only removes the resource from Terraform state.
	log.Printf("[DEBUG] Removing Kerberos auth backend config from Terraform state")

	resp.Diagnostics.AddWarning(
		"Configuration Remains in Vault",
		fmt.Sprintf("The Kerberos auth backend configuration at %q has been removed from Terraform state, "+
			"but it may still exist in Vault unless the auth mount itself is deleted.", configPath),
	)
}

func (r *kerberosAuthBackendConfigResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root(consts.FieldMount), req, resp)

	authMount, err := extractKerberosConfigPathFromID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error parsing import identifier",
			fmt.Sprintf("The import identifier '%s' is not valid: %s", req.ID, err.Error()),
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(fieldMount), authMount)...)

	ns := os.Getenv(consts.EnvVarVaultNamespaceImport)
	if ns != "" {
		log.Printf("[DEBUG] Environment variable %s set, attempting TF state import with namespace: %s", consts.EnvVarVaultNamespaceImport, ns)
		resp.Diagnostics.Append(
			resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...,
		)
	}
}

// extractKerberosConfigPathFromID extracts the auth backend path from the import identifier provided
// by the terraform import CLI command.
func extractKerberosConfigPathFromID(id string) (string, error) {
	// Trim leading/trailing slashes and whitespace
	id = strings.TrimSpace(strings.Trim(id, "/"))

	if id == "" {
		return "", fmt.Errorf("Expected import ID format: auth/{path}/config")
	}

	// Extract path using regex - FindStringSubmatch returns nil if no match
	matches := kerberosConfigPathRegexp.FindStringSubmatch(id)
	if len(matches) != 2 || strings.TrimSpace(matches[1]) == "" {
		return "", fmt.Errorf("Expected import ID format: auth/{path}/config")
	}

	return strings.TrimSpace(matches[1]), nil
}
