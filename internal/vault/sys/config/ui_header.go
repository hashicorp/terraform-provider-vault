// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"context"
	"fmt"
	"strings"

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
	"github.com/hashicorp/vault/api"
)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &ConfigUIHeaderResource{}

// NewConfigUIHeaderResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewConfigUIHeaderResource() resource.Resource {
	return &ConfigUIHeaderResource{}
}

// ConfigUIHeaderResource implements the methods that define this resource
type ConfigUIHeaderResource struct {
	base.ResourceWithConfigure
}

// ConfigUIHeaderModel describes the Terraform resource data model to match the
// resource schema.
type ConfigUIHeaderModel struct {
	Name   types.String `tfsdk:"name"`
	Values types.Set    `tfsdk:"values"`
}

// Metadata defines the resource name as it would appear in Terraform configurations
// https://developer.hashicorp.com/terraform/plugin/framework/resources#metadata-method
func (r *ConfigUIHeaderResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_config_ui_header"
}

// Schema defines this resource's schema which is the data that is available in
// the resource's configuration, plan, and state
// https://developer.hashicorp.com/terraform/plugin/framework/resources#schema-method
func (r *ConfigUIHeaderResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldName: schema.StringAttribute{
				MarkdownDescription: "The name of the custom header. Cannot start with `X-Vault-`.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldValues: schema.SetAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "Set of values for the header. At least one value is required. Duplicates are automatically ignored.",
				Required:            true,
			},
		},
		MarkdownDescription: "Manages custom response headers returned from the Vault UI. This resource requires `sudo` capability and must be called from the root namespace. **Warning:** Setting `Content-Security-Policy` will override Vault's secure default CSP.",
	}
}

// Create is called during the terraform apply command.
// https://developer.hashicorp.com/terraform/plugin/framework/resources/create
func (r *ConfigUIHeaderResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ConfigUIHeaderModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.writeHeader(ctx, data, errutil.VaultCreateErr, "creating")...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during the terraform apply, terraform plan, and terraform
// refresh commands.
// https://developer.hashicorp.com/terraform/plugin/framework/resources/read
func (r *ConfigUIHeaderResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ConfigUIHeaderModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	vaultClient, err := r.getRootNamespaceClient(ctx)
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Read from Vault - if resource not found, remove from state
	name := data.Name.ValueString()
	path := r.path(name)
	queryParams := map[string][]string{
		"multivalue": {"true"},
	}
	headerResp, err := vaultClient.Logical().ReadWithDataWithContext(ctx, path, queryParams)
	if err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultReadErr(err),
		)
		return
	}
	// If response is nil, the header has been deleted outside of Terraform
	if headerResp == nil || headerResp.Data == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	// Extract values from response
	if valuesRaw, ok := headerResp.Data[consts.FieldValues]; ok {
		var values []string

		switch valuesTyped := valuesRaw.(type) {
		case []interface{}:
			values = make([]string, len(valuesTyped))
			for i, val := range valuesTyped {
				strVal, ok := val.(string)
				if !ok {
					resp.Diagnostics.AddError(
						"Unexpected Vault Response",
						fmt.Sprintf("Expected %q to contain only string values, but element %d had type %T.", consts.FieldValues, i, val),
					)
					return
				}
				values[i] = strVal
			}
		case []string:
			values = valuesTyped
		default:
			resp.Diagnostics.AddError(
				"Unexpected Vault Response",
				fmt.Sprintf("Expected %q to be a list of strings, but got %T.", consts.FieldValues, valuesRaw),
			)
			return
		}

		valuesSet, diags := types.SetValueFrom(ctx, types.StringType, values)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		data.Values = valuesSet
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update is called during the terraform apply command
// https://developer.hashicorp.com/terraform/plugin/framework/resources/update
func (r *ConfigUIHeaderResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data ConfigUIHeaderModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.writeHeader(ctx, data, errutil.VaultUpdateErr, "updating")...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Delete is called during the terraform apply command
// https://developer.hashicorp.com/terraform/plugin/framework/resources/delete
func (r *ConfigUIHeaderResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ConfigUIHeaderModel

	// Read Terraform state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	client, err := r.getRootNamespaceClient(ctx)
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	path := r.path(data.Name.ValueString())

	_, err = client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		// Provide helpful error message for sudo capability requirement
		if strings.Contains(err.Error(), "permission denied") {
			resp.Diagnostics.AddError(
				"Permission Denied",
				fmt.Sprintf("Error deleting UI header %q: %s\n\n"+
					"This operation requires the 'sudo' capability. "+
					"Ensure your Vault policy includes:\n"+
					"path \"sys/config/ui/headers/*\" {\n"+
					"  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\"]\n"+
					"}",
					data.Name.ValueString(), err),
			)
		} else {
			resp.Diagnostics.AddError(
				errutil.VaultDeleteErr(err),
			)
		}
		return
	}

	// If the logic reaches here, it implicitly succeeded and will remove
	// the resource from state if there are no other errors.
}

func (r *ConfigUIHeaderResource) writeHeader(
	ctx context.Context,
	data ConfigUIHeaderModel,
	vaultErr func(error) (string, string),
	operation string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	client, err := r.getRootNamespaceClient(ctx)
	if err != nil {
		diags.AddError(errutil.ClientConfigureErr(err))
		return diags
	}

	name := data.Name.ValueString()

	var values []string
	diags.Append(data.Values.ElementsAs(ctx, &values, false)...)
	if diags.HasError() {
		return diags
	}

	vaultRequest := map[string]interface{}{
		consts.FieldValues: values,
	}

	path := r.path(name)
	_, err = client.Logical().WriteWithContext(ctx, path, vaultRequest)
	if err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			diags.AddError(
				"Permission Denied",
				fmt.Sprintf("Error %s UI header %q: %s\n\n"+
					"This operation requires the 'sudo' capability. "+
					"Ensure your Vault policy includes:\n"+
					"path \"sys/config/ui/headers/*\" {\n"+
					"  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\"]\n"+
					"}",
					operation, name, err),
			)
		} else {
			title, detail := vaultErr(err)
			diags.AddError(title, detail)
		}
	}

	return diags
}

// ImportState implements the import functionality for this resource
func (r *ConfigUIHeaderResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Directly map the import ID to the "name" attribute in the schema
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), req.ID)...)
}

// getRootNamespaceClient returns a Vault client configured for the root namespace.
// UI header configuration is a global setting that must be managed from the root namespace.
func (r *ConfigUIHeaderResource) getRootNamespaceClient(ctx context.Context) (*api.Client, error) {
	baseClient, err := client.GetClient(ctx, r.Meta(), "")
	if err != nil {
		return nil, err
	}

	// Clone the client to avoid modifying the shared client
	rootClient, err := baseClient.Clone()
	if err != nil {
		return nil, err
	}

	// Clear any namespace to ensure we're operating in the root namespace
	rootClient.ClearNamespace()

	return rootClient, nil
}

func (r *ConfigUIHeaderResource) path(name string) string {
	return fmt.Sprintf("sys/config/ui/headers/%s", name)
}
