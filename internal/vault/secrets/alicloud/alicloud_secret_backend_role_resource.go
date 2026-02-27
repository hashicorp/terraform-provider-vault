// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package alicloud

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
)

const rolesAffix = "role"

var roleIDRegex = regexp.MustCompile(`^(.+)/` + rolesAffix + `/(.+)$`)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &AliCloudSecretBackendRoleResource{}
var _ resource.ResourceWithImportState = &AliCloudSecretBackendRoleResource{}

// NewAliCloudSecretBackendRoleResource returns the implementation for this resource
func NewAliCloudSecretBackendRoleResource() resource.Resource {
	return &AliCloudSecretBackendRoleResource{}
}

// AliCloudSecretBackendRoleResource implements the methods that define this resource
type AliCloudSecretBackendRoleResource struct {
	base.ResourceWithConfigure
}

// AliCloudSecretBackendRoleModel describes the Terraform resource data model
type AliCloudSecretBackendRoleModel struct {
	base.BaseModel

	Mount          types.String `tfsdk:"mount"`
	Name           types.String `tfsdk:"name"`
	RoleARN        types.String `tfsdk:"role_arn"`
	InlinePolicies types.String `tfsdk:"inline_policies"`
	RemotePolicies types.String `tfsdk:"remote_policies"`
	TTL            types.Int64  `tfsdk:"ttl"`
	MaxTTL         types.Int64  `tfsdk:"max_ttl"`
}

// AliCloudRoleAPIModel describes the Vault API data model.
// Vault API expects inline_policies and remote_policies as comma-separated strings.
type AliCloudRoleAPIModel struct {
	RoleARN        string `json:"role_arn,omitempty" mapstructure:"role_arn"`
	InlinePolicies string `json:"inline_policies,omitempty" mapstructure:"inline_policies"`
	RemotePolicies string `json:"remote_policies,omitempty" mapstructure:"remote_policies"`
	TTL            int64  `json:"ttl,omitempty" mapstructure:"ttl"`
	MaxTTL         int64  `json:"max_ttl,omitempty" mapstructure:"max_ttl"`
}

func (r *AliCloudSecretBackendRoleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_alicloud_secret_backend_role"
}

func (r *AliCloudSecretBackendRoleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldMount: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Path of the AliCloud Secret Backend the role belongs to.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldName: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the role.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldRoleArn: schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "ARN of the RAM role to assume. If provided, inline_policies and remote_policies should be blank. The trusted principal of the role must be configured to allow assumption by the access key and secret configured in the backend.",
				Validators: []validator.String{
					stringvalidator.ConflictsWith(
						path.MatchRoot(consts.FieldInlinePolicies),
						path.MatchRoot(consts.FieldRemotePolicies),
					),
				},
			},
			consts.FieldInlinePolicies: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "JSON-encoded inline policy to be applied to the generated credentials. Deprecated: use remote_policies instead.",
				Validators: []validator.String{
					stringvalidator.ConflictsWith(
						path.MatchRoot(consts.FieldRoleArn),
					),
				},
			},
			consts.FieldRemotePolicies: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Comma-separated list of remote policy specifications in format 'name:PolicyName,type:PolicyType' (e.g., 'name:AliyunOSSReadOnlyAccess,type:System,name:AnotherPolicy,type:Custom').",
				Validators: []validator.String{
					stringvalidator.ConflictsWith(
						path.MatchRoot(consts.FieldRoleArn),
					),
				},
			},
			consts.FieldTTL: schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "Duration in seconds after which the issued credentials should expire. Defaults to 0, in which case the value will fallback to the system/mount defaults.",
			},
			consts.FieldMaxTTL: schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "The maximum allowed lifetime of credentials issued using this role.",
			},
		},
		MarkdownDescription: "Manages an AliCloud Secrets Engine role in Vault.",
	}

	base.MustAddBaseSchema(&resp.Schema)
}
func (r *AliCloudSecretBackendRoleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data AliCloudSecretBackendRoleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mount := data.Mount.ValueString()
	name := data.Name.ValueString()
	rolePath := fmt.Sprintf("%s/%s/%s", strings.Trim(mount, "/"), rolesAffix, strings.Trim(name, "/"))

	vaultRequest, diags := buildVaultRequestFromModel(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if _, err := cli.Logical().WriteWithContext(ctx, rolePath, vaultRequest); err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	// Read back the role to get computed values
	vaultResp, err := cli.Logical().ReadWithContext(ctx, rolePath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}

	if vaultResp == nil {
		resp.Diagnostics.AddError("Resource Not Found", "Role was created but could not be read back")
		return
	}

	diags = populateModelFromVaultResponse(ctx, &data, vaultResp)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AliCloudSecretBackendRoleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data AliCloudSecretBackendRoleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mount := data.Mount.ValueString()
	name := data.Name.ValueString()
	rolePath := fmt.Sprintf("%s/%s/%s", strings.Trim(mount, "/"), rolesAffix, strings.Trim(name, "/"))
	vaultResp, err := cli.Logical().ReadWithContext(ctx, rolePath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}

	if vaultResp == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	diags := populateModelFromVaultResponse(ctx, &data, vaultResp)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AliCloudSecretBackendRoleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data AliCloudSecretBackendRoleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mount := data.Mount.ValueString()
	name := data.Name.ValueString()
	rolePath := fmt.Sprintf("%s/%s/%s", strings.Trim(mount, "/"), rolesAffix, strings.Trim(name, "/"))

	vaultRequest, diags := buildVaultRequestFromModel(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if _, err := cli.Logical().WriteWithContext(ctx, rolePath, vaultRequest); err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}

	// Read back the role to get computed values
	vaultResp, err := cli.Logical().ReadWithContext(ctx, rolePath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}

	if vaultResp == nil {
		resp.Diagnostics.AddError("Resource Not Found", "Role was updated but could not be read back")
		return
	}

	diags = populateModelFromVaultResponse(ctx, &data, vaultResp)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AliCloudSecretBackendRoleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data AliCloudSecretBackendRoleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	mount := data.Mount.ValueString()
	name := data.Name.ValueString()
	rolePath := fmt.Sprintf("%s/%s/%s", strings.Trim(mount, "/"), rolesAffix, strings.Trim(name, "/"))

	if _, err := cli.Logical().DeleteWithContext(ctx, rolePath); err != nil {
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
		return
	}
}

func (r *AliCloudSecretBackendRoleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := req.ID

	// Parse the ID to extract mount and name
	// Expected format: <mount>/role/<name>
	matches := roleIDRegex.FindStringSubmatch(id)
	if len(matches) != 3 {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Expected format: <mount>/%s/<name>, got: %s", rolesAffix, id),
		)
		return
	}

	mount := matches[1]
	name := matches[2]

	// Set mount and name in state - these will trigger a Read to populate the rest
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldMount), mount)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldName), name)...)
}

// buildVaultRequestFromModel converts the Terraform model to a Vault API request
func buildVaultRequestFromModel(ctx context.Context, data *AliCloudSecretBackendRoleModel) (map[string]interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics
	request := make(map[string]interface{})

	// Always include role_arn (empty string if not set) to clear it when switching types
	if !data.RoleARN.IsNull() && !data.RoleARN.IsUnknown() {
		request[consts.FieldRoleArn] = data.RoleARN.ValueString()
	} else {
		request[consts.FieldRoleArn] = ""
	}

	// Always include inline_policies (empty array if not set) to clear it when switching types
	if !data.InlinePolicies.IsNull() && !data.InlinePolicies.IsUnknown() {
		// Parse JSON string, wrap in array, marshal back to JSON string
		// Vault validation expects string, but backend expects array in the string
		policyStr := data.InlinePolicies.ValueString()
		var policyObj map[string]interface{}
		if err := json.Unmarshal([]byte(policyStr), &policyObj); err != nil {
			diags.AddError(
				"Invalid inline policy JSON",
				fmt.Sprintf("Failed to parse inline policy: %v", err),
			)
			return nil, diags
		}
		// Wrap in array and convert to JSON string
		policyArray := []map[string]interface{}{policyObj}
		jsonBytes, _ := json.Marshal(policyArray)
		request[consts.FieldInlinePolicies] = string(jsonBytes)
	} else {
		// Send "[]" (JSON string of empty array) to clear the field
		request[consts.FieldInlinePolicies] = "[]"
	}

	// Always include remote_policies (empty array if not set) to clear it when switching types
	if !data.RemotePolicies.IsNull() && !data.RemotePolicies.IsUnknown() {
		// Parse comma-separated string and convert to array of strings
		// User provides: "name:X,type:Y,name:A,type:B"
		// We send: ["name:X,type:Y", "name:A,type:B"]
		policiesStr := data.RemotePolicies.ValueString()

		// Split by policy boundaries - each policy is "name:X,type:Y"
		// We need to parse "name:X,type:Y,name:A,type:B" into ["name:X,type:Y", "name:A,type:B"]
		parts := strings.Split(policiesStr, ",")
		var policies []string

		// Group every 2 parts (name and type) into one policy string
		for i := 0; i < len(parts); i += 2 {
			if i+1 < len(parts) {
				policyStr := parts[i] + "," + parts[i+1]
				policies = append(policies, policyStr)
			}
		}

		request[consts.FieldRemotePolicies] = policies
	} else {
		// Send empty array [] to clear the field
		request[consts.FieldRemotePolicies] = []string{}
	}

	request[consts.FieldTTL] = data.TTL.ValueInt64()

	request[consts.FieldMaxTTL] = data.MaxTTL.ValueInt64()

	return request, diags
}

// populateModelFromVaultResponse populates the Terraform model from a Vault API response
func populateModelFromVaultResponse(ctx context.Context, data *AliCloudSecretBackendRoleModel, resp *api.Secret) diag.Diagnostics {
	var diags diag.Diagnostics

	// role_arn: Vault returns empty string "" when not set (not null)
	data.RoleARN = types.StringNull()
	if v, ok := resp.Data[consts.FieldRoleArn]; ok && v != nil {
		if roleARN := v.(string); roleARN != "" {
			data.RoleARN = types.StringValue(roleARN)
		}
	}

	// inline_policies: Vault returns array [{"hash": "...", "policy_document": {...}}]
	// Extract policy_document and convert to JSON string
	data.InlinePolicies = types.StringNull()
	if v, ok := resp.Data[consts.FieldInlinePolicies]; ok && v != nil {
		policies, ok := v.([]interface{})
		if !ok || len(policies) == 0 {
			return diags
		}

		policyMap, ok := policies[0].(map[string]interface{})
		if !ok {
			return diags
		}

		policyDoc, ok := policyMap["policy_document"].(map[string]interface{})
		if !ok {
			return diags
		}

		jsonBytes, err := json.Marshal(policyDoc)
		if err != nil {
			diags.AddWarning("Failed to marshal inline policy", fmt.Sprintf("Error: %v", err))
			return diags
		}

		data.InlinePolicies = types.StringValue(string(jsonBytes))
	}

	// remote_policies: Vault returns array of objects [{"name": "...", "type": "..."}]
	// Convert to comma-separated string format
	data.RemotePolicies = types.StringNull()
	if v, ok := resp.Data[consts.FieldRemotePolicies]; ok && v != nil {
		policies, ok := v.([]interface{})
		if !ok || len(policies) == 0 {
			return diags
		}

		var policyStrs []string
		for _, policy := range policies {
			policyMap, ok := policy.(map[string]interface{})
			if !ok {
				continue
			}

			name, hasName := policyMap["name"].(string)
			policyType, hasType := policyMap["type"].(string)
			if hasName && hasType {
				policyStr := fmt.Sprintf("name:%s,type:%s", name, policyType)
				policyStrs = append(policyStrs, policyStr)
			}
		}

		if len(policyStrs) > 0 {
			data.RemotePolicies = types.StringValue(strings.Join(policyStrs, ","))
		}
	}

	// ttl: Set if Vault returns it
	if v, ok := resp.Data[consts.FieldTTL]; ok && v != nil {
		if ttlVal, ok := v.(int64); ok {
			data.TTL = types.Int64Value(ttlVal)
		}
	}

	// max_ttl: Set if Vault returns it
	if v, ok := resp.Data[consts.FieldMaxTTL]; ok && v != nil {
		if maxTTLVal, ok := v.(int64); ok {
			data.MaxTTL = types.Int64Value(maxTTLVal)
		}
	}

	return diags
}
