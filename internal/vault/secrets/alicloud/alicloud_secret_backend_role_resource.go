// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package alicloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
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
)

const rolesAffix = "role"

var roleIDRegex = regexp.MustCompile(`^(.+)/` + rolesAffix + `/(.+)$`)

// Ensure the implementation satisfies the expected interfaces
var _ resource.ResourceWithConfigure = &AliCloudSecretBackendRoleResource{}
var _ resource.ResourceWithImportState = &AliCloudSecretBackendRoleResource{}
var _ resource.ResourceWithValidateConfig = &AliCloudSecretBackendRoleResource{}

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
	InlinePolicies types.Set    `tfsdk:"inline_policies"`
	RemotePolicies types.Set    `tfsdk:"remote_policies"`
	TTL            types.Int64  `tfsdk:"ttl"`
	MaxTTL         types.Int64  `tfsdk:"max_ttl"`
}

// InlinePolicyModel is the Terraform model for a single inline policy nested object.
type InlinePolicyModel struct {
	PolicyDocument types.String `tfsdk:"policy_document"`
}

// RemotePolicyModel is the Terraform model for a single remote policy nested object.
type RemotePolicyModel struct {
	Name types.String `tfsdk:"name"`
	Type types.String `tfsdk:"type"`
}

// inlinePolicyAttrTypes returns the attr.Type map for InlinePolicyModel,
// used to construct types.Set values for the inline_policies attribute.
func inlinePolicyAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		consts.FieldPolicyDocument: types.StringType,
	}
}

// remotePolicyAttrTypes returns the attr.Type map for RemotePolicyModel,
// used to construct types.Set values for the remote_policies attribute.
func remotePolicyAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		consts.FieldName: types.StringType,
		consts.FieldType: types.StringType,
	}
}

// vaultRoleEntry mirrors the upstream Vault AliCloud plugin's roleEntry struct.
// Used to deserialize Vault API responses via model.ToAPIModel.
type vaultRoleEntry struct {
	RoleARN        string          `json:"role_arn"`
	RemotePolicies []*remotePolicy `json:"remote_policies"`
	InlinePolicies []*inlinePolicy `json:"inline_policies"`
	TTL            json.Number     `json:"ttl"`
	MaxTTL         json.Number     `json:"max_ttl"`
}

// inlinePolicy mirrors the upstream plugin's inlinePolicy struct.
type inlinePolicy struct {
	Hash           string                 `json:"hash"`
	PolicyDocument map[string]interface{} `json:"policy_document"`
}

// remotePolicy mirrors the upstream plugin's remotePolicy struct.
type remotePolicy struct {
	Name string `json:"name"`
	Type string `json:"type"`
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
				MarkdownDescription: "ARN of the RAM role to assume. If provided, inline_policies and remote_policies should be blank. The trusted principal of the role must be configured to allow assumption by the access key and secret configured in the backend.",
				// Note: Declarative ConflictsWith validators (stringvalidator.ConflictsWith)
				// cannot be used between attributes and SetNestedBlock because blocks
				// are always present as an empty set (not null) when unspecified in config,
				// which causes ConflictsWith to always trigger a false positive.
				// The conflict is enforced via ValidateConfig instead.
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
		// SetNestedBlock is used (instead of flat Set(String) attributes) because:
		// 1. remote_policies has two fields (name + type) that must be grouped per
		//    policy — flat sets are unordered so separate name/type sets can’t
		//    guarantee pairing, and encoding both into one string ("name:X,type:Y")
		//    is poor UX with no per-field validation.
		// 2. inline_policies uses the same block pattern for consistency, and to
		//    match the Vault API response structure ([{hash, policy_document}]
		//    objects). This also allows extensibility if the API adds fields.
		//
		//
		// Note: SetNestedAttribute would be preferred but requires protocol v6.
		// This provider is pinned to v5 (tf5muxserver with 311 legacy SDK
		// resources), so SetNestedBlock is the v5-compatible equivalent.
		Blocks: map[string]schema.Block{
			consts.FieldInlinePolicies: schema.SetNestedBlock{
				MarkdownDescription: "Set of inline policy documents to be applied to the generated credentials. " +
					"Each block represents one policy with a JSON-encoded policy_document field.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						consts.FieldPolicyDocument: schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "JSON-encoded inline policy document.",
						},
					},
				},
			},
			consts.FieldRemotePolicies: schema.SetNestedBlock{
				MarkdownDescription: "Set of remote policy specifications to attach to the generated credentials. " +
					"Each block groups a policy name with its type (System or Custom).",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						consts.FieldName: schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "Name of the remote policy.",
						},
						consts.FieldType: schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "Type of the remote policy (System or Custom).",
						},
					},
				},
			},
		},
		MarkdownDescription: "Manages an AliCloud Secrets Engine role in Vault.",
	}

	base.MustAddBaseSchema(&resp.Schema)
}

// path constructs the Vault API path for the role.
func (r *AliCloudSecretBackendRoleResource) path(data *AliCloudSecretBackendRoleModel) string {
	return fmt.Sprintf("%s/%s/%s", strings.Trim(data.Mount.ValueString(), "/"), rolesAffix, strings.Trim(data.Name.ValueString(), "/"))
}

// ValidateConfig implements resource.ResourceWithValidateConfig.
// This provides plan-time validation for the mutual exclusivity between
// role_arn and inline_policies/remote_policies.
//
// Declarative ConflictsWith validators cannot be used between attributes
// and SetNestedBlock because blocks are always present as an empty set
// (not null) when unspecified, causing ConflictsWith to always fire.
func (r *AliCloudSecretBackendRoleResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data AliCloudSecretBackendRoleModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hasRoleARN := !data.RoleARN.IsNull() && !data.RoleARN.IsUnknown() && data.RoleARN.ValueString() != ""
	hasInline := len(data.InlinePolicies.Elements()) > 0
	hasRemote := len(data.RemotePolicies.Elements()) > 0

	if hasRoleARN && (hasInline || hasRemote) {
		resp.Diagnostics.AddAttributeError(
			path.Root(consts.FieldRoleArn),
			"Conflicting configuration arguments",
			"\"role_arn\" cannot be set together with \"inline_policies\" or \"remote_policies\". "+
				"Use either role_arn for STS assumed roles, or inline_policies/remote_policies for RAM user credentials.",
		)
	}
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

	rolePath := r.path(&data)

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
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
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

	rolePath := r.path(&data)
	vaultResp, err := cli.Logical().ReadWithContext(ctx, rolePath)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}

	if vaultResp == nil {
		tflog.Warn(ctx, "AliCloud secret backend role not found, removing from state")
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

	rolePath := r.path(&data)

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
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
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

	rolePath := r.path(&data)

	if _, err := cli.Logical().DeleteWithContext(ctx, rolePath); err != nil {
		var respErr *api.ResponseError
		if errors.As(err, &respErr) && respErr.StatusCode == 404 {
			return
		}
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
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

	// Set namespace from environment variable if provided
	// This supports importing resources that exist inside a Vault namespace
	ns := os.Getenv(consts.EnvVarVaultNamespaceImport)
	if ns != "" {
		tflog.Info(
			ctx,
			fmt.Sprintf("Environment variable %s set, attempting TF state import with namespace", consts.EnvVarVaultNamespaceImport),
			map[string]any{consts.FieldNamespace: ns},
		)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...)
	}
}

// toVaultRequest converts the vaultRoleEntry to a Vault API write request map.
// This handles the type asymmetry between read and write formats:
//   - inline_policies: []*inlinePolicy → JSON string (framework.TypeString)
//   - remote_policies: []*remotePolicy → []string{"name:X,type:Y"} (framework.TypeStringSlice)
func (r *vaultRoleEntry) toVaultRequest() (map[string]interface{}, error) {
	request := map[string]interface{}{
		consts.FieldRoleArn: r.RoleARN,
	}

	// inline_policies: serialize policy documents to JSON string
	if len(r.InlinePolicies) > 0 {
		var policyDocs []map[string]interface{}
		for _, p := range r.InlinePolicies {
			if p != nil && p.PolicyDocument != nil {
				policyDocs = append(policyDocs, p.PolicyDocument)
			}
		}
		jsonBytes, err := json.Marshal(policyDocs)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal inline policies: %w", err)
		}
		request[consts.FieldInlinePolicies] = string(jsonBytes)
	} else {
		request[consts.FieldInlinePolicies] = "[]"
	}

	// remote_policies: serialize to []string{"name:X,type:Y"}
	if len(r.RemotePolicies) > 0 {
		var policies []string
		for _, p := range r.RemotePolicies {
			if p != nil && p.Name != "" && p.Type != "" {
				policies = append(policies, fmt.Sprintf("name:%s,type:%s", p.Name, p.Type))
			}
		}
		request[consts.FieldRemotePolicies] = policies
	} else {
		request[consts.FieldRemotePolicies] = []string{}
	}

	// TTL fields: convert json.Number to int64
	if ttl, err := r.TTL.Int64(); err == nil {
		request[consts.FieldTTL] = ttl
	} else {
		request[consts.FieldTTL] = int64(0)
	}
	if maxTTL, err := r.MaxTTL.Int64(); err == nil {
		request[consts.FieldMaxTTL] = maxTTL
	} else {
		request[consts.FieldMaxTTL] = int64(0)
	}

	return request, nil
}

// buildVaultRequestFromModel converts the Terraform model to a Vault API request.
// It first populates a vaultRoleEntry struct from the TF model using ElementsAs
// on the SetNestedBlock fields, then calls toVaultRequest() to serialize
// it into the format expected by the upstream plugin.
func buildVaultRequestFromModel(ctx context.Context, data *AliCloudSecretBackendRoleModel) (map[string]interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics

	role := &vaultRoleEntry{
		TTL:    json.Number(fmt.Sprintf("%d", data.TTL.ValueInt64())),
		MaxTTL: json.Number(fmt.Sprintf("%d", data.MaxTTL.ValueInt64())),
	}

	// role_arn: empty string if not set, to clear it when switching credential types
	if !data.RoleARN.IsNull() && !data.RoleARN.IsUnknown() {
		role.RoleARN = data.RoleARN.ValueString()
	}

	// inline_policies: extract typed InlinePolicyModel set via ElementsAs
	if len(data.InlinePolicies.Elements()) > 0 {
		var inlinePolicies []InlinePolicyModel
		diags.Append(data.InlinePolicies.ElementsAs(ctx, &inlinePolicies, false)...)
		if diags.HasError() {
			return nil, diags
		}
		for _, p := range inlinePolicies {
			var policyDoc map[string]interface{}
			if err := json.Unmarshal([]byte(p.PolicyDocument.ValueString()), &policyDoc); err != nil {
				diags.AddError(
					"Invalid inline policy JSON",
					fmt.Sprintf("Failed to parse inline policy document: %v", err),
				)
				return nil, diags
			}
			role.InlinePolicies = append(role.InlinePolicies, &inlinePolicy{
				PolicyDocument: policyDoc,
			})
		}
	}

	// remote_policies: extract typed RemotePolicyModel set via ElementsAs
	if len(data.RemotePolicies.Elements()) > 0 {
		var remotePolicies []RemotePolicyModel
		diags.Append(data.RemotePolicies.ElementsAs(ctx, &remotePolicies, false)...)
		if diags.HasError() {
			return nil, diags
		}
		for _, p := range remotePolicies {
			role.RemotePolicies = append(role.RemotePolicies, &remotePolicy{
				Name: p.Name.ValueString(),
				Type: p.Type.ValueString(),
			})
		}
	}

	// Convert the typed struct to Vault API request format
	request, err := role.toVaultRequest()
	if err != nil {
		diags.AddError("Failed to build Vault request", err.Error())
		return nil, diags
	}

	return request, diags
}

// populateModelFromVaultResponse deserializes the Vault API response into the
// vaultRoleEntry API model struct (matching the upstream plugin's roleEntry),
// then maps the relevant fields to the Terraform state model.
// The hash/UUID field from inlinePolicy is discarded — only policy_document
// is stored in state to prevent drift from server-generated values.
func populateModelFromVaultResponse(ctx context.Context, data *AliCloudSecretBackendRoleModel, resp *api.Secret) diag.Diagnostics {
	var diags diag.Diagnostics

	// Deserialize Vault response into the API model struct
	var role vaultRoleEntry
	if err := model.ToAPIModel(resp.Data, &role); err != nil {
		diags.AddError("Failed to parse Vault response", err.Error())
		return diags
	}

	// role_arn: store as null (not empty string) when Vault returns empty,
	// so that after role_arn is cleared, subsequent plans see null config
	// vs null state = no drift. Previously Computed: true suppressed the
	// initial diff that triggers the clearing Update.
	if role.RoleARN != "" {
		data.RoleARN = types.StringValue(role.RoleARN)
	} else {
		data.RoleARN = types.StringNull()
	}

	// inline_policies: extract policy_document, discard hash (server-generated UUID),
	// build typed types.Set of InlinePolicyModel objects
	if len(role.InlinePolicies) > 0 {
		var policyObjects []InlinePolicyModel
		for _, p := range role.InlinePolicies {
			if p != nil && p.PolicyDocument != nil {
				jsonBytes, err := json.Marshal(p.PolicyDocument)
				if err != nil {
					diags.AddWarning("Failed to marshal inline policy document", err.Error())
					continue
				}
				policyObjects = append(policyObjects, InlinePolicyModel{
					PolicyDocument: types.StringValue(string(jsonBytes)),
				})
			}
		}
		if len(policyObjects) > 0 {
			setVal, setDiags := types.SetValueFrom(ctx, types.ObjectType{AttrTypes: inlinePolicyAttrTypes()}, policyObjects)
			diags.Append(setDiags...)
			data.InlinePolicies = setVal
		} else {
			data.InlinePolicies = types.SetValueMust(types.ObjectType{AttrTypes: inlinePolicyAttrTypes()}, []attr.Value{})
		}
	} else {
		data.InlinePolicies = types.SetValueMust(types.ObjectType{AttrTypes: inlinePolicyAttrTypes()}, []attr.Value{})
	}

	// remote_policies: convert remotePolicy structs to typed types.Set of RemotePolicyModel
	if len(role.RemotePolicies) > 0 {
		var policyObjects []RemotePolicyModel
		for _, p := range role.RemotePolicies {
			if p != nil && p.Name != "" && p.Type != "" {
				policyObjects = append(policyObjects, RemotePolicyModel{
					Name: types.StringValue(p.Name),
					Type: types.StringValue(p.Type),
				})
			}
		}
		if len(policyObjects) > 0 {
			setVal, setDiags := types.SetValueFrom(ctx, types.ObjectType{AttrTypes: remotePolicyAttrTypes()}, policyObjects)
			diags.Append(setDiags...)
			data.RemotePolicies = setVal
		} else {
			data.RemotePolicies = types.SetValueMust(types.ObjectType{AttrTypes: remotePolicyAttrTypes()}, []attr.Value{})
		}
	} else {
		data.RemotePolicies = types.SetValueMust(types.ObjectType{AttrTypes: remotePolicyAttrTypes()}, []attr.Value{})
	}

	// TTL fields: Only set in state if non-zero, otherwise leave as null.
	// This prevents drift when the field is omitted from config (null) and
	// Vault returns 0 (system default). Without Computed: true, null config
	// vs null state = no change detected.
	if ttlVal, err := role.TTL.Int64(); err == nil && ttlVal != 0 {
		data.TTL = types.Int64Value(ttlVal)
	}

	if maxTTLVal, err := role.MaxTTL.Int64(); err == nil && maxTTLVal != 0 {
		data.MaxTTL = types.Int64Value(maxTTLVal)
	}

	return diags
}
