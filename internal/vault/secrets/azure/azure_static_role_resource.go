// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package azure

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"

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
	"github.com/hashicorp/terraform-provider-vault/internal/framework/model"
)

const staticRolesAffix = "static-roles"

var idRe = regexp.MustCompile(`^([^/]+)/` + staticRolesAffix + `/([^/]+)$`)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &AzureSecretsStaticRoleResource{}

// NewAzureStaticRoleResource returns the implementation for this resource to be
// imported by the Terraform Plugin Framework provider
func NewAzureStaticRoleResource() resource.Resource { return &AzureSecretsStaticRoleResource{} }

// AzureSecretsStaticRoleResource implements the methods that define this resource
type AzureSecretsStaticRoleResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

// AzureStaticRoleModel describes the Terraform resource data model to match the
// resource schema.
type AzureStaticRoleModel struct {
	base.BaseModelLegacy

	Backend             types.String `tfsdk:"backend"`
	Role                types.String `tfsdk:"role"`
	ApplicationObjectID types.String `tfsdk:"application_object_id"`
	TTL                 types.Int64  `tfsdk:"ttl"`
	Metadata            types.Map    `tfsdk:"metadata"`
	SecretID            types.String `tfsdk:"secret_id"`
	ClientSecret        types.String `tfsdk:"client_secret"`
	Expiration          types.String `tfsdk:"expiration"`
	SkipImportRotation  types.Bool   `tfsdk:"skip_import_rotation"`
}

// AzureStaticRoleAPIModel describes the Vault API data model.
type AzureStaticRoleAPIModel struct {
	ApplicationObjectID string            `json:"application_object_id" mapstructure:"application_object_id"`
	TTL                 any               `json:"ttl" mapstructure:"ttl"`
	Metadata            map[string]string `json:"metadata" mapstructure:"metadata"`
}

func (r *AzureSecretsStaticRoleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_secret_backend_static_role"
}

func (r *AzureSecretsStaticRoleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldBackend: schema.StringAttribute{
				MarkdownDescription: "The path where the Azure secrets backend is mounted.",
				Required:            true,
			},
			consts.FieldRole: schema.StringAttribute{
				MarkdownDescription: "Name of the static role to create.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldApplicationObjectID: schema.StringAttribute{
				MarkdownDescription: "Application object ID for an existing service principal that is managed by the static role.",
				Required:            true,
			},
			consts.FieldTTL: schema.Int64Attribute{
				MarkdownDescription: "Timespan of 1 year (31536000) or more during which the role credentials are valid.",
				Optional:            true,
				Computed:            true,
			},
			consts.FieldMetadata: schema.MapAttribute{
				MarkdownDescription: "A map of string key/value pairs that will be stored as metadata on the secret.",
				ElementType:         types.StringType,
				Optional:            true,
			},
			consts.FieldSecretID: schema.StringAttribute{
				MarkdownDescription: "The secret ID of the Azure password credential you want to import.",
				Optional:            true,
			},
			consts.FieldClientSecret: schema.StringAttribute{
				MarkdownDescription: "The plaintext secret value of the credential you want to import.",
				Optional:            true,
				Sensitive:           true,
			},
			consts.FieldExpiration: schema.StringAttribute{
				MarkdownDescription: "A future expiration time for the imported credential, in RFC3339 format.",
				Optional:            true,
			},
			consts.FieldSkipImportRotation: schema.BoolAttribute{
				MarkdownDescription: "If true, skip rotation of the client secret on import.",
				Optional:            true,
			},
		},
		MarkdownDescription: "Manage Azure static roles.",
	}
	base.MustAddLegacyBaseSchema(&resp.Schema)
}

// Create is called during the terraform apply command.
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/create
func (r *AzureSecretsStaticRoleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data AzureStaticRoleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	backend := data.Backend.ValueString()
	role := data.Role.ValueString()
	path := fmt.Sprintf("%s/%s/%s", backend, staticRolesAffix, role)

	vaultRequest, diags := buildVaultRequestFromModel(ctx, &data, true)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if _, err := cli.Logical().WriteWithContext(ctx, path, vaultRequest); err != nil {
		resp.Diagnostics.AddError(errutil.VaultCreateErr(err))
		return
	}

	data.ID = types.StringValue(makeID(backend, role))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during the terraform apply, terraform plan, and terraform
// refresh commands.
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/read
func (r *AzureSecretsStaticRoleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data AzureStaticRoleModel
	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	backend := data.Backend.ValueString()
	role := data.Role.ValueString()
	path := fmt.Sprintf("%s/%s/%s", backend, staticRolesAffix, role)

	readResp, err := cli.Logical().ReadWithContext(ctx, path)
	if err != nil {
		resp.Diagnostics.AddError(errutil.VaultReadErr(err))
		return
	}
	if readResp == nil {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	var apiModel AzureStaticRoleAPIModel
	err = model.ToAPIModel(readResp.Data, &apiModel)
	if err != nil {
		resp.Diagnostics.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Map values back to Terraform model
	data.ApplicationObjectID = types.StringValue(apiModel.ApplicationObjectID)
	val, diags := types.MapValueFrom(ctx, types.StringType, apiModel.Metadata)

	// Normalize TTL value since Vault can return either a string or a number
	ttlSeconds, err := normalizeTTL(apiModel.TTL)
	if err != nil {
		resp.Diagnostics.AddError("Invalid TTL format from Vault", err.Error())
		return
	}
	data.TTL = types.Int64Value(ttlSeconds)

	resp.Diagnostics.Append(diags...)
	data.Metadata = val
	data.ID = types.StringValue(makeID(backend, role))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AzureSecretsStaticRoleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data AzureStaticRoleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	backend := data.Backend.ValueString()
	role := data.Role.ValueString()
	path := fmt.Sprintf("%s/%s/%s", backend, staticRolesAffix, role)

	vaultRequest, diags := buildVaultRequestFromModel(ctx, &data, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if _, err := cli.Logical().WriteWithContext(ctx, path, vaultRequest); err != nil {
		resp.Diagnostics.AddError(errutil.VaultUpdateErr(err))
		return
	}

	data.ID = types.StringValue(makeID(backend, role))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func buildVaultRequestFromModel(ctx context.Context, data *AzureStaticRoleModel, includeSkipImport bool) (map[string]any, diag.Diagnostics) {
	var diags diag.Diagnostics

	vaultRequest := map[string]any{
		consts.FieldApplicationObjectID: data.ApplicationObjectID.ValueString(),
	}

	fieldMap := map[string]any{
		consts.FieldSecretID:     data.SecretID.ValueString(),
		consts.FieldClientSecret: data.ClientSecret.ValueString(),
		consts.FieldExpiration:   data.Expiration.ValueString(),
	}

	for k, v := range fieldMap {
		if s, ok := v.(string); ok && s != "" {
			vaultRequest[k] = s
		}
	}

	if !data.TTL.IsNull() {
		vaultRequest[consts.FieldTTL] = data.TTL.ValueInt64()
	}

	if !data.Metadata.IsNull() && !data.Metadata.IsUnknown() {
		var meta map[string]string
		if mdDiags := data.Metadata.ElementsAs(ctx, &meta, false); mdDiags.HasError() {
			diags.Append(mdDiags...)
			return nil, diags
		}
		vaultRequest[consts.FieldMetadata] = meta
	}

	// only include on create and only when true
	if includeSkipImport && data.SkipImportRotation.ValueBool() {
		vaultRequest[consts.FieldSkipImportRotation] = true
	}

	return vaultRequest, diags
}

func (r *AzureSecretsStaticRoleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data AzureStaticRoleModel

	// Load state
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	backend := data.Backend.ValueString()
	role := data.Role.ValueString()
	path := fmt.Sprintf("%s/%s/%s", backend, staticRolesAffix, role)

	if _, err := cli.Logical().DeleteWithContext(ctx, path); err != nil {
		resp.Diagnostics.AddError(errutil.VaultDeleteErr(err))
		return
	}
}

func (r *AzureSecretsStaticRoleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := req.ID

	matches := idRe.FindStringSubmatch(id)
	if len(matches) != 3 {
		resp.Diagnostics.AddError(
			"Unexpected Import Identifier",
			fmt.Sprintf("Expected ID in format '<backend>/static-roles/<role>', got: %q", id),
		)
		return
	}

	backend := matches[1]
	role := matches[2]

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldBackend), backend)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(consts.FieldRole), role)...)

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}

func makeID(backend, role string) string {
	return fmt.Sprintf("%s/%s/%s", backend, staticRolesAffix, role)
}

// normalizeTTL converts Vault TTL (string or number) into seconds as int64
// Since Vault may return either a string or number for TTL, we need to
// normalize it, so we have a consistent type.
func normalizeTTL(ttl any) (int64, error) {
	if ttl == nil {
		return 0, nil
	}

	switch v := ttl.(type) {
	case int:
		return int64(v), nil
	case int64:
		return v, nil
	case float64:
		return int64(v), nil
	case string:
		if d, err := time.ParseDuration(v); err == nil {
			return int64(d / time.Second), nil
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("unsupported TTL string: %q", v)
		}
		return n, nil
	}
	return 0, fmt.Errorf("unsupported TTL type: %T", ttl)
}
