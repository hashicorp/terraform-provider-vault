// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
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
var _ resource.ResourceWithConfigure = &OAuthResourceServerConfigProfileResource{}

// NewOAuthResourceServerConfigProfileResource returns the implementation for this resource
func NewOAuthResourceServerConfigProfileResource() resource.Resource {
	return &OAuthResourceServerConfigProfileResource{}
}

// OAuthResourceServerConfigProfileResource implements the resource
type OAuthResourceServerConfigProfileResource struct {
	base.ResourceWithConfigure
}

// PublicKeyModel represents a public key with key_id and pem
type PublicKeyModel struct {
	KeyID types.String `tfsdk:"key_id"`
	PEM   types.String `tfsdk:"pem"`
}

// OAuthResourceServerConfigProfileModel describes the Terraform resource data model
type OAuthResourceServerConfigProfileModel struct {
	base.BaseModel

	// Computed ID field
	ID types.String `tfsdk:"id"`

	// Required fields
	ProfileName types.String `tfsdk:"profile_name"`
	IssuerId    types.String `tfsdk:"issuer_id"`

	// Configuration mode
	UseJWKS types.Bool `tfsdk:"use_jwks"`

	// JWKS-specific fields (when use_jwks=true)
	JWKSUri   types.String `tfsdk:"jwks_uri"`
	JwksCaPem types.String `tfsdk:"jwks_ca_pem"`

	// PEM-specific fields (when use_jwks=false)
	PublicKeys types.List `tfsdk:"public_keys"` // List of PublicKeyModel

	// Optional fields
	Audiences           types.List   `tfsdk:"audiences"` // List of strings
	NoDefaultPolicy     types.Bool   `tfsdk:"no_default_policy"`
	UserClaim           types.String `tfsdk:"user_claim"`
	SupportedAlgorithms types.List   `tfsdk:"supported_algorithms"` // List of strings
	JwtType             types.String `tfsdk:"jwt_type"`
	ClockSkewLeeway     types.Int64  `tfsdk:"clock_skew_leeway"`
	Enabled             types.Bool   `tfsdk:"enabled"`
}

// OAuthResourceServerConfigProfileAPIModel describes the Vault API data model
type OAuthResourceServerConfigProfileAPIModel struct {
	ConfigID            string              `json:"config_id" mapstructure:"config_id"`
	ProfileName         string              `json:"profile_name" mapstructure:"profile_name"`
	IssuerId            string              `json:"issuer_id" mapstructure:"issuer_id"`
	UseJWKS             bool                `json:"use_jwks" mapstructure:"use_jwks"`
	JWKSUri             string              `json:"jwks_uri" mapstructure:"jwks_uri"`
	JwksCaPem           string              `json:"jwks_ca_pem" mapstructure:"jwks_ca_pem"`
	PublicKeys          []PublicKeyAPIModel `json:"public_keys" mapstructure:"public_keys"`
	Audiences           []string            `json:"audiences" mapstructure:"audiences"`
	NoDefaultPolicy     bool                `json:"no_default_policy" mapstructure:"no_default_policy"`
	UserClaim           string              `json:"user_claim" mapstructure:"user_claim"`
	SupportedAlgorithms []string            `json:"supported_algorithms" mapstructure:"supported_algorithms"`
	JwtType             string              `json:"jwt_type" mapstructure:"jwt_type"`
	ClockSkewLeeway     int                 `json:"clock_skew_leeway" mapstructure:"clock_skew_leeway"`
	Enabled             bool                `json:"enabled" mapstructure:"enabled"`
}

// PublicKeyAPIModel represents a public key in the API
type PublicKeyAPIModel struct {
	KeyID string `json:"key_id" mapstructure:"key_id"`
	PEM   string `json:"pem" mapstructure:"pem"`
}

// Metadata defines the resource name
func (r *OAuthResourceServerConfigProfileResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_oauth_resource_server_config_profile"
}

// Schema defines the resource schema
func (r *OAuthResourceServerConfigProfileResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			consts.FieldID: schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Unique identifier for this resource. This is a stable UUID that persists across updates.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			consts.FieldProfileName: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The name of the OAuth Resource Server Configuration profile. Must be unique within the namespace.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldIssuerId: schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The issuer ID (iss claim) to validate against in incoming JWTs.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			consts.FieldUseJWKS: schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "If true, use JWKS URI for key validation; if false, use static public keys. Defaults to true.",
			},
			consts.FieldJWKSURI: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The JWKS URI to fetch public keys from. Required when use_jwks=true.",
			},
			consts.FieldJwksCaPem: schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Optional CA certificate (PEM format) for JWKS URI TLS validation.",
			},
			consts.FieldAudiences: schema.ListAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "List of allowed audiences (aud claim) to validate in JWTs.",
			},
			consts.FieldNoDefaultPolicy: schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "If true, JWT-authenticated tokens omit the default policy unless added elsewhere. Defaults to false.",
			},
			consts.FieldUserClaim: schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("sub"),
				MarkdownDescription: "The claim to use as the user identifier. Defaults to 'sub'.",
			},
			consts.FieldSupportedAlgorithms: schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Default: listdefault.StaticValue(types.ListValueMust(types.StringType, []attr.Value{
					types.StringValue("RS256"),
					types.StringValue("RS384"),
					types.StringValue("RS512"),
					types.StringValue("ES256"),
					types.StringValue("ES384"),
					types.StringValue("ES512"),
					types.StringValue("PS256"),
					types.StringValue("PS384"),
					types.StringValue("PS512"),
				})),
				MarkdownDescription: "List of supported signing algorithms (e.g., RS256, ES256). Defaults to all supported algorithms.",
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.OneOf("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"),
					),
				},
			},
			consts.FieldJwtType: schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("access_token"),
				MarkdownDescription: "The JWT type: 'access_token' or 'transaction_token'. Defaults to 'access_token'.",
				Validators: []validator.String{
					stringvalidator.OneOf("access_token", "transaction_token"),
				},
			},
			consts.FieldClockSkewLeeway: schema.Int64Attribute{
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(0),
				MarkdownDescription: "Leeway for clock skew in seconds when validating time-based claims. Defaults to 0.",
			},
			consts.FieldEnabled: schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "Whether this profile is enabled for JWT validation. Disabled profiles are ignored. Defaults to true.",
			},
		},
		// Note: ListNestedBlock is used instead of ListNestedAttribute because this provider
		// is pinned to protocol v5. ListNestedAttribute requires protocol v6.
		Blocks: map[string]schema.Block{
			consts.FieldPublicKeys: schema.ListNestedBlock{
				MarkdownDescription: "List of static public keys with key_id and pem fields. Required when use_jwks=false.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						consts.FieldKeyID: schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "The key ID (kid) for this public key.",
						},
						"pem": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "The PEM-encoded public key.",
						},
					},
				},
			},
		},
		MarkdownDescription: "Manages OAuth Resource Server Configuration profiles in Vault Enterprise. " +
			"These profiles define how Vault validates JWT tokens from OAuth 2.0 resource servers.",
	}

	base.MustAddBaseSchema(&resp.Schema)
}

// Create is called during terraform apply
func (r *OAuthResourceServerConfigProfileResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data OAuthResourceServerConfigProfileModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check if Enterprise is supported
	if !provider.IsEnterpriseSupported(r.Meta()) {
		resp.Diagnostics.AddError(
			"Enterprise Feature Required",
			"OAuth Resource Server Configuration is only available in Vault Enterprise",
		)
		return
	}

	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Build the request payload
	vaultRequest := r.buildVaultRequest(ctx, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate mutual exclusivity
	if err := r.validateConfiguration(&data, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Configuration Validation Error", err.Error())
		return
	}

	path := r.profilePath(data.ProfileName.ValueString())
	_, err = client.Logical().WriteWithContext(ctx, path, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultCreateErr(err),
		)
		return
	}

	// Read back to get computed fields including config_id
	r.readFromVault(ctx, client, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read is called during terraform apply, plan, and refresh
func (r *OAuthResourceServerConfigProfileResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data OAuthResourceServerConfigProfileModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	r.readFromVault(ctx, client, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update is called during terraform apply
func (r *OAuthResourceServerConfigProfileResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state OAuthResourceServerConfigProfileModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	client, err := client.GetClient(ctx, r.Meta(), plan.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Build the request payload
	vaultRequest := r.buildVaultRequest(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate mutual exclusivity
	if err := r.validateConfiguration(&plan, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError("Configuration Validation Error", err.Error())
		return
	}

	path := r.profilePath(plan.ProfileName.ValueString())
	_, err = client.Logical().WriteWithContext(ctx, path, vaultRequest)
	if err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultUpdateErr(err),
		)
		return
	}

	// Read back the updated profile
	r.readFromVault(ctx, client, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete is called during terraform apply
func (r *OAuthResourceServerConfigProfileResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data OAuthResourceServerConfigProfileModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	path := r.profilePath(data.ProfileName.ValueString())
	_, err = client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		resp.Diagnostics.AddError(
			errutil.VaultDeleteErr(err),
		)
		return
	}
}

// ImportState implements resource.ResourceWithImportState
func (r *OAuthResourceServerConfigProfileResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import by profile_name, optionally with namespace prefix
	// Format: profile_name or namespace/profile_name
	profileName := req.ID
	namespace := ""

	if strings.Contains(req.ID, "/") {
		parts := strings.SplitN(req.ID, "/", 2)
		if len(parts) == 2 {
			namespace = parts[0]
			profileName = parts[1]
		}
	}

	var data OAuthResourceServerConfigProfileModel
	data.ProfileName = types.StringValue(profileName)

	if namespace != "" {
		data.Namespace = types.StringValue(namespace)
	}

	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	r.readFromVault(ctx, client, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// readFromVault reads the profile from Vault and updates the model
func (r *OAuthResourceServerConfigProfileResource) readFromVault(ctx context.Context, client *api.Client, data *OAuthResourceServerConfigProfileModel, diags *diag.Diagnostics) {
	path := r.profilePath(data.ProfileName.ValueString())

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

	var apiModel OAuthResourceServerConfigProfileAPIModel
	err = model.ToAPIModel(readResp.Data, &apiModel)
	if err != nil {
		diags.AddError("Unable to translate Vault response data", err.Error())
		return
	}

	// Update model with API response
	data.ProfileName = types.StringValue(apiModel.ProfileName)
	// ID should be the stable config_id from the API
	data.ID = types.StringValue(apiModel.ConfigID)
	data.IssuerId = types.StringValue(apiModel.IssuerId)
	data.UseJWKS = types.BoolValue(apiModel.UseJWKS)
	data.NoDefaultPolicy = types.BoolValue(apiModel.NoDefaultPolicy)
	data.Enabled = types.BoolValue(apiModel.Enabled)

	// JWKS fields
	if apiModel.JWKSUri != "" {
		data.JWKSUri = types.StringValue(apiModel.JWKSUri)
	} else {
		data.JWKSUri = types.StringNull()
	}

	if apiModel.JwksCaPem != "" {
		data.JwksCaPem = types.StringValue(apiModel.JwksCaPem)
	} else {
		data.JwksCaPem = types.StringNull()
	}

	// Public keys
	if len(apiModel.PublicKeys) > 0 {
		publicKeys := make([]PublicKeyModel, 0, len(apiModel.PublicKeys))
		for _, pk := range apiModel.PublicKeys {
			publicKeys = append(publicKeys, PublicKeyModel{
				KeyID: types.StringValue(pk.KeyID),
				PEM:   types.StringValue(pk.PEM),
			})
		}
		pkList, d := types.ListValueFrom(ctx, types.ObjectType{
			AttrTypes: map[string]attr.Type{
				consts.FieldKeyID: types.StringType,
				"pem":             types.StringType,
			},
		}, publicKeys)
		diags.Append(d...)
		if !diags.HasError() {
			data.PublicKeys = pkList
		}
	} else {
		data.PublicKeys = types.ListNull(types.ObjectType{
			AttrTypes: map[string]attr.Type{
				consts.FieldKeyID: types.StringType,
				"pem":             types.StringType,
			},
		})
	}

	// Optional string fields
	if apiModel.UserClaim != "" {
		data.UserClaim = types.StringValue(apiModel.UserClaim)
	}

	if apiModel.JwtType != "" {
		data.JwtType = types.StringValue(apiModel.JwtType)
	}

	// Audiences
	if len(apiModel.Audiences) > 0 {
		audiences, d := types.ListValueFrom(ctx, types.StringType, apiModel.Audiences)
		diags.Append(d...)
		if !diags.HasError() {
			data.Audiences = audiences
		}
	} else {
		data.Audiences = types.ListNull(types.StringType)
	}

	// Supported algorithms
	if len(apiModel.SupportedAlgorithms) > 0 {
		algorithms, d := types.ListValueFrom(ctx, types.StringType, apiModel.SupportedAlgorithms)
		diags.Append(d...)
		if !diags.HasError() {
			data.SupportedAlgorithms = algorithms
		}
	}

	// Clock skew leeway
	data.ClockSkewLeeway = types.Int64Value(int64(apiModel.ClockSkewLeeway))
}

// buildVaultRequest builds the Vault API request from the Terraform model
func (r *OAuthResourceServerConfigProfileResource) buildVaultRequest(ctx context.Context, data *OAuthResourceServerConfigProfileModel, diags *diag.Diagnostics) map[string]interface{} {
	vaultRequest := map[string]interface{}{
		consts.FieldIssuerId: data.IssuerId.ValueString(),
		consts.FieldUseJWKS:  data.UseJWKS.ValueBool(),
	}

	// JWKS fields
	if !data.JWKSUri.IsNull() && !data.JWKSUri.IsUnknown() {
		vaultRequest[consts.FieldJWKSURI] = data.JWKSUri.ValueString()
	}

	if !data.JwksCaPem.IsNull() && !data.JwksCaPem.IsUnknown() {
		vaultRequest[consts.FieldJwksCaPem] = data.JwksCaPem.ValueString()
	}

	// Public keys
	if !data.PublicKeys.IsNull() && !data.PublicKeys.IsUnknown() {
		var publicKeys []PublicKeyModel
		diags.Append(data.PublicKeys.ElementsAs(ctx, &publicKeys, false)...)
		if !diags.HasError() {
			apiPublicKeys := make([]map[string]interface{}, 0, len(publicKeys))
			for _, pk := range publicKeys {
				apiPublicKeys = append(apiPublicKeys, map[string]interface{}{
					consts.FieldKeyID: pk.KeyID.ValueString(),
					"pem":             pk.PEM.ValueString(),
				})
			}
			vaultRequest[consts.FieldPublicKeys] = apiPublicKeys
		}
	}

	// Audiences
	if !data.Audiences.IsNull() && !data.Audiences.IsUnknown() {
		var audiences []string
		diags.Append(data.Audiences.ElementsAs(ctx, &audiences, false)...)
		if !diags.HasError() {
			vaultRequest[consts.FieldAudiences] = audiences
		}
	}

	// Optional boolean fields
	if !data.NoDefaultPolicy.IsNull() && !data.NoDefaultPolicy.IsUnknown() {
		vaultRequest[consts.FieldNoDefaultPolicy] = data.NoDefaultPolicy.ValueBool()
	}

	if !data.Enabled.IsNull() && !data.Enabled.IsUnknown() {
		vaultRequest[consts.FieldEnabled] = data.Enabled.ValueBool()
	}

	// Optional string fields
	if !data.UserClaim.IsNull() && !data.UserClaim.IsUnknown() {
		vaultRequest[consts.FieldUserClaim] = data.UserClaim.ValueString()
	}

	if !data.JwtType.IsNull() && !data.JwtType.IsUnknown() {
		vaultRequest[consts.FieldJwtType] = data.JwtType.ValueString()
	}

	// Supported algorithms
	if !data.SupportedAlgorithms.IsNull() && !data.SupportedAlgorithms.IsUnknown() {
		var algorithms []string
		diags.Append(data.SupportedAlgorithms.ElementsAs(ctx, &algorithms, false)...)
		if !diags.HasError() {
			vaultRequest[consts.FieldSupportedAlgorithms] = algorithms
		}
	}

	// Clock skew leeway
	if !data.ClockSkewLeeway.IsNull() && !data.ClockSkewLeeway.IsUnknown() {
		vaultRequest[consts.FieldClockSkewLeeway] = int(data.ClockSkewLeeway.ValueInt64())
	}

	return vaultRequest
}

// validateConfiguration validates mutual exclusivity of JWKS and PEM configurations
func (r *OAuthResourceServerConfigProfileResource) validateConfiguration(data *OAuthResourceServerConfigProfileModel, diags *diag.Diagnostics) error {
	useJWKS := data.UseJWKS.ValueBool()
	hasJWKSUri := !data.JWKSUri.IsNull() && !data.JWKSUri.IsUnknown() && data.JWKSUri.ValueString() != ""
	hasPublicKeys := !data.PublicKeys.IsNull() && !data.PublicKeys.IsUnknown() && len(data.PublicKeys.Elements()) > 0

	if useJWKS && !hasJWKSUri {
		return fmt.Errorf("jwks_uri is required when use_jwks=true")
	}

	if !useJWKS && !hasPublicKeys {
		return fmt.Errorf("public_keys is required when use_jwks=false")
	}

	if useJWKS && hasPublicKeys {
		return fmt.Errorf("cannot specify both use_jwks=true and public_keys")
	}

	if !useJWKS && hasJWKSUri {
		return fmt.Errorf("cannot specify both use_jwks=false and jwks_uri")
	}

	return nil
}

// profilePath returns the Vault API path for a profile
func (r *OAuthResourceServerConfigProfileResource) profilePath(profileName string) string {
	return fmt.Sprintf("sys/config/oauth-resource-server/%s", profileName)
}
