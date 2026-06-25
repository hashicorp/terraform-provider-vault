// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"fmt"
	"net/url"
	"os"

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
	Audiences                    types.List   `tfsdk:"audiences"` // List of strings
	NoDefaultPolicy              types.Bool   `tfsdk:"no_default_policy"`
	UserClaim                    types.String `tfsdk:"user_claim"`
	SupportedAlgorithms          types.List   `tfsdk:"supported_algorithms"` // List of strings
	JwtType                      types.String `tfsdk:"jwt_type"`
	ClockSkewLeeway              types.Int64  `tfsdk:"clock_skew_leeway"`
	Enabled                      types.Bool   `tfsdk:"enabled"`
	OptionalAuthorizationDetails types.Bool   `tfsdk:"optional_authorization_details"`
}

// OAuthResourceServerConfigProfileAPIModel describes the Vault API data model
type OAuthResourceServerConfigProfileAPIModel struct {
	ConfigID                     string              `json:"config_id" mapstructure:"config_id"`
	ProfileName                  string              `json:"profile_name" mapstructure:"profile_name"`
	IssuerId                     string              `json:"issuer_id" mapstructure:"issuer_id"`
	UseJWKS                      bool                `json:"use_jwks" mapstructure:"use_jwks"`
	JWKSUri                      string              `json:"jwks_uri" mapstructure:"jwks_uri"`
	JwksCaPem                    string              `json:"jwks_ca_pem" mapstructure:"jwks_ca_pem"`
	PublicKeys                   []PublicKeyAPIModel `json:"public_keys" mapstructure:"public_keys"`
	Audiences                    []string            `json:"audiences" mapstructure:"audiences"`
	NoDefaultPolicy              bool                `json:"no_default_policy" mapstructure:"no_default_policy"`
	UserClaim                    string              `json:"user_claim" mapstructure:"user_claim"`
	SupportedAlgorithms          []string            `json:"supported_algorithms" mapstructure:"supported_algorithms"`
	JwtType                      string              `json:"jwt_type" mapstructure:"jwt_type"`
	ClockSkewLeeway              int                 `json:"clock_skew_leeway" mapstructure:"clock_skew_leeway"`
	Enabled                      bool                `json:"enabled" mapstructure:"enabled"`
	OptionalAuthorizationDetails bool                `json:"optional_authorization_details" mapstructure:"optional_authorization_details"`
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
			consts.FieldJWKSCAPEM: schema.StringAttribute{
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
			consts.FieldOptionalAuthorizationDetails: schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "When false, RAR (Rich Authorization Requests) is mandatory and authorization_details must be present in the token. When set to true, authorization_details in the JWT token are optional. Defaults to false.",
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
						consts.FieldPEM: schema.StringAttribute{
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
			"OAuth Resource Server Configuration is available only in Vault Enterprise",
		)
		return
	}

	r.writeProfile(ctx, &data, &resp.Diagnostics, errutil.VaultCreateErr)
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

	found := r.readFromVault(ctx, client, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if !found {
		tflog.Warn(ctx, "OAuth Resource Server Configuration profile not found, removing from state")
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update is called during terraform apply
func (r *OAuthResourceServerConfigProfileResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan OAuthResourceServerConfigProfileModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.writeProfile(ctx, &plan, &resp.Diagnostics, errutil.VaultUpdateErr)
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
	var data OAuthResourceServerConfigProfileModel

	// The import ID is the verbatim profile_name. Profiles are read by
	// profile_name (Vault exposes no read-by-config_id endpoint), so the import
	// ID is used as-is rather than parsing a namespace out of it.
	data.ProfileName = types.StringValue(req.ID)

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

	found := r.readFromVault(ctx, client, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if !found {
		resp.Diagnostics.AddError(errutil.VaultReadResponseNil())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// writeProfile configures a client, validates the configuration, writes the
// profile to Vault, and reads the result back into data. writeErr wraps a write
// failure so callers can distinguish create from update. Errors are reported via
// diags; callers should check diags.HasError after calling.
func (r *OAuthResourceServerConfigProfileResource) writeProfile(ctx context.Context, data *OAuthResourceServerConfigProfileModel, diags *diag.Diagnostics, writeErr func(error) (string, string)) {
	client, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		diags.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Validate mutual exclusivity before building the request payload.
	if err := r.validateConfiguration(data, diags); err != nil {
		diags.AddError("Configuration Validation Error", err.Error())
		return
	}

	vaultRequest := r.buildVaultRequest(ctx, data, diags)
	if diags.HasError() {
		return
	}

	path := r.profilePath(data.ProfileName.ValueString())
	if _, err := client.Logical().WriteWithContext(ctx, path, vaultRequest); err != nil {
		diags.AddError(writeErr(err))
		return
	}

	// Read back to get computed fields including config_id. A missing profile
	// immediately after a successful write is a real inconsistency, so treat it
	// as an error rather than silently dropping the resource.
	found := r.readFromVault(ctx, client, data, diags)
	if diags.HasError() {
		return
	}
	if !found {
		diags.AddError(errutil.VaultReadResponseNil())
	}
}

// readFromVault reads the profile from Vault into data. It reports whether the
// profile was found: a nil/empty Vault response returns false without adding an
// error, so callers can decide whether a missing profile is an error (create,
// update, and import read-back) or a signal to remove the resource from state
// (read). Genuine read or decode failures are recorded in diags and return false.
func (r *OAuthResourceServerConfigProfileResource) readFromVault(ctx context.Context, client *api.Client, data *OAuthResourceServerConfigProfileModel, diags *diag.Diagnostics) bool {
	path := r.profilePath(data.ProfileName.ValueString())

	readResp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		diags.AddError(
			errutil.VaultReadErr(err),
		)
		return false
	}

	if readResp == nil || readResp.Data == nil {
		// The profile does not exist in Vault. Report "not found" without an
		// error so the caller can decide how to handle it.
		return false
	}

	var apiModel OAuthResourceServerConfigProfileAPIModel
	err = model.ToAPIModel(readResp.Data, &apiModel)
	if err != nil {
		diags.AddError("Unable to translate Vault response data", err.Error())
		return false
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
				consts.FieldPEM:   types.StringType,
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
				consts.FieldPEM:   types.StringType,
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

	// RAR support
	data.OptionalAuthorizationDetails = types.BoolValue(apiModel.OptionalAuthorizationDetails)

	return true
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
		vaultRequest[consts.FieldJWKSCAPEM] = data.JwksCaPem.ValueString()
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
					consts.FieldPEM:   pk.PEM.ValueString(),
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

	// RAR support
	if !data.OptionalAuthorizationDetails.IsNull() && !data.OptionalAuthorizationDetails.IsUnknown() {
		vaultRequest[consts.FieldOptionalAuthorizationDetails] = data.OptionalAuthorizationDetails.ValueBool()
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
	return "sys/config/oauth-resource-server/" + url.PathEscape(profileName)
}
