package token

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
)

// TokenModel provides a base struct for auth backend roles that contain the common token
// fields. Note that this model does not include any of the deprecated token fields.
type TokenModel struct {
	base.BaseModel

	TokenTTL             types.Int64  `tfsdk:"token_ttl"`
	TokenMaxTTL          types.Int64  `tfsdk:"token_max_ttl"`
	TokenPolicies        types.Set    `tfsdk:"token_policies"`
	TokenBoundCIDRs      types.Set    `tfsdk:"token_bound_cidrs"`
	TokenExplicitMaxTTL  types.Int64  `tfsdk:"token_explicit_max_ttl"`
	TokenNoDefaultPolicy types.Bool   `tfsdk:"token_no_default_policy"`
	TokenNumUses         types.Int64  `tfsdk:"token_num_uses"`
	TokenPeriod          types.Int64  `tfsdk:"token_period"`
	TokenType            types.String `tfsdk:"token_type"`
	AliasMetadata        types.Map    `tfsdk:"alias_metadata"`
}

// TokenAPIModel represents all the common auth token fields from an API perspective. Note none
// of the deprecated token fields are included.
type TokenAPIModel struct {
	TokenTTL             int64             `json:"token_ttl" mapstructure:"token_ttl"`
	TokenMaxTTL          int64             `json:"token_max_ttl" mapstructure:"token_max_ttl"`
	TokenPolicies        []string          `json:"token_policies" mapstructure:"token_policies"`
	TokenBoundCIDRs      []string          `json:"token_bound_cidrs" mapstructure:"token_bound_cidrs"`
	TokenExplicitMaxTTL  int64             `json:"token_explicit_max_ttl" mapstructure:"token_explicit_max_ttl"`
	TokenNoDefaultPolicy bool              `json:"token_no_default_policy" mapstructure:"token_no_default_policy"`
	TokenNumUses         int64             `json:"token_num_uses" mapstructure:"token_num_uses"`
	TokenPeriod          int64             `json:"token_period" mapstructure:"token_period"`
	TokenType            string            `json:"token_type" mapstructure:"token_type"`
	AliasMetadata        map[string]string `json:"alias_metadata" mapstructure:"alias_metadata"`
}

// MustAddBaseAndTokenSchemas adds the schema fields that are required for all net new
// resources and data sources built with the TF Plugin Framework extending the
// TokenModel base model.
//
// This should be called from a resources or data source's Schema() method.
func MustAddBaseAndTokenSchemas(s *schema.Schema) {
	base.MustAddBaseSchema(s)

	for k, v := range tokenSchema() {
		if _, ok := s.Attributes[k]; ok {
			panic(fmt.Sprintf("cannot add schema field %q, already exists in the Schema map", k))
		}

		s.Attributes[k] = v
	}
}

func PopulateTokenDataMap(ctx context.Context, model *TokenModel, data map[string]interface{}) diag.Diagnostics {
	if model == nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("cannot populate data map from nil token model", ""),
		}
	}
	if data == nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("cannot populate nil data map", ""),
		}
	}

	// Only add fields that are not null or unknown
	if !model.TokenTTL.IsNull() && !model.TokenTTL.IsUnknown() {
		data[consts.FieldTokenTTL] = model.TokenTTL.ValueInt64()
	}

	if !model.TokenMaxTTL.IsNull() && !model.TokenMaxTTL.IsUnknown() {
		data[consts.FieldTokenMaxTTL] = model.TokenMaxTTL.ValueInt64()
	}

	if !model.TokenPolicies.IsNull() && !model.TokenPolicies.IsUnknown() {
		var tokenPolicies []string
		if err := model.TokenPolicies.ElementsAs(ctx, &tokenPolicies, false); err.HasError() {
			return err
		}
		data[consts.FieldTokenPolicies] = tokenPolicies
	}

	if !model.TokenBoundCIDRs.IsNull() && !model.TokenBoundCIDRs.IsUnknown() {
		var tokenBoundCIDRs []string
		if err := model.TokenBoundCIDRs.ElementsAs(ctx, &tokenBoundCIDRs, false); err.HasError() {
			return err
		}
		data[consts.FieldTokenBoundCIDRs] = tokenBoundCIDRs
	}

	if !model.TokenExplicitMaxTTL.IsNull() && !model.TokenExplicitMaxTTL.IsUnknown() {
		data[consts.FieldTokenExplicitMaxTTL] = model.TokenExplicitMaxTTL.ValueInt64()
	}

	if !model.TokenNoDefaultPolicy.IsNull() && !model.TokenNoDefaultPolicy.IsUnknown() {
		data[consts.FieldTokenNoDefaultPolicy] = model.TokenNoDefaultPolicy.ValueBool()
	}

	if !model.TokenNumUses.IsNull() && !model.TokenNumUses.IsUnknown() {
		data[consts.FieldTokenNumUses] = model.TokenNumUses.ValueInt64()
	}

	if !model.TokenPeriod.IsNull() && !model.TokenPeriod.IsUnknown() {
		data[consts.FieldTokenPeriod] = model.TokenPeriod.ValueInt64()
	}

	if !model.TokenType.IsNull() && !model.TokenType.IsUnknown() {
		data[consts.FieldTokenType] = model.TokenType.ValueString()
	}

	if !model.AliasMetadata.IsNull() && !model.AliasMetadata.IsUnknown() {
		var aliasMetadata map[string]string
		if err := model.AliasMetadata.ElementsAs(ctx, &aliasMetadata, false); err.HasError() {
			return err
		}
		data[consts.FieldAliasMetadata] = aliasMetadata
	}

	return diag.Diagnostics{}
}

func PopulateTokenModelFromAPI(ctx context.Context, model *TokenModel, apiModel *TokenAPIModel) diag.Diagnostics {
	if apiModel == nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("cannot populate token model from nil api model", ""),
		}
	}
	if model == nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic("cannot populate nil model", ""),
		}
	}

	// Set all fields directly from API model (following the same pattern as populateDataModelFromApi)
	model.TokenTTL = types.Int64Value(apiModel.TokenTTL)
	model.TokenMaxTTL = types.Int64Value(apiModel.TokenMaxTTL)
	model.TokenExplicitMaxTTL = types.Int64Value(apiModel.TokenExplicitMaxTTL)
	model.TokenNoDefaultPolicy = types.BoolValue(apiModel.TokenNoDefaultPolicy)
	model.TokenNumUses = types.Int64Value(apiModel.TokenNumUses)
	model.TokenPeriod = types.Int64Value(apiModel.TokenPeriod)
	model.TokenType = types.StringValue(apiModel.TokenType)

	// Handle Set and Map types
	policies, err := types.SetValueFrom(ctx, types.StringType, apiModel.TokenPolicies)
	if err.HasError() {
		return err
	}
	model.TokenPolicies = policies

	cidrs, err := types.SetValueFrom(ctx, types.StringType, apiModel.TokenBoundCIDRs)
	if err.HasError() {
		return err
	}
	model.TokenBoundCIDRs = cidrs

	metadata, err := types.MapValueFrom(ctx, types.StringType, apiModel.AliasMetadata)
	if err.HasError() {
		return err
	}
	model.AliasMetadata = metadata

	return diag.Diagnostics{}
}

func tokenSchema() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		consts.FieldTokenTTL: schema.Int64Attribute{
			Optional:    true,
			Computed:    true,
			Description: "The initial ttl of the token to generate in seconds",
		},
		consts.FieldTokenMaxTTL: schema.Int64Attribute{
			Optional:    true,
			Computed:    true,
			Description: "The maximum lifetime of the generated token",
		},
		consts.FieldTokenPolicies: schema.SetAttribute{
			ElementType: types.StringType,
			Optional:    true,
			Computed:    true,
			Description: "Generated Token's Policies",
		},
		consts.FieldTokenBoundCIDRs: schema.SetAttribute{
			ElementType: types.StringType,
			Optional:    true,
			Computed:    true,
			Description: "Specifies the blocks of IP addresses which are allowed to use the generated token",
		},
		consts.FieldTokenExplicitMaxTTL: schema.Int64Attribute{
			Optional:    true,
			Computed:    true,
			Description: "Generated Token's Explicit Maximum TTL in seconds",
		},
		consts.FieldTokenNoDefaultPolicy: schema.BoolAttribute{
			Optional:    true,
			Computed:    true,
			Description: "If true, the 'default' policy will not automatically be added to generated tokens",
		},
		consts.FieldTokenNumUses: schema.Int64Attribute{
			Optional:    true,
			Computed:    true,
			Description: "The maximum number of times a token may be used, a value of zero means unlimited",
		},
		consts.FieldTokenPeriod: schema.Int64Attribute{
			Optional:    true,
			Computed:    true,
			Description: "Generated Token's Period",
		},
		consts.FieldTokenType: schema.StringAttribute{
			Optional:    true,
			Computed:    true,
			Description: "The type of token to generate, service or batch",
		},
		consts.FieldAliasMetadata: schema.MapAttribute{
			ElementType: types.StringType,
			Optional:    true,
			Computed:    true,
			Description: "A map of string to string that will be set as metadata on the identity alias",
		},
	}
}
