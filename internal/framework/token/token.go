package token

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/types"
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

// PopulateTokenAPIFromModel copies the data from a TokenModel into a TokenAPIModel, useful for
// translating TF data into the Vault API data model.
func PopulateTokenAPIFromModel(ctx context.Context, model *TokenModel, apiModel *TokenAPIModel) diag.Diagnostics {
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

	apiModel.TokenTTL = model.TokenTTL.ValueInt64()
	apiModel.TokenMaxTTL = model.TokenMaxTTL.ValueInt64()

	var tokenPolicies []string
	if err := model.TokenPolicies.ElementsAs(ctx, &tokenPolicies, false); err.HasError() {
		return err
	}
	apiModel.TokenPolicies = tokenPolicies

	var tokenBoundCIDRs []string
	if err := model.TokenBoundCIDRs.ElementsAs(ctx, &tokenBoundCIDRs, false); err.HasError() {
		return err
	}
	apiModel.TokenBoundCIDRs = tokenBoundCIDRs

	apiModel.TokenExplicitMaxTTL = model.TokenExplicitMaxTTL.ValueInt64()
	apiModel.TokenNoDefaultPolicy = model.TokenNoDefaultPolicy.ValueBool()
	apiModel.TokenNumUses = model.TokenNumUses.ValueInt64()
	apiModel.TokenPeriod = model.TokenPeriod.ValueInt64()
	apiModel.TokenType = model.TokenType.ValueString()

	var aliasMetadata map[string]string
	if err := model.AliasMetadata.ElementsAs(ctx, &aliasMetadata, false); err.HasError() {
		return err
	}
	apiModel.AliasMetadata = aliasMetadata

	return diag.Diagnostics{}
}

// PopulateTokenModelFromAPI copies the data from a TokenAPIModel into a TokenModel, useful for
// translating Vault API data into the TF data model.
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

	model.TokenTTL = types.Int64Null()
	if apiModel.TokenTTL != 0 {
		model.TokenTTL = types.Int64Value(apiModel.TokenTTL)
	}

	model.TokenMaxTTL = types.Int64Null()
	if apiModel.TokenMaxTTL != 0 {
		model.TokenMaxTTL = types.Int64Value(apiModel.TokenMaxTTL)
	}

	model.TokenPolicies = types.SetNull(types.StringType)
	if len(apiModel.TokenPolicies) > 0 {
		policies, err := types.SetValueFrom(ctx, types.StringType, apiModel.TokenPolicies)
		if err.HasError() {
			return err
		}
		model.TokenPolicies = policies
	}

	model.TokenBoundCIDRs = types.SetNull(types.StringType)
	if len(apiModel.TokenBoundCIDRs) > 0 {
		cidrs, err := types.SetValueFrom(ctx, types.StringType, apiModel.TokenBoundCIDRs)
		if err.HasError() {
			return err
		}
		model.TokenBoundCIDRs = cidrs
	}

	model.TokenExplicitMaxTTL = types.Int64Null()
	if apiModel.TokenExplicitMaxTTL != 0 {
		model.TokenExplicitMaxTTL = types.Int64Value(apiModel.TokenExplicitMaxTTL)
	}

	model.TokenNoDefaultPolicy = types.BoolNull()
	if apiModel.TokenNoDefaultPolicy {
		model.TokenNoDefaultPolicy = types.BoolValue(apiModel.TokenNoDefaultPolicy)
	}

	model.TokenNumUses = types.Int64Null()
	if apiModel.TokenNumUses != 0 {
		model.TokenNumUses = types.Int64Value(apiModel.TokenNumUses)
	}

	model.TokenPeriod = types.Int64Null()
	if apiModel.TokenPeriod != 0 {
		model.TokenPeriod = types.Int64Value(apiModel.TokenPeriod)
	}

	model.TokenType = types.StringNull()
	if apiModel.TokenType != "" {
		model.TokenType = types.StringValue(apiModel.TokenType)
	}

	model.AliasMetadata = types.MapNull(types.StringType)
	if len(apiModel.AliasMetadata) > 0 {
		metadata, err := types.MapValueFrom(ctx, types.StringType, apiModel.AliasMetadata)
		if err.HasError() {
			return err
		}
		model.AliasMetadata = metadata
	}

	return diag.Diagnostics{}
}

func tokenSchema() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"token_ttl": schema.Int64Attribute{
			Optional:    true,
			Description: "The initial ttl of the token to generate in seconds",
		},
		"token_max_ttl": schema.Int64Attribute{
			Optional:    true,
			Description: "The maximum lifetime of the generated token",
		},
		"token_policies": schema.SetAttribute{
			ElementType: types.StringType,
			Optional:    true,
			Description: "Generated Token's Policies",
		},
		"token_bound_cidrs": schema.SetAttribute{
			ElementType: types.StringType,
			Optional:    true,
			Description: "Specifies the blocks of IP addresses which are allowed to use the generated token",
		},
		"token_explicit_max_ttl": schema.Int64Attribute{
			Optional:    true,
			Description: "Generated Token's Explicit Maximum TTL in seconds",
		},
		"token_no_default_policy": schema.BoolAttribute{
			Optional:    true,
			Description: "If true, the 'default' policy will not automatically be added to generated tokens",
		},
		"token_num_uses": schema.Int64Attribute{
			Optional:    true,
			Description: "The maximum number of times a token may be used, a value of zero means unlimited",
		},
		"token_period": schema.Int64Attribute{
			Optional:    true,
			Description: "Generated Token's Period",
		},
		"token_type": schema.StringAttribute{
			Optional:    true,
			Computed:    true,
			Description: "The type of token to generate, service or batch",
			Default:     stringdefault.StaticString("default"),
		},
		"alias_metadata": schema.MapAttribute{
			ElementType: types.StringType,
			Optional:    true,
			Description: "A map of string to string that will be set as metadata on the identity alias",
		},
	}
}
