package vault

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func commonTokenFields() []string {
	return []string{
		"token_bound_cidrs",
		"token_explicit_max_ttl",
		"token_max_ttl",
		"token_no_default_policy",
		"token_period",
		"token_policies",
		"token_type",
		"token_ttl",
		"token_num_uses",
	}
}

type addTokenFieldsConfig struct {
	TokenBoundCidrsConflict     []string
	TokenExplicitMaxTTLConflict []string
	TokenMaxTTLConflict         []string
	TokenNumUsesConflict        []string
	TokenPeriodConflict         []string
	TokenPoliciesConflict       []string
	TokenTTLConflict            []string

	TokenTypeDefault string
}

// Common field schemas for Auth Backends
func addTokenFields(fields map[string]*schema.Schema, config *addTokenFieldsConfig) {
	if config.TokenTypeDefault == "" {
		config.TokenTypeDefault = "default"
	}

	fields["token_bound_cidrs"] = &schema.Schema{
		Type: schema.TypeSet,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
		Description: "Specifies the blocks of IP addresses which are allowed to use the generated token",
		Optional:    true,
	}

	fields["token_explicit_max_ttl"] = &schema.Schema{
		Type:          schema.TypeInt,
		Description:   "Generated Token's Explicit Maximum TTL in seconds",
		Optional:      true,
		ConflictsWith: config.TokenExplicitMaxTTLConflict,
	}

	fields["token_max_ttl"] = &schema.Schema{
		Type:          schema.TypeInt,
		Description:   "The maximum lifetime of the generated token",
		Optional:      true,
		ConflictsWith: config.TokenMaxTTLConflict,
	}

	fields["token_no_default_policy"] = &schema.Schema{
		Type:        schema.TypeBool,
		Description: "If true, the 'default' policy will not automatically be added to generated tokens",
		Optional:    true,
	}

	fields["token_period"] = &schema.Schema{
		Type:          schema.TypeInt,
		Description:   "Generated Token's Period",
		Optional:      true,
		ConflictsWith: config.TokenPeriodConflict,
	}

	fields["token_policies"] = &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
		Description:   "Generated Token's Policies",
		ConflictsWith: config.TokenPoliciesConflict,
	}

	fields["token_type"] = &schema.Schema{
		Type:        schema.TypeString,
		Description: "The type of token to generate, service or batch",
		Optional:    true,
		Default:     config.TokenTypeDefault,
	}

	fields["token_ttl"] = &schema.Schema{
		Type:          schema.TypeInt,
		Description:   "The initial ttl of the token to generate in seconds",
		Optional:      true,
		ConflictsWith: config.TokenTTLConflict,
	}

	fields["token_num_uses"] = &schema.Schema{
		Type:          schema.TypeInt,
		Description:   "The maximum number of times a token may be used, a value of zero means unlimited",
		Optional:      true,
		ConflictsWith: config.TokenNumUsesConflict,
	}
}

func setTokenFields(d *schema.ResourceData, data map[string]interface{}, config *addTokenFieldsConfig) {
	data["token_no_default_policy"] = d.Get("token_no_default_policy").(bool)
	data["token_type"] = d.Get("token_type").(string)

	conflicted := false
	for _, k := range config.TokenExplicitMaxTTLConflict {
		if _, ok := d.GetOk(k); ok {
			conflicted = true
			break
		}
	}
	if !conflicted {
		data["token_explicit_max_ttl"] = d.Get("token_explicit_max_ttl").(int)
	}

	conflicted = false
	for _, k := range config.TokenMaxTTLConflict {
		if _, ok := d.GetOk(k); ok {
			conflicted = true
			break
		}
	}
	if !conflicted {
		data["token_max_ttl"] = d.Get("token_max_ttl").(int)
	}

	conflicted = false
	for _, k := range config.TokenPeriodConflict {
		if _, ok := d.GetOk(k); ok {
			conflicted = true
			break
		}
	}
	if !conflicted {
		data["token_period"] = d.Get("token_period").(int)
	}

	conflicted = false
	for _, k := range config.TokenPoliciesConflict {
		if _, ok := d.GetOk(k); ok {
			conflicted = true
			break
		}
	}
	if !conflicted {
		data["token_policies"] = d.Get("token_policies").(*schema.Set).List()
	}

	conflicted = false
	for _, k := range config.TokenTTLConflict {
		if _, ok := d.GetOk(k); ok {
			conflicted = true
			break
		}
	}
	if !conflicted {
		data["token_ttl"] = d.Get("token_ttl").(int)
	}

	conflicted = false
	for _, k := range config.TokenNumUsesConflict {
		if _, ok := d.GetOk(k); ok {
			conflicted = true
			break
		}
	}
	if !conflicted {
		data["token_num_uses"] = d.Get("token_num_uses").(int)
	}

	conflicted = false
	for _, k := range config.TokenBoundCidrsConflict {
		if _, ok := d.GetOk(k); ok {
			conflicted = true
			break
		}
	}
	if !conflicted {
		data["token_bound_cidrs"] = d.Get("token_bound_cidrs").(*schema.Set).List()
	}

}

func updateTokenFields(d *schema.ResourceData, data map[string]interface{}, create bool) {
	if create {
		if v, ok := d.GetOk("token_bound_cidrs"); ok {
			data["token_bound_cidrs"] = v.(*schema.Set).List()
		}

		if v, ok := d.GetOk("token_policies"); ok {
			data["token_policies"] = v.(*schema.Set).List()
		}

		if v, ok := d.GetOk("token_explicit_max_ttl"); ok {
			data["token_explicit_max_ttl"] = v.(int)
		}

		if v, ok := d.GetOk("token_max_ttl"); ok {
			data["token_max_ttl"] = v.(int)
		}

		if v, ok := d.GetOkExists("token_no_default_policy"); ok {
			data["token_no_default_policy"] = v.(bool)
		}

		if v, ok := d.GetOk("token_period"); ok {
			data["token_period"] = v.(int)
		}

		if v, ok := d.GetOk("token_type"); ok {
			data["token_type"] = v.(string)
		}

		if v, ok := d.GetOk("token_ttl"); ok {
			data["token_ttl"] = v.(int)
		}

		if v, ok := d.GetOk("token_num_uses"); ok {
			data["token_num_uses"] = v.(int)
		}
	} else {
		if d.HasChange("token_bound_cidrs") {
			data["token_bound_cidrs"] = d.Get("token_bound_cidrs").(*schema.Set).List()
		}

		if d.HasChange("token_policies") {
			data["token_policies"] = d.Get("token_policies").(*schema.Set).List()
		}

		if d.HasChange("token_explicit_max_ttl") {
			data["token_explicit_max_ttl"] = d.Get("token_explicit_max_ttl").(int)
		}

		if d.HasChange("token_max_ttl") {
			data["token_max_ttl"] = d.Get("token_max_ttl").(int)
		}

		if d.HasChange("token_no_default_policy") {
			data["token_no_default_policy"] = d.Get("token_no_default_policy").(bool)
		}

		if d.HasChange("token_period") {
			data["token_period"] = d.Get("token_period").(int)
		}

		if d.HasChange("token_type") {
			data["token_type"] = d.Get("token_type").(string)
		}

		if d.HasChange("token_ttl") {
			data["token_ttl"] = d.Get("token_ttl").(int)
		}

		if d.HasChange("token_num_uses") {
			data["token_num_uses"] = d.Get("token_num_uses").(int)
		}
	}
}

func readTokenFields(d *schema.ResourceData, resp *api.Secret) error {
	for _, k := range []string{"token_bound_cidrs", "token_explicit_max_ttl", "token_max_ttl", "token_no_default_policy", "token_period", "token_policies", "token_type", "token_ttl", "token_num_uses"} {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return fmt.Errorf("error setting state key \"%s\": %s", k, err)
		}
	}

	return nil
}
