package util

import (
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"strings"
	"time"

	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
)

func JsonDiffSuppress(k, old, new string, d *schema.ResourceData) bool {
	var oldJSON, newJSON interface{}
	err := json.Unmarshal([]byte(old), &oldJSON)
	if err != nil {
		log.Printf("[ERROR] Version of %q in state is not valid JSON: %s", k, err)
		return false
	}
	err = json.Unmarshal([]byte(new), &newJSON)
	if err != nil {
		log.Printf("[ERROR] Version of %q in config is not valid JSON: %s", k, err)
		return true
	}
	return reflect.DeepEqual(oldJSON, newJSON)
}

func ToStringArray(input []interface{}) []string {
	output := make([]string, len(input))

	for i, item := range input {
		output[i] = item.(string)
	}

	return output
}

func Is404(err error) bool {
	return strings.Contains(err.Error(), "Code: 404")
}

func CalculateConflictsWith(self string, group []string) []string {
	if len(group) < 2 {
		return []string{}
	}
	results := make([]string, 0, len(group)-2)
	for _, item := range group {
		if item == self {
			continue
		}
		results = append(results, item)
	}
	return results
}

func ArrayToTerraformList(values []string) string {
	output := make([]string, len(values))
	for idx, value := range values {
		output[idx] = fmt.Sprintf(`"%s"`, value)
	}
	return fmt.Sprintf("[%s]", strings.Join(output, ", "))
}

func TerraformSetToStringArray(set interface{}) []string {
	list := set.(*schema.Set).List()
	arr := make([]string, 0, len(list))
	for _, v := range list {
		arr = append(arr, v.(string))
	}
	return arr
}

func JsonStringArrayToStringArray(jsonList []interface{}) []string {
	strList := make([]string, 0, len(jsonList))
	for _, v := range jsonList {
		strList = append(strList, v.(string))
	}
	return strList
}

func IsExpiredTokenErr(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "invalid accessor") {
		return true
	}
	if strings.Contains(err.Error(), "failed to find accessor entry") {
		return true
	}
	return false
}

func TestCheckResourceAttrJSON(name, key, expectedValue string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("not found: %q", name)
		}
		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("%q has no primary instance state", name)
		}
		v, ok := instanceState.Attributes[key]
		if !ok {
			return fmt.Errorf("%s: attribute not found %q", name, key)
		}
		if expectedValue == "" && v == expectedValue {
			return nil
		}
		if v == "" {
			return fmt.Errorf("%s: attribute %q expected %#v, got %#v", name, key, expectedValue, v)
		}

		var stateJSON, expectedJSON interface{}
		err := json.Unmarshal([]byte(v), &stateJSON)
		if err != nil {
			return fmt.Errorf("%s: attribute %q not JSON: %s", name, key, err)
		}
		err = json.Unmarshal([]byte(expectedValue), &expectedJSON)
		if err != nil {
			return fmt.Errorf("expected value %q not JSON: %s", expectedValue, err)
		}
		if !reflect.DeepEqual(stateJSON, expectedJSON) {
			return fmt.Errorf("%s: attribute %q expected %#v, got %#v", name, key, expectedJSON, stateJSON)
		}
		return nil
	}
}

func ShortDur(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2]
	}
	if strings.HasSuffix(s, "h0m") {
		s = s[:len(s)-2]
	}
	return s
}

func CommonTokenFields() []string {
	return []string{
		"token_bound_cidrs",
		"token_explicit_max_ttl",
		"token_no_default_policy",
		"token_no_default_policy",
		"token_period",
		"token_policies",
		"token_type",
		"token_ttl",
		"token_num_uses",
	}
}

type AddTokenFieldsConfig struct {
	TokenPoliciesConflict []string
	TokenPeriodConflict   []string
}

// Common field schemas for Auth Backends
func AddTokenFields(fields map[string]*schema.Schema, config *AddTokenFieldsConfig) {
	fields["token_bound_cidrs"] = &schema.Schema{
		Type: schema.TypeSet,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
		Description: "Specifies the blocks of IP addresses which are allowed to use the generated token",
		Optional:    true,
		Computed:    true,
	}

	fields["token_explicit_max_ttl"] = &schema.Schema{
		Type:        schema.TypeInt,
		Description: "Generated Token's Explicit Maximum TTL in seconds",
		Optional:    true,
		Computed:    true,
	}

	fields["token_max_ttl"] = &schema.Schema{
		Type:        schema.TypeInt,
		Description: "The maximum lifetime of the generated token",
		Optional:    true,
		Computed:    true,
	}

	fields["token_no_default_policy"] = &schema.Schema{
		Type:        schema.TypeBool,
		Description: "If true, the 'default' policy will not automatically be added to generated tokens",
		Optional:    true,
		Computed:    true,
	}

	fields["token_period"] = &schema.Schema{
		Type:          schema.TypeInt,
		Description:   "Generated Token's Period",
		Optional:      true,
		Computed:      true,
		ConflictsWith: config.TokenPeriodConflict,
	}

	fields["token_policies"] = &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Computed: true,
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
		Computed:    true,
	}

	fields["token_ttl"] = &schema.Schema{
		Type:        schema.TypeInt,
		Description: "The initial ttl of the token to generate in seconds",
		Optional:    true,
		Computed:    true,
	}

	fields["token_num_uses"] = &schema.Schema{
		Type:        schema.TypeInt,
		Description: "The maximum number of times a token may be used, a value of zero means unlimited",
		Optional:    true,
		Computed:    true,
	}
}

func UpdateTokenFields(d *schema.ResourceData, data map[string]interface{}) {
	if v, ok := d.GetOk("token_bound_cidrs"); ok {
		data["token_bound_cidrs"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("token_explicit_max_ttl"); ok {
		data["token_explicit_max_ttl"] = v.(int)
	}

	if v, ok := d.GetOk("token_max_ttl"); ok {
		data["token_max_ttl"] = v.(int)
	}

	if v, ok := d.GetOk("token_no_default_policy"); ok {
		data["token_no_default_policy"] = v.(bool)
	}

	if v, ok := d.GetOk("token_period"); ok {
		data["token_period"] = v.(int)
	}

	if v, ok := d.GetOk("token_policies"); ok {
		data["token_policies"] = v.(*schema.Set).List()
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
}

func ReadTokenFields(d *schema.ResourceData, resp *api.Secret) error {
	for _, k := range []string{"token_bound_cidrs", "token_explicit_max_ttl", "token_max_ttl", "token_no_default_policy", "token_period", "token_policies", "token_type", "token_ttl", "token_num_uses"} {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return fmt.Errorf("error setting state key \"%s\": %s", k, err)
		}
	}

	return nil
}
