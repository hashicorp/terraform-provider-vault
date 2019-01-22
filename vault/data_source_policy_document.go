package vault

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform/helper/hashcode"
	"github.com/hashicorp/terraform/helper/schema"
)

type Policy struct {
	Rules []PolicyRule
}

type PolicyRule struct {
	Path         string
	Description  string
	Capabilities []string
}

var allowedCapabilities = []string{"create", "read", "update", "delete", "list", "sudo", "deny"}

func policyDocumentDataSource() *schema.Resource {
	return &schema.Resource{
		Read: policyDocumentDataSourceRead,
		Schema: map[string]*schema.Schema{
			"rule": {
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				Description: "The policy rule",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"path": {
							Type:     schema.TypeString,
							Required: true,
						},

						"capabilities": {
							Type:     schema.TypeList,
							Required: true,
							Elem: &schema.Schema{
								ValidateFunc: capabilityValidation,
								Type:         schema.TypeString,
							},
						},

						"description": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},

			"hcl": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func policyDocumentDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	policyHCL := renderPolicy(policyConvert(d.Get("rule").([]interface{})))
	err := d.Set("hcl", policyHCL)
	if err != nil {
		return fmt.Errorf("failed to store policy hcl: %s", err)
	}
	d.SetId(strconv.Itoa(hashcode.String(policyHCL)))
	return nil
}

func capabilityValidation(configI interface{}, k string) ([]string, []error) {
	for _, capability := range allowedCapabilities {
		if configI.(string) == capability {
			return nil, nil
		}
	}
	return nil, []error{fmt.Errorf("invalid capability: \"%s\" in: %s", configI.(string), k)}
}

func policyRuleConvert(rawRule interface{}) (policyRule PolicyRule) {
	policyRule.Path = rawRule.(map[string]interface{})["path"].(string)
	policyRule.Description = rawRule.(map[string]interface{})["description"].(string)

	rawCaps := rawRule.(map[string]interface{})["capabilities"].([]interface{})
	policyRule.Capabilities = make([]string, len(rawCaps))
	for i, v := range rawCaps {
		policyRule.Capabilities[i] = v.(string)
	}

	return
}

func policyConvert(rawRules []interface{}) (policy Policy) {
	policy.Rules = make([]PolicyRule, len(rawRules))
	for i, rawRule := range rawRules {
		policy.Rules[i] = policyRuleConvert(rawRule)
	}
	return
}

func renderList(items []string) string {
	return fmt.Sprintf(`["%s"]`, strings.Join(items, `", "`))
}

func renderRule(rule PolicyRule) string {
	renderedRule := fmt.Sprintf("path \"%s\" {\n  capabilities = %s\n}", rule.Path, renderList(rule.Capabilities))
	if rule.Description != "" {
		renderedRule = fmt.Sprintf("# %s\n%s", rule.Description, renderedRule)
	}
	return renderedRule
}

func renderPolicy(policy Policy) string {
	rules := make([]string, len(policy.Rules))
	for i, rule := range policy.Rules {
		rules[i] = renderRule(rule)
	}
	return strings.Join(rules, "\n\n")
}
