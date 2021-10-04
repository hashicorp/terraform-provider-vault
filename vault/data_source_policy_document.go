package vault

import (
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-provider-vault/helper"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type Policy struct {
	Rules []*PolicyRule
}

type PolicyRule struct {
	Path               string
	Description        string
	MinWrappingTTL     string
	MaxWrappingTTL     string
	Capabilities       []string
	RequiredParameters []string
	AllowedParameters  map[string][]string
	DeniedParameters   map[string][]string
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

						"description": {
							Type:     schema.TypeString,
							Optional: true,
						},

						"min_wrapping_ttl": {
							Type:     schema.TypeString,
							Optional: true,
						},

						"max_wrapping_ttl": {
							Type:     schema.TypeString,
							Optional: true,
						},

						"capabilities": {
							Type:     schema.TypeList,
							Required: true,
							Elem: &schema.Schema{
								Type:         schema.TypeString,
								ValidateFunc: capabilityValidation,
							},
						},

						"required_parameters": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},

						"allowed_parameter": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"key": {
										Type:     schema.TypeString,
										Required: true,
									},

									"value": {
										Type:     schema.TypeList,
										Required: true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
								},
							},
						},

						"denied_parameter": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"key": {
										Type:     schema.TypeString,
										Required: true,
									},

									"value": {
										Type:     schema.TypeList,
										Required: true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
								},
							},
						},
					},
				},
			},

			"hcl": {
				Type:     schema.TypeString,
				Computed: true, Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func policyDocumentDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	policy := &Policy{}

	if rawRules, hasRawRules := d.GetOk("rule"); hasRawRules {
		var rawRuleIntfs = rawRules.([]interface{})
		rules := make([]*PolicyRule, len(rawRuleIntfs))

		for i, ruleI := range rawRuleIntfs {
			rawRule := ruleI.(map[string]interface{})
			rule := &PolicyRule{
				Path:           rawRule["path"].(string),
				Description:    rawRule["description"].(string),
				MinWrappingTTL: rawRule["min_wrapping_ttl"].(string),
				MaxWrappingTTL: rawRule["max_wrapping_ttl"].(string),
			}

			if capabilityIntfs := rawRule["capabilities"].([]interface{}); len(capabilityIntfs) > 0 {
				rule.Capabilities = policyDecodeConfigListOfStrings(capabilityIntfs)
			}

			if reqParamIntfs := rawRule["required_parameters"].([]interface{}); len(reqParamIntfs) > 0 {
				rule.RequiredParameters = policyDecodeConfigListOfStrings(reqParamIntfs)
			}

			if allowedParamIntfs := rawRule["allowed_parameter"].([]interface{}); len(allowedParamIntfs) > 0 {
				var err error
				rule.AllowedParameters, err = policyDecodeConfigListOfMapsOfListToString(allowedParamIntfs)
				if err != nil {
					return fmt.Errorf("error reading argument allowed_parameter: %s", err)
				}
			}

			if deniedParamIntfs := rawRule["denied_parameter"].([]interface{}); len(deniedParamIntfs) > 0 {
				var err error
				rule.DeniedParameters, err = policyDecodeConfigListOfMapsOfListToString(deniedParamIntfs)
				if err != nil {
					return fmt.Errorf("error reading argument denied_parameter: %s", err)
				}
			}

			log.Printf("[DEBUG] Rule is: %#v", rule)

			rules[i] = rule
		}

		policy.Rules = rules
	}

	policyHCL := renderPolicy(policy)
	log.Printf("[DEBUG] Policy HCL is: %s", policyHCL)

	err := d.Set("hcl", policyHCL)
	if err != nil {
		return fmt.Errorf("failed to store policy hcl: %s", err)
	}
	d.SetId(strconv.Itoa(helper.HashCodeString(policyHCL)))

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

func policyDecodeConfigListOfStrings(input []interface{}) []string {
	output := make([]string, len(input))
	for i, v := range input {
		output[i] = v.(string)
	}
	return output
}

func policyDecodeConfigListOfMapsOfListToString(input []interface{}) (map[string][]string, error) {
	output := make(map[string][]string, len(input))
	for _, paramI := range input {
		rawParam := paramI.(map[string]interface{})
		key := rawParam["key"].(string)
		value := rawParam["value"].([]interface{})

		if _, ok := output[key]; ok {
			return nil, fmt.Errorf("found duplicate key: %s", key)
		}

		output[key] = policyDecodeConfigListOfStrings(value)
	}
	return output, nil
}

func policyRenderListOfStrings(items []string) string {
	if len(items) > 0 {
		return fmt.Sprintf(`["%s"]`, strings.Join(items, `", "`))
	}

	return "[]"
}

func policyRenderListOfMapsOfListToString(input map[string][]string) string {
	output := fmt.Sprintf("{\n")

	keys := make([]string, 0, len(input))
	for k := range input {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		output = fmt.Sprintf("%s    \"%s\" = %s\n", output, k, policyRenderListOfStrings(input[k]))
	}

	return fmt.Sprintf("%s  }", output)
}

func policyRenderPolicyRule(rule *PolicyRule) string {
	renderedRule := fmt.Sprintf("path \"%s\" {\n", rule.Path)
	renderedRule = fmt.Sprintf("%s  capabilities = %s\n", renderedRule, policyRenderListOfStrings(rule.Capabilities))

	if rule.Description != "" {
		renderedRule = fmt.Sprintf("# %s\n%s", rule.Description, renderedRule)
	}

	if rule.RequiredParameters != nil {
		renderedRule = fmt.Sprintf("%s  required_parameters = %s\n", renderedRule, policyRenderListOfStrings(rule.RequiredParameters))
	}

	if rule.AllowedParameters != nil {
		renderedRule = fmt.Sprintf("%s  allowed_parameters = %s\n", renderedRule, policyRenderListOfMapsOfListToString(rule.AllowedParameters))
	}

	if rule.DeniedParameters != nil {
		renderedRule = fmt.Sprintf("%s  denied_parameters = %s\n", renderedRule, policyRenderListOfMapsOfListToString(rule.DeniedParameters))
	}

	if rule.MinWrappingTTL != "" {
		renderedRule = fmt.Sprintf("%s  min_wrapping_ttl = \"%s\"\n", renderedRule, rule.MinWrappingTTL)
	}

	if rule.MaxWrappingTTL != "" {
		renderedRule = fmt.Sprintf("%s  max_wrapping_ttl = \"%s\"\n", renderedRule, rule.MaxWrappingTTL)
	}

	return fmt.Sprintf("%s}\n", renderedRule)
}

func renderPolicy(policy *Policy) string {
	var output string

	for i, rule := range policy.Rules {
		if i == 0 {
			output = fmt.Sprintf("%s", policyRenderPolicyRule(rule))
		} else {
			output = fmt.Sprintf("%s\n%s", output, policyRenderPolicyRule(rule))
		}
	}

	return output
}
