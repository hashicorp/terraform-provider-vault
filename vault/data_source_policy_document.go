// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-provider-vault/helper"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type Policy struct {
	Rules []*PolicyRule
}

type PolicyRule struct {
	// Path in Vault that the rule applies to.
	Path string

	// Description is an optional annotation for the rule.
	Description string

	// MinWrappingTTL is the minimum allowed TTL for the wrapped response.
	MinWrappingTTL string

	// MaxWrappingTTL is the maximum allowed TTL for the wrapped response.
	MaxWrappingTTL string

	// Capabilities is the list of allowed operations on the specified path.
	Capabilities []string

	// RequiredParameters is a list of parameters that must be specified.
	RequiredParameters []string

	// SubscribeEventTypes is a list of event types to subscribe to when using `subscribe` capability.
	SubscribeEventTypes []string

	// AllowedParameters defines a whitelist of keys and values that are permitted on the given path.
	AllowedParameters map[string][]string

	// DeniedParameters defines a blacklist of keys and values that are denied on the given path.
	DeniedParameters map[string][]string
}

var allowedCapabilities = []string{
	"create",
	"read",
	"update",
	"delete",
	"list",
	"sudo",
	"deny",
	"patch",
	"subscribe",
}

func policyDocumentDataSource() *schema.Resource {
	return &schema.Resource{
		Read: provider.ReadWrapper(policyDocumentDataSourceRead),
		Schema: map[string]*schema.Schema{
			"rule": {
				Type:        schema.TypeList,
				Optional:    true,
				Computed:    true,
				Description: "The policy rule",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						consts.FieldPath: {
							Type:        schema.TypeString,
							Required:    true,
							Description: "A path in Vault that this rule applies to.",
						},

						"description": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Description of the rule.",
						},

						"min_wrapping_ttl": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "The minimum allowed TTL that clients can specify for a wrapped response.",
						},

						"max_wrapping_ttl": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "The maximum allowed TTL that clients can specify for a wrapped response.",
						},

						"capabilities": {
							Type:        schema.TypeList,
							Required:    true,
							Description: "A list of capabilities to apply to the specified path.",
							Elem: &schema.Schema{
								Type:         schema.TypeString,
								ValidateFunc: capabilityValidation,
							},
						},

						"required_parameters": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "A list of parameters that must be specified.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},

						"subscribe_event_types": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "A list of event types to subscribe to when using `subscribe` capability",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},

						"allowed_parameter": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "Whitelists a list of keys and values that are permitted on the given path.",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"key": {
										Type:        schema.TypeString,
										Required:    true,
										Description: "Name of permitted key.",
									},

									"value": {
										Type:        schema.TypeList,
										Required:    true,
										Description: "A list of values what are permitted by policy rule.",
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
								},
							},
						},

						"denied_parameter": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "Blacklists a list of parameter and values.",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"key": {
										Type:        schema.TypeString,
										Required:    true,
										Description: "Name of denied key.",
									},

									"value": {
										Type:        schema.TypeList,
										Required:    true,
										Description: "A list of values what are denied by policy rule.",
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
				Type:        schema.TypeString,
				Description: "The above arguments serialized as a standard Vault HCL policy document.",
				Computed:    true, Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func policyDocumentDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	policy := &Policy{}

	if rawRules, hasRawRules := d.GetOk("rule"); hasRawRules {
		rawRuleIntfs := rawRules.([]interface{})
		rules := make([]*PolicyRule, len(rawRuleIntfs))

		for i, ruleI := range rawRuleIntfs {
			rawRule := ruleI.(map[string]interface{})
			rule := &PolicyRule{}

			pathVal, ok := rawRule[consts.FieldPath].(string)
			if !ok || pathVal == "" {
				return fmt.Errorf("missing or invalid field: %s", consts.FieldPath)
			}
			rule.Path = pathVal

			optionalFields := map[string]*string{
				"description":      &rule.Description,
				"min_wrapping_ttl": &rule.MinWrappingTTL,
				"max_wrapping_ttl": &rule.MaxWrappingTTL,
			}
			for k, v := range optionalFields {
				if value, ok := rawRule[k].(string); ok {
					*v = value
				}
			}

			capVal, ok := rawRule["capabilities"]
			if !ok {
				return fmt.Errorf("missing field: capabilities")
			}
			capList, ok := capVal.([]interface{})
			if !ok || len(capList) == 0 {
				return fmt.Errorf("invalid or empty capabilities list, expected a list of strings")
			}
			rule.Capabilities = policyDecodeConfigListOfStrings(capList)

			if reqParamVal, ok := rawRule["required_parameters"]; ok {
				if reqParamIntfs, ok := reqParamVal.([]interface{}); ok && len(reqParamIntfs) > 0 {
					rule.RequiredParameters = policyDecodeConfigListOfStrings(reqParamIntfs)
				}
			}

			if subEventVal, ok := rawRule["subscribe_event_types"]; ok {
				if subEventTypesIntfs, ok := subEventVal.([]interface{}); ok && len(subEventTypesIntfs) > 0 {
					rule.SubscribeEventTypes = policyDecodeConfigListOfStrings(subEventTypesIntfs)
				}
			}

			if allowVal, ok := rawRule["allowed_parameter"]; ok {
				if allowedParamIntfs, ok := allowVal.([]interface{}); ok && len(allowedParamIntfs) > 0 {
					var err error
					rule.AllowedParameters, err = policyDecodeConfigListOfMapsOfListToString(allowedParamIntfs)
					if err != nil {
						return fmt.Errorf("error reading argument allowed_parameter: %s", err)
					}
				}
			}

			if deniedVal, ok := rawRule["denied_parameter"]; ok {
				if deniedParamIntfs, ok := deniedVal.([]interface{}); ok && len(deniedParamIntfs) > 0 {
					var err error
					rule.DeniedParameters, err = policyDecodeConfigListOfMapsOfListToString(deniedParamIntfs)
					if err != nil {
						return fmt.Errorf("error reading argument denied_parameter: %s", err)
					}
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

	if len(rule.RequiredParameters) > 0 {
		renderedRule = fmt.Sprintf("%s  required_parameters = %s\n", renderedRule, policyRenderListOfStrings(rule.RequiredParameters))
	}

	if len(rule.SubscribeEventTypes) > 0 {
		renderedRule = fmt.Sprintf("%s  subscribe_event_types = %s\n", renderedRule, policyRenderListOfStrings(rule.SubscribeEventTypes))
	}

	if len(rule.AllowedParameters) > 0 {
		renderedRule = fmt.Sprintf("%s  allowed_parameters = %s\n", renderedRule, policyRenderListOfMapsOfListToString(rule.AllowedParameters))
	}

	if len(rule.DeniedParameters) > 0 {
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
