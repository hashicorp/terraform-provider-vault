// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"net"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

const (
	TokenFieldBoundCIDRs      = "token_bound_cidrs"
	TokenFieldMaxTTL          = "token_max_ttl"
	TokenFieldTTL             = "token_ttl"
	TokenFieldExplicitMaxTTL  = "token_explicit_max_ttl"
	TokenFieldNoDefaultPolicy = "token_no_default_policy"
	TokenFieldPeriod          = "token_period"
	TokenFieldPolicies        = "token_policies"
	TokenFieldType            = "token_type"
	TokenFieldNumUses         = "token_num_uses"
	FieldAliasMetadata        = "alias_metadata" // Vault 1.21+
)

var commonTokenFields = []string{
	TokenFieldBoundCIDRs,
	TokenFieldMaxTTL,
	TokenFieldTTL,
	TokenFieldExplicitMaxTTL,
	TokenFieldNoDefaultPolicy,
	TokenFieldPeriod,
	TokenFieldPolicies,
	TokenFieldType,
	TokenFieldNumUses,
	FieldAliasMetadata,
}

type addTokenFieldsConfig struct {
	TokenBoundCIDRsConflict     []string
	TokenExplicitMaxTTLConflict []string
	TokenMaxTTLConflict         []string
	TokenNumUsesConflict        []string
	TokenPeriodConflict         []string
	TokenPoliciesConflict       []string
	TokenTTLConflict            []string
	AliasMetadataConflict       []string

	TokenTypeDefault string
}

// Common field schemas for Auth Backends
func addTokenFields(fields map[string]*schema.Schema, config *addTokenFieldsConfig) {
	if config.TokenTypeDefault == "" {
		config.TokenTypeDefault = "default"
	}

	fields[TokenFieldBoundCIDRs] = &schema.Schema{
		Type: schema.TypeSet,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
		Description: "Specifies the blocks of IP addresses which are allowed to use the generated token",
		Optional:    true,
	}

	fields[TokenFieldExplicitMaxTTL] = &schema.Schema{
		Type:          schema.TypeInt,
		Description:   "Generated Token's Explicit Maximum TTL in seconds",
		Optional:      true,
		ConflictsWith: config.TokenExplicitMaxTTLConflict,
	}

	fields[TokenFieldMaxTTL] = &schema.Schema{
		Type:          schema.TypeInt,
		Description:   "The maximum lifetime of the generated token",
		Optional:      true,
		ConflictsWith: config.TokenMaxTTLConflict,
	}

	fields[TokenFieldNoDefaultPolicy] = &schema.Schema{
		Type:        schema.TypeBool,
		Description: "If true, the 'default' policy will not automatically be added to generated tokens",
		Optional:    true,
	}

	fields[TokenFieldPeriod] = &schema.Schema{
		Type:          schema.TypeInt,
		Description:   "Generated Token's Period",
		Optional:      true,
		ConflictsWith: config.TokenPeriodConflict,
	}

	fields[TokenFieldPolicies] = &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
		Description:   "Generated Token's Policies",
		ConflictsWith: config.TokenPoliciesConflict,
	}

	fields[TokenFieldType] = &schema.Schema{
		Type:        schema.TypeString,
		Description: "The type of token to generate, service or batch",
		Optional:    true,
		Default:     config.TokenTypeDefault,
	}

	fields[TokenFieldTTL] = &schema.Schema{
		Type:          schema.TypeInt,
		Description:   "The initial ttl of the token to generate in seconds",
		Optional:      true,
		ConflictsWith: config.TokenTTLConflict,
	}

	fields[TokenFieldNumUses] = &schema.Schema{
		Type:          schema.TypeInt,
		Description:   "The maximum number of times a token may be used, a value of zero means unlimited",
		Optional:      true,
		ConflictsWith: config.TokenNumUsesConflict,
	}

	fields[FieldAliasMetadata] = &schema.Schema{
		Type:          schema.TypeMap,
		Description:   "The metadata to be tied to generated entity alias.\n  This should be a list or map containing the metadata in key value pairs.",
		Optional:      true,
		ConflictsWith: config.AliasMetadataConflict,
	}
}

func setTokenFields(d *schema.ResourceData, data map[string]interface{}, config *addTokenFieldsConfig) {
	data[TokenFieldNoDefaultPolicy] = d.Get(TokenFieldNoDefaultPolicy).(bool)
	data[TokenFieldType] = d.Get(TokenFieldType).(string)

	conflicted := false
	for _, k := range config.TokenExplicitMaxTTLConflict {
		if _, ok := d.GetOk(k); ok {
			conflicted = true
			break
		}
	}
	if !conflicted {
		data[TokenFieldExplicitMaxTTL] = d.Get(TokenFieldExplicitMaxTTL).(int)
	}

	conflicted = false
	for _, k := range config.TokenMaxTTLConflict {
		if _, ok := d.GetOk(k); ok {
			conflicted = true
			break
		}
	}
	if !conflicted {
		data[TokenFieldMaxTTL] = d.Get(TokenFieldMaxTTL).(int)
	}

	conflicted = false
	for _, k := range config.TokenPeriodConflict {
		if _, ok := d.GetOk(k); ok {
			conflicted = true
			break
		}
	}
	if !conflicted {
		data[TokenFieldPeriod] = d.Get(TokenFieldPeriod).(int)
	}

	conflicted = false
	for _, k := range config.TokenPoliciesConflict {
		if _, ok := d.GetOk(k); ok {
			conflicted = true
			break
		}
	}
	if !conflicted {
		data[TokenFieldPolicies] = d.Get(TokenFieldPolicies).(*schema.Set).List()
	}

	conflicted = false
	for _, k := range config.TokenTTLConflict {
		if _, ok := d.GetOk(k); ok {
			conflicted = true
			break
		}
	}
	if !conflicted {
		data[TokenFieldTTL] = d.Get(TokenFieldTTL).(int)
	}

	conflicted = false
	for _, k := range config.TokenNumUsesConflict {
		if _, ok := d.GetOk(k); ok {
			conflicted = true
			break
		}
	}
	if !conflicted {
		data[TokenFieldNumUses] = d.Get(TokenFieldNumUses).(int)
	}

	conflicted = false
	for _, k := range config.TokenBoundCIDRsConflict {
		if _, ok := d.GetOk(k); ok {
			conflicted = true
			break
		}
	}
	if !conflicted {
		data[TokenFieldBoundCIDRs] = d.Get(TokenFieldBoundCIDRs).(*schema.Set).List()
	}

	conflicted = false
	for _, k := range config.AliasMetadataConflict {
		if _, ok := d.GetOk(k); ok {
			conflicted = true
			break
		}
	}

	if !conflicted {
		data[FieldAliasMetadata] = d.Get(FieldAliasMetadata)
	}
}

func updateTokenFields(d *schema.ResourceData, data map[string]interface{}, create bool) {
	if create {
		if v, ok := d.GetOk(TokenFieldBoundCIDRs); ok {
			data[TokenFieldBoundCIDRs] = v.(*schema.Set).List()
		}

		if v, ok := d.GetOk(TokenFieldPolicies); ok {
			data[TokenFieldPolicies] = v.(*schema.Set).List()
		}

		if v, ok := d.GetOk(TokenFieldExplicitMaxTTL); ok {
			data[TokenFieldExplicitMaxTTL] = v.(int)
		}

		if v, ok := d.GetOk(TokenFieldMaxTTL); ok {
			data[TokenFieldMaxTTL] = v.(int)
		}

		if v, ok := d.GetOkExists(TokenFieldNoDefaultPolicy); ok {
			data[TokenFieldNoDefaultPolicy] = v.(bool)
		}

		if v, ok := d.GetOk(TokenFieldPeriod); ok {
			data[TokenFieldPeriod] = v.(int)
		}

		if v, ok := d.GetOk(TokenFieldType); ok {
			data[TokenFieldType] = v.(string)
		}

		if v, ok := d.GetOk(TokenFieldTTL); ok {
			data[TokenFieldTTL] = v.(int)
		}

		if v, ok := d.GetOk(TokenFieldNumUses); ok {
			data[TokenFieldNumUses] = v.(int)
		}

		if v, ok := d.GetOk(FieldAliasMetadata); ok {
			data[FieldAliasMetadata] = v
		}
	} else {
		if d.HasChange(TokenFieldBoundCIDRs) {
			data[TokenFieldBoundCIDRs] = d.Get(TokenFieldBoundCIDRs).(*schema.Set).List()
		}

		if d.HasChange(TokenFieldPolicies) {
			data[TokenFieldPolicies] = d.Get(TokenFieldPolicies).(*schema.Set).List()
		}

		if d.HasChange(TokenFieldExplicitMaxTTL) {
			data[TokenFieldExplicitMaxTTL] = d.Get(TokenFieldExplicitMaxTTL).(int)
		}

		if d.HasChange(TokenFieldMaxTTL) {
			data[TokenFieldMaxTTL] = d.Get(TokenFieldMaxTTL).(int)
		}

		if d.HasChange(TokenFieldNoDefaultPolicy) {
			data[TokenFieldNoDefaultPolicy] = d.Get(TokenFieldNoDefaultPolicy).(bool)
		}

		if d.HasChange(TokenFieldPeriod) {
			data[TokenFieldPeriod] = d.Get(TokenFieldPeriod).(int)
		}

		if d.HasChange(TokenFieldType) {
			data[TokenFieldType] = d.Get(TokenFieldType).(string)
		}

		if d.HasChange(TokenFieldTTL) {
			data[TokenFieldTTL] = d.Get(TokenFieldTTL).(int)
		}

		if d.HasChange(TokenFieldNumUses) {
			data[TokenFieldNumUses] = d.Get(TokenFieldNumUses).(int)
		}

		if d.HasChange(FieldAliasMetadata) {
			data[FieldAliasMetadata] = d.Get(FieldAliasMetadata)
		}
	}
}

func readTokenFields(d *schema.ResourceData, resp *api.Secret) error {
	handlers := map[string]fieldHandlerFunc{
		TokenFieldBoundCIDRs: handleCIDRField,
	}

	return readTokenFieldsWithHandlers(d, resp, handlers)
}

type fieldHandlerFunc func(d *schema.ResourceData, k string, resp *api.Secret) (interface{}, error)

func readTokenFieldsWithHandlers(d *schema.ResourceData, resp *api.Secret, handlers map[string]fieldHandlerFunc) error {
	return setValueWithHandlers(d, getCommonTokenFieldMap(resp), resp, handlers)
}

func setValueWithHandlers(d *schema.ResourceData, fieldMap map[string]interface{}, resp *api.Secret,
	handlers map[string]fieldHandlerFunc,
) error {
	for k, v := range fieldMap {
		var err error
		if f, ok := handlers[k]; ok {
			v, err = f(d, k, resp)
			if err != nil {
				return err
			}
		}
		if err := d.Set(k, v); err != nil {
			return fmt.Errorf("error setting state key %q: %w", k, err)
		}
	}
	return nil
}

func handleCIDRField(d *schema.ResourceData, k string, resp *api.Secret) (interface{}, error) {
	var s *schema.Set
	switch t := d.Get(k).(type) {
	case *schema.Set:
		s = t
	default:
		return nil, fmt.Errorf("unsupported type %T", t)
	}

	var addrs []string

	if v, ok := resp.Data[k]; ok && v != nil {
		for _, val := range v.([]interface{}) {
			// Vault strips the CIDR prefix from IPv4 /32, IPv6 /128 host addresses
			// we want to normalize these addresses unless they are otherwise explicitly
			// configured in the Terraform config.
			addr := val.(string)
			if s != nil && s.Contains(val) {
				addrs = append(addrs, addr)
				continue
			}

			if _, _, err := net.ParseCIDR(addr); err != nil {
				ip := net.ParseIP(addr)
				if ip == nil {
					// should never happen
					return nil, fmt.Errorf("invalid address %q in response", addr)
				}

				var bits int
				if m := ip.DefaultMask(); m != nil {
					// IPv4
					_, bits = m.Size()
				} else {
					// IPv6
					bits = 128
				}
				addr = fmt.Sprintf("%s/%d", addr, bits)
			}
			addrs = append(addrs, addr)
		}
	}

	return addrs, nil
}

func getCommonTokenFieldMap(resp *api.Secret) map[string]interface{} {
	m := make(map[string]interface{})
	for _, k := range commonTokenFields {
		m[k] = resp.Data[k]
	}
	return m
}

func checkCIDRs(d *schema.ResourceData, k string) diag.Diagnostics {
	diags := diag.Diagnostics{}

	var cidrs []interface{}
	if i, ok := d.GetOk(k); ok {
		switch t := i.(type) {
		case *schema.Set:
			cidrs = t.List()
		case []interface{}:
			cidrs = t
		default:
			return diag.Errorf("could not check CIDRs, unsupported type %T", t)
		}

		var invalid []string
		for _, v := range cidrs {
			addr := v.(string)
			if _, _, err := net.ParseCIDR(addr); err != nil {
				invalid = append(invalid, addr)
			}
		}

		count := len(invalid)
		if count > 0 {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Warning,
				Summary: fmt.Sprintf("found %d invalid CIDR block(s) for %q, values=%s", count, k,
					strings.Join(invalid, ",")),
				Detail: `Please ensure all values are configured in CIDR notation. 
This check will be enforced in future releases of the provider, and will result in an error`,
			})
		}
	}
	return diags
}
