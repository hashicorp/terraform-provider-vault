package vault

import (
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

func sharedAuthAndMountSchema(fields map[string]*schema.Schema) *schema.Schema {
	baseFields := map[string]*schema.Schema{
		"default_lease_ttl": {
			Type:         schema.TypeString,
			Optional:     true,
			Description:  "Specifies the default time-to-live duration. This overrides the global default. A value of 0 is equivalent to the system default TTL",
			ValidateFunc: validateDuration,
		},
		"max_lease_ttl": {
			Type:         schema.TypeString,
			Optional:     true,
			Description:  "Specifies the maximum time-to-live duration. This overrides the global default. A value of 0 are equivalent and set to the system max TTL.",
			ValidateFunc: validateDuration,
		},
		"audit_non_hmac_request_keys": {
			Type:        schema.TypeList,
			Optional:    true,
			Description: "Specifies the list of keys that will not be HMAC'd by audit devices in the request data object.",
			Elem:        &schema.Schema{Type: schema.TypeString},
		},
		"audit_non_hmac_response_keys": {
			Type:        schema.TypeList,
			Optional:    true,
			Description: "Specifies the list of keys that will not be HMAC'd by audit devices in the response data object.",
			Elem:        &schema.Schema{Type: schema.TypeString},
		},
		"listing_visibility": {
			Type:         schema.TypeString,
			Optional:     true,
			Description:  "Specifies whether to show this mount in the UI-specific listing endpoint. Valid values are \"unauth\" or \"hidden\". If not set, behaves like \"hidden\".",
			ValidateFunc: validation.StringInSlice([]string{"unauth", "hidden"}, false),
		},
		"passthrough_request_headers": {
			Type:        schema.TypeList,
			Optional:    true,
			Description: "List of headers to whitelist and pass from the request to the backend.",
			Elem:        &schema.Schema{Type: schema.TypeString},
		},
		"allowed_response_headers": {
			Type:        schema.TypeList,
			Optional:    true,
			Description: "List of headers to whitelist and allowing a plugin to include them in the response.",
			Elem:        &schema.Schema{Type: schema.TypeString},
		},
	}

	for k, v := range fields {
		baseFields[k] = v
	}
	return &schema.Schema{
		Type:       schema.TypeSet,
		Optional:   true,
		Computed:   true,
		MaxItems:   1,
		ConfigMode: schema.SchemaConfigModeAttr,
		Elem: &schema.Resource{
			Schema: baseFields,
		},
	}
}
func expandMountConfigInput(rawL []interface{}) api.MountConfigInput {
	data := api.MountConfigInput{}
	if len(rawL) == 0 {
		return data
	}
	raw := rawL[0].(map[string]interface{})

	if v, ok := raw["default_lease_ttl"]; ok {
		data.DefaultLeaseTTL = v.(string)
	}
	if v, ok := raw["max_lease_ttl"]; ok {
		data.MaxLeaseTTL = v.(string)
	}
	if v, ok := raw["audit_non_hmac_request_keys"]; ok {
		data.AuditNonHMACRequestKeys = expandStringSliceWithEmpty(v.([]interface{}), true)
	}
	if v, ok := raw["audit_non_hmac_response_keys"]; ok {
		data.AuditNonHMACResponseKeys = expandStringSliceWithEmpty(v.([]interface{}), true)
	}
	if v, ok := raw["listing_visibility"]; ok {
		data.ListingVisibility = v.(string)
	}
	if v, ok := raw["passthrough_request_headers"]; ok {
		data.PassthroughRequestHeaders = expandStringSliceWithEmpty(v.([]interface{}), true)
	}
	if v, ok := raw["allowed_response_headers"]; ok {
		data.AllowedResponseHeaders = expandStringSliceWithEmpty(v.([]interface{}), true)
	}
	if v, ok := raw["token_type"]; ok {
		data.TokenType = v.(string)
	}
	if v, ok := raw["force_no_cache"]; ok {
		data.ForceNoCache = v.(bool)
	}
	return data
}

func flattenAuthMountConfig(dt *api.MountConfigOutput) map[string]interface{} {
	m := flattenMountConfigShared(dt)
	m["token_type"] = dt.TokenType
	return m
}
func flattenMountConfigShared(dt *api.MountConfigOutput) map[string]interface{} {
	m := make(map[string]interface{})
	m["default_lease_ttl"] = flattenVaultDuration(dt.DefaultLeaseTTL)
	m["max_lease_ttl"] = flattenVaultDuration(dt.MaxLeaseTTL)
	if len(dt.AuditNonHMACRequestKeys) > 0 && dt.AuditNonHMACRequestKeys[0] != "" {
		m["audit_non_hmac_request_keys"] = flattenStringSlice(dt.AuditNonHMACRequestKeys)
	}
	if len(dt.AuditNonHMACResponseKeys) > 0 && dt.AuditNonHMACResponseKeys[0] != "" {
		m["audit_non_hmac_response_keys"] = flattenStringSlice(dt.AuditNonHMACResponseKeys)
	}
	m["listing_visibility"] = dt.ListingVisibility
	if len(dt.PassthroughRequestHeaders) > 0 && dt.PassthroughRequestHeaders[0] != "" {
		m["passthrough_request_headers"] = flattenStringSlice(dt.PassthroughRequestHeaders)
	}
	if len(dt.AllowedResponseHeaders) > 0 && dt.AllowedResponseHeaders[0] != "" {
		m["allowed_response_headers"] = flattenStringSlice(dt.AllowedResponseHeaders)
	}
	return m
}
func flattenMountConfig(dt *api.MountConfigOutput) map[string]interface{} {
	m := flattenMountConfigShared(dt)
	m["force_no_cache"] = dt.ForceNoCache
	return m
}

func expandStringSlice(configured []interface{}) []string {
	vs := make([]string, 0, len(configured))
	for _, v := range configured {
		val, ok := v.(string)
		if ok && val != "" {
			vs = append(vs, v.(string))
		}
	}
	return vs
}

func expandStringSliceWithEmpty(configured []interface{}, returnSingleEmpty bool) []string {
	if returnSingleEmpty && len(configured) == 0 {
		return []string{""}
	}
	vs := make([]string, 0, len(configured))
	for _, v := range configured {
		val, ok := v.(string)
		if ok && val != "" {
			vs = append(vs, v.(string))
		}
	}
	return vs
}

func flattenStringSlice(list []string) []interface{} {
	vs := make([]interface{}, 0, len(list))
	for _, v := range list {
		vs = append(vs, v)
	}
	return vs
}

func flattenCommaSeparatedStringSlice(s string) []interface{} {
	split := strings.Split(s, ",")
	vs := make([]interface{}, 0, len(split))
	for _, v := range split {
		vs = append(vs, v)
	}
	log.Printf("[INFO] flattenedCommaSeparatedList: %+v", vs)
	return vs
}

func flattenVaultDuration(d interface{}) string {
	if d == nil {
		return time.Duration(0).String()
	}

	switch d.(type) {
	case int:
		return util.ShortDur(time.Duration(d.(int)) * time.Second)
	case int64:
		return util.ShortDur(time.Duration(d.(int64)) * time.Second)
	case json.Number:
		if i, err := d.(json.Number).Int64(); err == nil {
			return util.ShortDur(time.Duration(i) * time.Second)
		}
	}

	return time.Duration(0).String()
}
