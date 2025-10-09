// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func expandAuthMethodTune(raw interface{}) (api.MountConfigInput, error) {
	data := api.MountConfigInput{}
	rawL, ok := raw.([]interface{})
	if !ok {
		return data, fmt.Errorf("error type asserting tune block: expected []interface{}, got %T", raw)
	}

	if len(rawL) == 0 {
		return data, nil
	}
	config := rawL[0].(map[string]interface{})

	if v, ok := config[consts.FieldDefaultLeaseTTL]; ok {
		data.DefaultLeaseTTL = v.(string)
	}
	if v, ok := config[consts.FieldMaxLeaseTTL]; ok {
		data.MaxLeaseTTL = v.(string)
	}
	if v, ok := config[consts.FieldAuditNonHMACRequestKeys]; ok {
		data.AuditNonHMACRequestKeys = expandStringSliceWithEmpty(v.([]interface{}), true)
	}
	if v, ok := config[consts.FieldAuditNonHMACResponseKeys]; ok {
		data.AuditNonHMACResponseKeys = expandStringSliceWithEmpty(v.([]interface{}), true)
	}
	if v, ok := config[consts.FieldListingVisibility]; ok {
		data.ListingVisibility = v.(string)
	}
	if v, ok := config[consts.FieldPassthroughRequestHeaders]; ok {
		data.PassthroughRequestHeaders = expandStringSliceWithEmpty(v.([]interface{}), true)
	}
	if v, ok := config[consts.FieldAllowedResponseHeaders]; ok {
		data.AllowedResponseHeaders = expandStringSliceWithEmpty(v.([]interface{}), true)
	}
	if v, ok := config[consts.FieldTokenType]; ok {
		data.TokenType = v.(string)
	}
	return data, nil
}

func flattenAuthMethodTune(dt *api.MountConfigOutput) map[string]interface{} {
	m := make(map[string]interface{})

	m[consts.FieldDefaultLeaseTTL] = flattenVaultDuration(dt.DefaultLeaseTTL)
	m[consts.FieldMaxLeaseTTL] = flattenVaultDuration(dt.MaxLeaseTTL)
	if len(dt.AuditNonHMACRequestKeys) > 0 && dt.AuditNonHMACRequestKeys[0] != "" {
		m[consts.FieldAuditNonHMACRequestKeys] = flattenStringSlice(dt.AuditNonHMACRequestKeys)
	}
	if len(dt.AuditNonHMACResponseKeys) > 0 && dt.AuditNonHMACResponseKeys[0] != "" {
		m[consts.FieldAuditNonHMACResponseKeys] = flattenStringSlice(dt.AuditNonHMACResponseKeys)
	}
	m[consts.FieldListingVisibility] = dt.ListingVisibility
	if len(dt.PassthroughRequestHeaders) > 0 && dt.PassthroughRequestHeaders[0] != "" {
		m[consts.FieldPassthroughRequestHeaders] = flattenStringSlice(dt.PassthroughRequestHeaders)
	}
	if len(dt.AllowedResponseHeaders) > 0 && dt.AllowedResponseHeaders[0] != "" {
		m[consts.FieldAllowedResponseHeaders] = flattenStringSlice(dt.AllowedResponseHeaders)
	}
	m[consts.FieldTokenType] = dt.TokenType
	return m
}

// retrieveMountConfigInput retrieves the tune block from the resource data
// and converts it into a reference to api.MountConfigInput
func retrieveMountConfigInput(d *schema.ResourceData) (*api.MountConfigInput, error) {
	// If the tune block is not set, it means the user did not
	// provide any values or the block is imported
	tune, ok := d.GetOk("tune")
	if !ok {
		return nil, nil
	}

	tuneL, ok := tune.([]interface{})
	if !ok {
		return nil, fmt.Errorf("error type asserting tune block: expected []interface{}, got %T", tune)
	}

	input, err := expandAuthMethodTune(tuneL)
	if err != nil {
		return nil, err
	}

	return &input, nil
}

// mergeAuthMethodTune merges the raw tune GET API response with the non-nil
// *api.MountConfigInput parsed from the resource data.
// Any field with the Vault APIs's global default effect will be set to empty
// when the user did not provide a value even if the Vault API response returns non-empty.
// This is to ensure the tune block reflects the user provided values.
// See more details in the https://github.com/hashicorp/terraform-provider-vault/issues/2234
func mergeAuthMethodTune(rawTune map[string]interface{}, input *api.MountConfigInput) []map[string]interface{} {
	mergedRawTune := make(map[string]interface{})
	for k, v := range rawTune {
		mergedRawTune[k] = v
	}

	// Merge the fields that have the global default effect
	// github.com/hashicorp/terraform-provider-vault/vault/auth_mount.go
	// If the input is nil
	if input != nil {
		if input.TokenType == "" {
			mergedRawTune[consts.FieldTokenType] = ""
		}
		if input.ListingVisibility == "" {
			mergedRawTune[consts.FieldListingVisibility] = ""
		}

		// Some tune API GET responses may convert *TTL fields of string
		// e.g. default_lease_ttl = "200s", which
		// is the user provided value, will be converted to "3m20s".
		//
		// The merged takes the user provided value
		mergedRawTune[consts.FieldDefaultLeaseTTL] = input.DefaultLeaseTTL
		mergedRawTune[consts.FieldMaxLeaseTTL] = input.MaxLeaseTTL
	}

	return []map[string]interface{}{mergedRawTune}
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
