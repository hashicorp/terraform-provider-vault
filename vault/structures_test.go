// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"reflect"
	"testing"

	"github.com/hashicorp/vault/api"
)

func TestExpandAuthMethodTune(t *testing.T) {
	flattened := []interface{}{
		map[string]interface{}{
			"default_lease_ttl":           "10m",
			"max_lease_ttl":               "20m",
			"audit_non_hmac_request_keys": []interface{}{"foo", "bar"},
			"listing_visibility":          "unauth",
			"passthrough_request_headers": []interface{}{"X-Custom", "X-Mas"},
			"allowed_response_headers":    []interface{}{"X-Response-Custom", "X-Response-Mas"},
			"token_type":                  "default-batch",
		},
	}
	actual := expandAuthMethodTune(flattened)
	expected := api.MountConfigInput{
		DefaultLeaseTTL:           "10m",
		MaxLeaseTTL:               "20m",
		AuditNonHMACRequestKeys:   []string{"foo", "bar"},
		AuditNonHMACResponseKeys:  nil,
		ListingVisibility:         "unauth",
		PassthroughRequestHeaders: []string{"X-Custom", "X-Mas"},
		AllowedResponseHeaders:    []string{"X-Response-Custom", "X-Response-Mas"},
		TokenType:                 "default-batch",
	}

	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf(
			"Got:\n\n%#v\n\nExpected:\n\n%#v\n",
			actual,
			expected)
	}
}

func TestFlattenAuthMethodTune(t *testing.T) {
	expanded := &api.MountConfigOutput{
		DefaultLeaseTTL:           600,
		MaxLeaseTTL:               1200,
		AuditNonHMACRequestKeys:   []string{"foo", "bar"},
		ListingVisibility:         "",
		PassthroughRequestHeaders: []string{"X-Custom", "X-Mas"},
		AllowedResponseHeaders:    []string{"X-Response-Custom", "X-Response-Mas"},
		TokenType:                 "default-service",
	}

	expected := map[string]interface{}{
		"default_lease_ttl":           "10m",
		"max_lease_ttl":               "20m",
		"audit_non_hmac_request_keys": []interface{}{"foo", "bar"},
		"passthrough_request_headers": []interface{}{"X-Custom", "X-Mas"},
		"listing_visibility":          "",
		"allowed_response_headers":    []interface{}{"X-Response-Custom", "X-Response-Mas"},
		"token_type":                  "default-service",
	}

	actual := flattenAuthMethodTune(expanded)

	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf(
			"Got:\n\n%#v\n\nExpected:\n\n%#v\n",
			actual,
			expected)
	}
}

func TestMergeAuthMethodTune(t *testing.T) {
	rawTune := map[string]interface{}{
		"default_lease_ttl":            "768h", // global default
		"max_lease_ttl":                "768h", // global default
		"audit_non_hmac_request_keys":  []interface{}{"foo", "bar"},
		"audit_non_hmac_response_keys": []interface{}{},
		"listing_visibility":           "",
		"passthrough_request_headers":  []interface{}{"X-Custom", "X-Mas"},
		"allowed_response_headers":     []interface{}{"X-Response-Custom", "X-Response-Mas"},
		"token_type":                   "default-service",
	}

	input := &api.MountConfigInput{
		DefaultLeaseTTL:           "",
		MaxLeaseTTL:               "",
		AuditNonHMACRequestKeys:   []string{"foo", "bar"},
		AuditNonHMACResponseKeys:  []string{},
		ListingVisibility:         "",
		PassthroughRequestHeaders: []string{"X-Custom", "X-Mas"},
		AllowedResponseHeaders:    []string{"X-Response-Custom", "X-Response-Mas"},
		TokenType:                 "default-service",
	}

	expected := map[string]interface{}{
		"default_lease_ttl":            "",
		"max_lease_ttl":                "",
		"audit_non_hmac_request_keys":  []interface{}{"foo", "bar"},
		"audit_non_hmac_response_keys": []interface{}{},
		"listing_visibility":           "",
		"passthrough_request_headers":  []interface{}{"X-Custom", "X-Mas"},
		"allowed_response_headers":     []interface{}{"X-Response-Custom", "X-Response-Mas"},
		"token_type":                   "default-service",
	}

	actual := mergeAuthMethodTune(rawTune, input)

	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf(
			"Got:\n\n%#v\n\nExpected:\n\n%#v\n",
			actual,
			expected)
	}
}
