package vault

import (
	"reflect"
	"testing"

	"github.com/hashicorp/vault/api"
)

func TestExpandMountConfigInput(t *testing.T) {
	flattened := []interface{}{
		map[string]interface{}{
			"default_lease_ttl":           "10m",
			"max_lease_ttl":               "20m",
			"audit_non_hmac_request_keys": []interface{}{"foo", "bar"},
			"listing_visibility":          "unauth",
			"passthrough_request_headers": []interface{}{"X-Custom", "X-Mas"},
			"allowed_response_headers":    []interface{}{"X-Response-Custom", "X-Response-Mas"},
			"token_type":                  "default-batch",
			"force_no_cache":              true,
		},
	}
	actual := expandMountConfigInput(flattened)
	expected := api.MountConfigInput{
		DefaultLeaseTTL:           "10m",
		MaxLeaseTTL:               "20m",
		AuditNonHMACRequestKeys:   []string{"foo", "bar"},
		AuditNonHMACResponseKeys:  nil,
		ListingVisibility:         "unauth",
		PassthroughRequestHeaders: []string{"X-Custom", "X-Mas"},
		AllowedResponseHeaders:    []string{"X-Response-Custom", "X-Response-Mas"},
		TokenType:                 "default-batch",
		ForceNoCache:              true,
	}

	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf(
			"Got:\n\n%#v\n\nExpected:\n\n%#v\n",
			actual,
			expected)
	}
}

func TestFlattenAuthMountConfig(t *testing.T) {
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

	actual := flattenAuthMountConfig(expanded)

	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf(
			"Got:\n\n%#v\n\nExpected:\n\n%#v\n",
			actual,
			expected)
	}
}

func TestFlattenMountConfig(t *testing.T) {
	expanded := &api.MountConfigOutput{
		DefaultLeaseTTL:           600,
		MaxLeaseTTL:               1200,
		AuditNonHMACRequestKeys:   []string{"foo", "bar"},
		ListingVisibility:         "",
		PassthroughRequestHeaders: []string{"X-Custom", "X-Mas"},
		AllowedResponseHeaders:    []string{"X-Response-Custom", "X-Response-Mas"},
		ForceNoCache:              true,
	}

	expected := map[string]interface{}{
		"default_lease_ttl":           "10m",
		"max_lease_ttl":               "20m",
		"audit_non_hmac_request_keys": []interface{}{"foo", "bar"},
		"passthrough_request_headers": []interface{}{"X-Custom", "X-Mas"},
		"listing_visibility":          "",
		"allowed_response_headers":    []interface{}{"X-Response-Custom", "X-Response-Mas"},
		"force_no_cache":              true,
	}

	actual := flattenMountConfig(expanded)

	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf(
			"Got:\n\n%#v\n\nExpected:\n\n%#v\n",
			actual,
			expected)
	}
}
