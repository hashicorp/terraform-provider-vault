package vault

import (
	"reflect"
	"testing"

	"github.com/hashicorp/vault/api"
)

func TestExpandAuthMethodTune(t *testing.T) {
	flattened := []interface{}{
		map[string]interface{}{
			"default_lease_ttl":           10,
			"max_lease_ttl":               20,
			"audit_non_hmac_request_keys": []interface{}{"foo", "bar"},
			"listing_visibility":          "unauth",
			"passthrough_request_headers": []interface{}{"X-Custom", "X-Mas"},
		},
	}
	actual := expandAuthMethodTune(flattened)
	expected := api.MountConfigInput{
		DefaultLeaseTTL:           "10",
		MaxLeaseTTL:               "20",
		AuditNonHMACRequestKeys:   []string{"foo", "bar"},
		AuditNonHMACResponseKeys:  nil,
		ListingVisibility:         "unauth",
		PassthroughRequestHeaders: []string{"X-Custom", "X-Mas"},
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
		DefaultLeaseTTL:           10,
		MaxLeaseTTL:               20,
		AuditNonHMACRequestKeys:   []string{"foo", "bar"},
		ListingVisibility:         "",
		PassthroughRequestHeaders: []string{"X-Custom", "X-Mas"},
	}

	expected := map[string]interface{}{
		"default_lease_ttl":            10,
		"max_lease_ttl":                20,
		"audit_non_hmac_request_keys":  []interface{}{"foo", "bar"},
		"audit_non_hmac_response_keys": []interface{}{},
		"passthrough_request_headers":  []interface{}{"X-Custom", "X-Mas"},
		"listing_visibility":           "",
	}

	actual := flattenAuthMethodTune(expanded)

	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf(
			"Got:\n\n%#v\n\nExpected:\n\n%#v\n",
			actual,
			expected)
	}
}
