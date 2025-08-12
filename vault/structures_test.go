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
	type args struct {
		rawTune map[string]interface{}
		input   *api.MountConfigInput
	}
	tests := []struct {
		name     string
		args     args
		expected map[string]interface{}
	}{
		{
			name: "Nil input makes merged equal rawTune",
			args: args{
				rawTune: map[string]interface{}{
					// Vault's tune API returns the global defaults for these fields
					"default_lease_ttl":  "768h",
					"max_lease_ttl":      "768h",
					"listing_visibility": "hidden",
				},
				input: nil,
			},
			expected: map[string]interface{}{
				"default_lease_ttl":  "768h",
				"max_lease_ttl":      "768h",
				"listing_visibility": "hidden",
			},
		},
		{
			name: "All empty fields in input zero out corresponding fields in rawTune",
			args: args{
				rawTune: map[string]interface{}{
					// Vault's tune API returns the global defaults for these fields
					"default_lease_ttl":  "768h",
					"max_lease_ttl":      "768h",
					"listing_visibility": "unauth",
				},
				input: &api.MountConfigInput{},
			},
			expected: map[string]interface{}{
				"default_lease_ttl":  "",
				"max_lease_ttl":      "",
				"listing_visibility": "",
			},
		},
		{
			name: "Mixed: some empty, some non-empty",
			args: args{
				rawTune: map[string]interface{}{
					"default_lease_ttl":  "768h",
					"max_lease_ttl":      "20h",
					"listing_visibility": "unauth",
					"token_type":         "default-service",
				},
				input: &api.MountConfigInput{
					DefaultLeaseTTL:   "",
					MaxLeaseTTL:       "20m",
					ListingVisibility: "",
					TokenType:         "default-service",
				},
			},
			expected: map[string]interface{}{
				"default_lease_ttl":  "",
				"max_lease_ttl":      "20h",
				"listing_visibility": "",
				"token_type":         "default-service",
			},
		},
		{
			name: "Partial: only DefaultLeaseTTL is specified",
			args: args{
				rawTune: map[string]interface{}{
					"default_lease_ttl":  "10m",
					"max_lease_ttl":      "768h",
					"listing_visibility": "unauth",
				},
				input: &api.MountConfigInput{
					DefaultLeaseTTL:   "10m",
					MaxLeaseTTL:       "",
					ListingVisibility: "unauth",
				},
			},
			expected: map[string]interface{}{
				"default_lease_ttl":  "10m",
				"max_lease_ttl":      "",
				"listing_visibility": "unauth",
			},
		},
		{
			name: "Partial: only MaxLeaseTTL is specified",
			args: args{
				rawTune: map[string]interface{}{
					"default_lease_ttl":  "",
					"max_lease_ttl":      "10m",
					"listing_visibility": "hidden",
				},
				input: &api.MountConfigInput{
					DefaultLeaseTTL:   "",
					MaxLeaseTTL:       "10m",
					ListingVisibility: "",
				},
			},
			expected: map[string]interface{}{
				"default_lease_ttl":  "",
				"max_lease_ttl":      "10m",
				"listing_visibility": "",
			},
		},
		{
			name: "Partial: only ListingVisibility is specified",
			args: args{
				rawTune: map[string]interface{}{
					"default_lease_ttl":  "768h",
					"max_lease_ttl":      "768h",
					"listing_visibility": "unauth",
				},
				input: &api.MountConfigInput{
					DefaultLeaseTTL:   "",
					MaxLeaseTTL:       "",
					ListingVisibility: "unauth",
				},
			},
			expected: map[string]interface{}{
				"default_lease_ttl":  "",
				"max_lease_ttl":      "",
				"listing_visibility": "unauth",
			},
		},
		{
			name: "Full: all fields specified",
			args: args{
				rawTune: map[string]interface{}{
					"default_lease_ttl":            "768h", // global default
					"max_lease_ttl":                "768h", // global default
					"audit_non_hmac_request_keys":  []interface{}{"foo", "bar"},
					"audit_non_hmac_response_keys": []interface{}{"baz"},
					"listing_visibility":           "unauth",
					"passthrough_request_headers":  []interface{}{"X-Custom", "X-Mas"},
					"allowed_response_headers":     []interface{}{"X-Response-Custom", "X-Response-Mas"},
					"token_type":                   "default-service",
				},

				input: &api.MountConfigInput{
					DefaultLeaseTTL:           "",
					MaxLeaseTTL:               "",
					AuditNonHMACRequestKeys:   []string{"foo", "bar"},
					AuditNonHMACResponseKeys:  []string{"baz"},
					ListingVisibility:         "unauth",
					PassthroughRequestHeaders: []string{"X-Custom", "X-Mas"},
					AllowedResponseHeaders:    []string{"X-Response-Custom", "X-Response-Mas"},
					TokenType:                 "default-service",
				},
			},
			expected: map[string]interface{}{
				"default_lease_ttl":            "",
				"max_lease_ttl":                "",
				"audit_non_hmac_request_keys":  []interface{}{"foo", "bar"},
				"audit_non_hmac_response_keys": []interface{}{"baz"},
				"listing_visibility":           "unauth",
				"passthrough_request_headers":  []interface{}{"X-Custom", "X-Mas"},
				"allowed_response_headers":     []interface{}{"X-Response-Custom", "X-Response-Mas"},
				"token_type":                   "default-service",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := mergeAuthMethodTune(tt.args.rawTune, tt.args.input)
			if !reflect.DeepEqual(actual, tt.expected) {
				t.Fatalf("Test %q failed:\nGot:\n%#v\nExpected:\n%#v\n", tt.name, actual, tt.expected)
			}
		})
	}
}
