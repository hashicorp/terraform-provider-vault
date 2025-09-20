// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
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
	actual, err := expandAuthMethodTune(flattened)
	if err != nil {
		t.Fatalf("error expanding auth method tune: %s", err)
	}
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
		expected []map[string]interface{}
	}{
		{
			name: "Nil input makes merged equal to rawTune. Equivalent to the state import",
			args: args{
				rawTune: map[string]interface{}{
					// Vault's tune API returns the global defaults for these fields
					consts.FieldDefaultLeaseTTL:   "768h",
					consts.FieldMaxLeaseTTL:       "768h",
					consts.FieldListingVisibility: "hidden",
					consts.FieldTokenType:         "default-service",
				},
				input: nil,
			},
			expected: []map[string]interface{}{
				{
					consts.FieldDefaultLeaseTTL:   "768h",
					consts.FieldMaxLeaseTTL:       "768h",
					consts.FieldListingVisibility: "hidden",
					consts.FieldTokenType:         "default-service",
				},
			},
		},
		{
			name: "All empty fields in input zero out corresponding fields in rawTune",
			args: args{
				rawTune: map[string]interface{}{
					// Vault's tune API returns the global defaults for these fields
					consts.FieldDefaultLeaseTTL:   "768h",
					consts.FieldMaxLeaseTTL:       "768h",
					consts.FieldListingVisibility: "hidden",
					consts.FieldTokenType:         "default-service",
				},
				input: &api.MountConfigInput{},
			},
			expected: []map[string]interface{}{
				{
					consts.FieldDefaultLeaseTTL:   "",
					consts.FieldMaxLeaseTTL:       "",
					consts.FieldListingVisibility: "",
					consts.FieldTokenType:         "",
				},
			},
		},
		{
			name: "Mixed: some empty, some non-empty",
			args: args{
				rawTune: map[string]interface{}{
					consts.FieldDefaultLeaseTTL:   "768h",
					consts.FieldMaxLeaseTTL:       "20h",
					consts.FieldListingVisibility: "hidden",
					consts.FieldTokenType:         "default-service",
				},
				input: &api.MountConfigInput{
					MaxLeaseTTL: "20h",
					TokenType:   "default-service",
				},
			},
			expected: []map[string]interface{}{
				{
					consts.FieldDefaultLeaseTTL:   "",
					consts.FieldMaxLeaseTTL:       "20h",
					consts.FieldListingVisibility: "",
					consts.FieldTokenType:         "default-service",
				},
			},
		},
		{
			name: "Partial: only DefaultLeaseTTL is specified",
			args: args{
				rawTune: map[string]interface{}{
					consts.FieldDefaultLeaseTTL:   "10m",
					consts.FieldMaxLeaseTTL:       "768h",
					consts.FieldListingVisibility: "hidden",
					consts.FieldTokenType:         "default-service",
				},
				input: &api.MountConfigInput{
					DefaultLeaseTTL: "10m",
				},
			},
			expected: []map[string]interface{}{
				{
					consts.FieldDefaultLeaseTTL:   "10m",
					consts.FieldMaxLeaseTTL:       "",
					consts.FieldListingVisibility: "",
					consts.FieldTokenType:         "",
				},
			},
		},
		{
			name: "Partial: only MaxLeaseTTL is specified",
			args: args{
				rawTune: map[string]interface{}{
					consts.FieldDefaultLeaseTTL:   "768h",
					consts.FieldMaxLeaseTTL:       "10m",
					consts.FieldListingVisibility: "hidden",
					consts.FieldTokenType:         "default-service",
				},
				input: &api.MountConfigInput{
					MaxLeaseTTL: "10m",
				},
			},
			expected: []map[string]interface{}{
				{
					consts.FieldDefaultLeaseTTL:   "",
					consts.FieldMaxLeaseTTL:       "10m",
					consts.FieldListingVisibility: "",
					consts.FieldTokenType:         "",
				},
			},
		},
		{
			name: "Partial: only ListingVisibility is specified",
			args: args{
				rawTune: map[string]interface{}{
					consts.FieldDefaultLeaseTTL:   "768h",
					consts.FieldMaxLeaseTTL:       "768h",
					consts.FieldListingVisibility: "unauth",
					consts.FieldTokenType:         "default-service",
				},
				input: &api.MountConfigInput{
					ListingVisibility: "unauth",
				},
			},
			expected: []map[string]interface{}{
				{
					consts.FieldDefaultLeaseTTL:   "",
					consts.FieldMaxLeaseTTL:       "",
					consts.FieldListingVisibility: "unauth",
					consts.FieldTokenType:         "",
				},
			},
		},
		{
			name: "Partial: only TokenType is specified",
			args: args{
				rawTune: map[string]interface{}{
					consts.FieldDefaultLeaseTTL:   "768h",
					consts.FieldMaxLeaseTTL:       "768h",
					consts.FieldListingVisibility: "hidden",
					// use the non-default value
					consts.FieldTokenType: "default-batch",
				},
				input: &api.MountConfigInput{
					TokenType: "default-batch",
				},
			},
			expected: []map[string]interface{}{
				{
					consts.FieldDefaultLeaseTTL:   "",
					consts.FieldMaxLeaseTTL:       "",
					consts.FieldListingVisibility: "",
					consts.FieldTokenType:         "default-batch",
				},
			},
		},
		{
			name: "Full: all fields specified",
			args: args{
				rawTune: map[string]interface{}{
					consts.FieldDefaultLeaseTTL:           "768h", // global default
					consts.FieldMaxLeaseTTL:               "768h", // global default
					consts.FieldAuditNonHMACRequestKeys:   []interface{}{"foo", "bar"},
					consts.FieldAuditNonHMACResponseKeys:  []interface{}{"baz"},
					consts.FieldListingVisibility:         "unauth",
					consts.FieldPassthroughRequestHeaders: []interface{}{"X-Custom", "X-Mas"},
					consts.FieldAllowedResponseHeaders:    []interface{}{"X-Response-Custom", "X-Response-Mas"},
					consts.FieldTokenType:                 "default-batch",
				},

				input: &api.MountConfigInput{
					DefaultLeaseTTL:           "",
					MaxLeaseTTL:               "",
					AuditNonHMACRequestKeys:   []string{"foo", "bar"},
					AuditNonHMACResponseKeys:  []string{"baz"},
					ListingVisibility:         "unauth",
					PassthroughRequestHeaders: []string{"X-Custom", "X-Mas"},
					AllowedResponseHeaders:    []string{"X-Response-Custom", "X-Response-Mas"},
					TokenType:                 "default-batch",
				},
			},
			expected: []map[string]interface{}{
				{
					consts.FieldDefaultLeaseTTL:           "",
					consts.FieldMaxLeaseTTL:               "",
					consts.FieldAuditNonHMACRequestKeys:   []interface{}{"foo", "bar"},
					consts.FieldAuditNonHMACResponseKeys:  []interface{}{"baz"},
					consts.FieldListingVisibility:         "unauth",
					consts.FieldPassthroughRequestHeaders: []interface{}{"X-Custom", "X-Mas"},
					consts.FieldAllowedResponseHeaders:    []interface{}{"X-Response-Custom", "X-Response-Mas"},
					consts.FieldTokenType:                 "default-batch",
				},
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
