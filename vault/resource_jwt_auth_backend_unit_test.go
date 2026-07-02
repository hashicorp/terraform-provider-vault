// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"testing"
)

func TestConvertProviderConfigValues(t *testing.T) {
	t.Run("converts typed keys and passes through the rest", func(t *testing.T) {
		input := map[string]interface{}{
			"provider":                 "azure",
			"fetch_groups":             "true",
			"fetch_user_info":          "false",
			"use_workload_identity":    "true",
			"groups_recurse_max_depth": "5",
		}

		got, err := convertProviderConfigValues(input)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}

		if v, ok := got["use_workload_identity"].(bool); !ok || v != true {
			t.Errorf("use_workload_identity = %#v, want bool true", got["use_workload_identity"])
		}
		if v, ok := got["fetch_groups"].(bool); !ok || v != true {
			t.Errorf("fetch_groups = %#v, want bool true", got["fetch_groups"])
		}
		if v, ok := got["fetch_user_info"].(bool); !ok || v != false {
			t.Errorf("fetch_user_info = %#v, want bool false", got["fetch_user_info"])
		}
		if v, ok := got["groups_recurse_max_depth"].(int64); !ok || v != 5 {
			t.Errorf("groups_recurse_max_depth = %#v, want int64 5", got["groups_recurse_max_depth"])
		}
		if v, ok := got["provider"].(string); !ok || v != "azure" {
			t.Errorf("provider = %#v, want string \"azure\"", got["provider"])
		}
	})

	t.Run("returns an error for a non-bool use_workload_identity", func(t *testing.T) {
		if _, err := convertProviderConfigValues(map[string]interface{}{
			"use_workload_identity": "notabool",
		}); err == nil {
			t.Fatal("expected error for invalid bool value, got nil")
		}
	})
}
