package vault

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestGenericSecretMigrateState(t *testing.T) {
	cases := map[string]struct {
		StateVersion int
		Attributes   map[string]string
		Expected     map[string]string
	}{
		"unset allow_read to disable_read": {
			StateVersion: 0,
			Attributes: map[string]string{
				"data_json": `{"hello": "world"}`,
				"path":      "secret/test-123",
			},
			Expected: map[string]string{
				"data_json": `{"hello": "world"}`,
				"path":      "secret/test-123",
			},
		},
		"allow_read false to disable_read": {
			StateVersion: 0,
			Attributes: map[string]string{
				"data_json":  `{"hello": "world"}`,
				"path":       "secret/test-123",
				"allow_read": "false",
			},
			Expected: map[string]string{
				"data_json":    `{"hello": "world"}`,
				"path":         "secret/test-123",
				"disable_read": "true",
			},
		},
		"allow_read true to disable_read": {
			StateVersion: 0,
			Attributes: map[string]string{
				"data_json":  `{"hello": "world"}`,
				"path":       "secret/test-123",
				"allow_read": "true",
			},
			Expected: map[string]string{
				"data_json": `{"hello": "world"}`,
				"path":      "secret/test-123",
			},
		},
	}

	for tn, tc := range cases {
		is, err := resourceGenericSecretMigrateState(
			tc.StateVersion, &terraform.InstanceState{
				ID:         tc.Attributes["path"],
				Attributes: tc.Attributes,
			}, nil)

		if err != nil {
			t.Fatalf("Unexpected error for migration %q: %+v", tn, err)
		}

		for k, v := range tc.Expected {
			if is.Attributes[k] != v {
				t.Fatalf("Expected %q to be %v for %q, got %v", k, v, tn, is.Attributes[k])
			}
		}
	}
}
