package vault

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAuthBackendMigrateState(t *testing.T) {
	cases := map[string]struct {
		StateVersion int
		Attributes   map[string]string
		Expected     map[string]string
		ID           string
		ExpectedID   string
	}{
		"switch ID to path instead of type": {
			StateVersion: 0,
			Attributes: map[string]string{
				"type": "github",
				"path": "github-123/",
			},
			Expected: map[string]string{
				"type": "github",
				"path": "github-123/",
			},
			ID:         "github",
			ExpectedID: "github-123",
		},
	}

	for tn, tc := range cases {
		is := &terraform.InstanceState{
			ID:         tc.ID,
			Attributes: tc.Attributes,
		}
		is, err := resourceAuthBackendMigrateState(
			tc.StateVersion, is, nil)

		if err != nil {
			t.Fatalf("Unexpected error for migration %q: %+v", tn, err)
		}

		if is.ID != tc.ExpectedID {
			t.Fatalf("Expected %q to be %v for %q, got %v", "ID", tc.ExpectedID, tn, is.ID)
		}
		for k, v := range tc.Expected {
			if is.Attributes[k] != v {
				t.Fatalf("Expected %q to be %v for %q, got %v", k, v, tn, is.Attributes[k])
			}
		}
	}
}
