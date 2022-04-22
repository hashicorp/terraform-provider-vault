package vault

import (
	"testing"

	"github.com/hashicorp/vault/api"
)

func TestSemVerComparison(t *testing.T) {
	client := testProvider.Meta().(*api.Client)

	testCases := []struct {
		name       string
		minVersion string
		expected   bool
	}{
		{
			"less-than",
			"1.8.0",
			true,
		},
		{
			"greater-than",
			"1.12.0",
			false,
		},
		{
			"equal",
			"1.10.0",
			true,
		},
	}

	for _, tt := range testCases {
		compare, err := semVerComparison(tt.minVersion, client)
		if err != nil {
			t.Fatal(err)
		}

		if compare != tt.expected {
			t.Fatalf("expected semantic version to return %t, got %t", tt.expected, compare)
		}
	}
}
