// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"io/ioutil"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const testFakeCredentialsPath = "./testdata/fake_account.json"

func TestFrameworkProvider_CredentialsValidator(t *testing.T) {
	cases := map[string]struct {
		configValue        func(t *testing.T) types.String
		expectedErrorCount int
	}{
		"configuring credentials as a path to a credentials JSON file is valid": {
			configValue: func(t *testing.T) types.String {
				return types.StringValue(testFakeCredentialsPath) // Path to a test fixture
			},
		},
		"configuring credentials as a path to a non-existant file is NOT valid": {
			configValue: func(t *testing.T) types.String {
				return types.StringValue("./this/path/doesnt/exist.json") // Doesn't exist
			},
			expectedErrorCount: 1,
		},
		"configuring credentials as a credentials JSON string is valid": {
			configValue: func(t *testing.T) types.String {
				contents, err := ioutil.ReadFile(testFakeCredentialsPath)
				if err != nil {
					t.Fatalf("Unexpected error: %s", err)
				}
				stringContents := string(contents)
				return types.StringValue(stringContents)
			},
		},
		"configuring credentials as an empty string is not valid": {
			configValue: func(t *testing.T) types.String {
				return types.StringValue("")
			},
			expectedErrorCount: 1,
		},
		"leaving credentials unconfigured is valid": {
			configValue: func(t *testing.T) types.String {
				return types.StringNull()
			},
		},
	}

	for tn, tc := range cases {
		t.Run(tn, func(t *testing.T) {
			// Arrange
			req := validator.StringRequest{
				ConfigValue: tc.configValue(t),
			}

			resp := validator.StringResponse{
				Diagnostics: diag.Diagnostics{},
			}

			cv := GCPCredentialsValidator()

			// Act
			cv.ValidateString(context.Background(), req, &resp)

			// Assert
			if resp.Diagnostics.ErrorsCount() != tc.expectedErrorCount {
				t.Errorf("Expected %d errors, got %d", tc.expectedErrorCount, resp.Diagnostics.ErrorsCount())
			}
		})
	}
}
