// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const testFilePath = "./testdata/fake_account.json"

func TestFrameworkProvider_FileExistsValidator(t *testing.T) {
	cases := map[string]struct {
		configValue        func(t *testing.T) types.String
		expectedErrorCount int
	}{
		"file-is-valid": {
			configValue: func(t *testing.T) types.String {
				return types.StringValue(testFilePath) // Path to a test fixture
			},
		},
		"non-existant-file-is-not-valid": {
			configValue: func(t *testing.T) types.String {
				return types.StringValue("./this/path/doesnt/exist.json") // Doesn't exist
			},
			expectedErrorCount: 1,
		},
		"empty-string-is-not-valid": {
			configValue: func(t *testing.T) types.String {
				return types.StringValue("")
			},
			expectedErrorCount: 1,
		},
		"unconfigured-is-valid": {
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

			f := FileExistsValidator()

			// Act
			f.ValidateString(context.Background(), req, &resp)

			// Assert
			if resp.Diagnostics.ErrorsCount() != tc.expectedErrorCount {
				t.Errorf("Expected %d errors, got %d", tc.expectedErrorCount, resp.Diagnostics.ErrorsCount())
			}
		})
	}
}
