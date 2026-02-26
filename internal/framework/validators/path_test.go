// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestFrameworkProvider_PathValidator(t *testing.T) {
	cases := map[string]struct {
		configValue        func(t *testing.T) types.String
		expectedErrorCount int
	}{
		"valid": {
			configValue: func(t *testing.T) types.String {
				return types.StringValue("foo")
			},
		},
		"valid-nested": {
			configValue: func(t *testing.T) types.String {
				return types.StringValue("foo/bar")
			},
		},
		"invalid-leading": {
			configValue: func(t *testing.T) types.String {
				return types.StringValue("/foo")
			},
			expectedErrorCount: 1,
		},
		"invalid-trailing": {
			configValue: func(t *testing.T) types.String {
				return types.StringValue("foo/")
			},
			expectedErrorCount: 1,
		},
		"invalid-both": {
			configValue: func(t *testing.T) types.String {
				return types.StringValue("/foo/")
			},
			expectedErrorCount: 1,
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

			cv := PathValidator()

			// Act
			cv.ValidateString(context.Background(), req, &resp)

			// Assert
			if resp.Diagnostics.ErrorsCount() != tc.expectedErrorCount {
				t.Errorf("Expected %d errors, got %d: %s", tc.expectedErrorCount, resp.Diagnostics.ErrorsCount(), resp.Diagnostics.Errors())
			}
		})
	}
}
