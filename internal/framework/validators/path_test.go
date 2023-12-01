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

func TestFrameworkProvider_PathValidator(t *testing.T) {
	cases := map[string]struct {
		ConfigValue          func(t *testing.T) types.String
		ExpectedWarningCount int
		ExpectedErrorCount   int
	}{
		"valid": {
			ConfigValue: func(t *testing.T) types.String {
				return types.StringValue("foo")
			},
		},
		"invalid-leading": {
			ConfigValue: func(t *testing.T) types.String {
				return types.StringValue("/foo")
			},
			ExpectedErrorCount: 1,
		},
		"invalid-trailing": {
			ConfigValue: func(t *testing.T) types.String {
				return types.StringValue("foo/")
			},
			ExpectedErrorCount: 1,
		},
		"invalid-both": {
			ConfigValue: func(t *testing.T) types.String {
				return types.StringValue("/foo/")
			},
			ExpectedErrorCount: 1,
		},
	}

	for tn, tc := range cases {
		t.Run(tn, func(t *testing.T) {
			// Arrange
			req := validator.StringRequest{
				ConfigValue: tc.ConfigValue(t),
			}

			resp := validator.StringResponse{
				Diagnostics: diag.Diagnostics{},
			}

			cv := PathValidator()

			// Act
			cv.ValidateString(context.Background(), req, &resp)

			// Assert
			if resp.Diagnostics.WarningsCount() > tc.ExpectedWarningCount {
				t.Errorf("Expected %d warnings, got %d", tc.ExpectedWarningCount, resp.Diagnostics.WarningsCount())
			}
			if resp.Diagnostics.ErrorsCount() > tc.ExpectedErrorCount {
				t.Errorf("Expected %d errors, got %d: %s", tc.ExpectedErrorCount, resp.Diagnostics.ErrorsCount(), resp.Diagnostics.Errors())
			}
		})
	}
}
