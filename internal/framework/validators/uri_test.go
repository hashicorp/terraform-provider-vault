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

func TestFrameworkProvider_URIValidator(t *testing.T) {
	cases := map[string]struct {
		configValue        func(t *testing.T) types.String
		schemes            []string
		expectedErrorCount int
	}{
		"basic": {
			configValue: func(t *testing.T) types.String {
				return types.StringValue("http://foo.baz:8080/qux")
			},
			schemes: []string{"http"},
		},
		"invalid-scheme": {
			configValue: func(t *testing.T) types.String {
				return types.StringValue("https://foo.baz:8080/qux")
			},
			schemes:            []string{"http", "tcp"},
			expectedErrorCount: 1,
		},
		"invalid-url": {
			configValue: func(t *testing.T) types.String {
				return types.StringValue("foo.bar")
			},
			schemes:            []string{"http", "tcp"},
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

			cv := URIValidator(tc.schemes)

			// Act
			cv.ValidateString(context.Background(), req, &resp)

			// Assert
			if resp.Diagnostics.ErrorsCount() != tc.expectedErrorCount {
				t.Errorf("Expected %d errors, got %d: %s", tc.expectedErrorCount, resp.Diagnostics.ErrorsCount(), resp.Diagnostics.Errors())
			}
		})
	}
}
