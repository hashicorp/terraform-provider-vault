// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const (
	// base64 encoded SPNEGO request token
	testNegTokenInit = "oIICqjCCAqagJzAlBgkqhkiG9xIBAgIGBSsFAQUCBgkqhkiC9xIBAgIGBisGAQUCBaKCAnkEggJ1YIICcQYJKoZIhvcSAQICAQBuggJgMIICXKADAgEFoQMCAQ6iBwMFAAAAAACjggFwYYIBbDCCAWigAwIBBaENGwtURVNULkdPS1JCNaIjMCGgAwIBA6EaMBgbBEhUVFAbEGhvc3QudGVzdC5nb2tyYjWjggErMIIBJ6ADAgESoQMCAQKiggEZBIIBFdS9iQq8RW9E4uei6BEb1nZ6vwMmbfzal8Ypry7ORQpa4fFF5KTRvCyEjmamxrMdl0CyawPNvSVwv88SbpCt9fXrzp4oP/UIbaR7EpsU/Aqr1NHfnB88crgMxhTfwoeDRQsse3dJZR9DK0eqov8VjABmt1fz+wDde09j1oJ2x2Nz7N0/GcZuvEOoHld/PCY7h4NW9X6NbE7M1Ye4FTjnA5LPfnP8Eqb3xTeolKe7VWbIOsTWl1eqMgpR2NaQAXrr+VKt0Yia38Mwew5s2Mm1fPhYn75SgArLZGHCVHPUn6ob3OuLzj9h2yP5zWoJ1a3OtBHhxFRrMLMzMeVw/WvFCqQDVX519IjnWXUOoDiqtkVGZ9m2T0GkgdIwgc+gAwIBEqKBxwSBxNZ7oq5M9dkXyqsdhjYFJJMg6QSCVjZi7ZJAilQ7atXt64+TdekGCiBUkd8IL9Kl/sk9+3b0EBK7YMriDwetu3ehqlbwUh824eoQ3J+3YpArJU3XZk0LzG91HyAD5BmQrxtDMNEEd7+tY4ufC3BKyAzEdzH47I2AF2K62IhLjekK2x2+f8ew/6/Tj7Xri2VHzuMNiYcygc5jrXAEKhNHixp8K93g8iOs5i27hOLQbxBw9CZfZuBUREkzXi/MTQruW/gcWZk="
	// base64 encoded response token
	testNegTokenResp = "oRQwEqADCgEAoQsGCSqGSIb3EgECAg=="
)

func TestFrameworkProvider_KRBNegTokenValidator(t *testing.T) {
	cases := map[string]struct {
		configValue        func(t *testing.T) types.String
		expectedErrorCount int
	}{
		"basic": {
			configValue: func(t *testing.T) types.String {
				return types.StringValue(testNegTokenInit)
			},
		},
		"error-b64-decoding": {
			configValue: func(t *testing.T) types.String {
				return types.StringValue("Negotiation foo")
			},
			expectedErrorCount: 1,
		},
		"error-unmarshal": {
			configValue: func(t *testing.T) types.String {
				return types.StringValue(base64.StdEncoding.EncodeToString([]byte(testNegTokenInit)))
			},
			expectedErrorCount: 1,
		},
		"error-not-init-token": {
			configValue: func(t *testing.T) types.String {
				return types.StringValue(testNegTokenResp)
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

			k := KRBNegTokenValidator()

			// Act
			k.ValidateString(context.Background(), req, &resp)

			// Assert
			if resp.Diagnostics.ErrorsCount() != tc.expectedErrorCount {
				t.Errorf("Expected %d errors, got %d", tc.expectedErrorCount, resp.Diagnostics.ErrorsCount())
			}
		})
	}
}
