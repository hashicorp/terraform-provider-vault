// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

var _ validator.String = uriValidator{}

// uriValidator validates that the raw url is a valid request URI, and
// optionally contains supported scheme(s).
type uriValidator struct {
	schemes []string
}

// Description describes the validation in plain text formatting.
func (v uriValidator) Description(_ context.Context) string {
	return "Invalid URI"
}

// MarkdownDescription describes the validation in Markdown formatting.
func (v uriValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateString performs the validation.
func (v uriValidator) ValidateString(ctx context.Context, request validator.StringRequest, response *validator.StringResponse) {
	if request.ConfigValue.IsNull() || request.ConfigValue.IsUnknown() {
		return
	}

	value := request.ConfigValue.ValueString()
	if value == "" {
		response.Diagnostics.AddError(v.Description(ctx), "value cannot be empty")
		return
	}

	u, err := url.ParseRequestURI(value)
	if err != nil {
		response.Diagnostics.AddError(v.Description(ctx), fmt.Sprintf("Failed to parse URL, err=%s", err))
		return
	}

	if len(v.schemes) == 0 {
		return
	}

	for _, scheme := range v.schemes {
		if scheme == u.Scheme {
			return
		}
	}

	response.Diagnostics.AddError(
		v.Description(ctx),
		fmt.Sprintf(
			"Unsupported scheme %q. Valid schemes are: %s",
			u.Scheme,
			strings.Join(v.schemes, ", "),
		),
	)
}

// URIValidator validates that the raw url is a valid request URI, and
// optionally contains supported scheme(s).
func URIValidator(schemes []string) validator.String {
	return uriValidator{
		schemes: schemes,
	}
}
