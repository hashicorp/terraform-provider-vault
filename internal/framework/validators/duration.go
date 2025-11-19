// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// DurationValidator returns a validator that checks that a string is a valid
// duration string. See also provider.ValidateDuration.
func DurationValidator() validator.String {
	return durationValidator{}
}

var _ validator.String = durationValidator{}

// durationValidator validates that the raw url is a valid request URI, and
// optionally contains supported scheme(s).
type durationValidator struct {
	schemes []string
}

// Description describes the validation in plain text formatting.
func (v durationValidator) Description(_ context.Context) string {
	return "Invalid Duration string"
}

// MarkdownDescription describes the validation in Markdown formatting.
func (v durationValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateString performs the validation.
func (v durationValidator) ValidateString(ctx context.Context, request validator.StringRequest, response *validator.StringResponse) {
	if request.ConfigValue.IsNull() || request.ConfigValue.IsUnknown() {
		return
	}

	value := request.ConfigValue.ValueString()
	if _, err := time.ParseDuration(value); err != nil {
		response.Diagnostics.AddError(v.Description(ctx), fmt.Sprintf("Failed to parse value as a duration string, err=%s", err))
	}
}
