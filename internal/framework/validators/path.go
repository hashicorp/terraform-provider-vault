// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

// Credentials Validator
var _ validator.String = pathValidator{}

// pathValidator  validates that a given path is a valid Vault path format
type pathValidator struct{}

// Description describes the validation in plain text formatting.
func (v pathValidator) Description(_ context.Context) string {
	return "value must be a valid Vault path format"
}

// MarkdownDescription describes the validation in Markdown formatting.
func (v pathValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateString performs the validation.
func (v pathValidator) ValidateString(ctx context.Context, request validator.StringRequest, response *validator.StringResponse) {
	if request.ConfigValue.IsNull() || request.ConfigValue.IsUnknown() {
		return
	}

	value := request.ConfigValue.ValueString()
	if value == "" {
		response.Diagnostics.AddError("invalid Vault path", "value cannot be empty")
		return
	}

	if provider.RegexpPath.MatchString(value) {
		response.Diagnostics.AddError("invalid Vault path", fmt.Sprintf("value %s contains leading/trailing \"/\"", value))
	}
}

func PathValidator() validator.String {
	return pathValidator{}
}
