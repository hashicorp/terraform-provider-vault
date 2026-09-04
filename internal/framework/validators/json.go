// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

var _ validator.String = jsonObjectValidator{}

// jsonObjectValidator validates that a string is a JSON object, so that it can
// be unmarshalled into a map and sent to Vault as a request body.
type jsonObjectValidator struct{}

// Description describes the validation in plain text formatting.
func (v jsonObjectValidator) Description(_ context.Context) string {
	return "value must be a JSON object"
}

// MarkdownDescription describes the validation in Markdown formatting.
func (v jsonObjectValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateString performs the validation.
func (v jsonObjectValidator) ValidateString(ctx context.Context, request validator.StringRequest, response *validator.StringResponse) {
	if request.ConfigValue.IsNull() || request.ConfigValue.IsUnknown() {
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(request.ConfigValue.ValueString()), &data); err != nil {
		response.Diagnostics.AddError(v.Description(ctx), fmt.Sprintf("Failed to parse value as a JSON object, err=%s", err))
	}
}

// JSONObjectValidator returns a validator that checks that a string is a valid
// JSON object.
func JSONObjectValidator() validator.String {
	return jsonObjectValidator{}
}
