// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

var _ validator.String = krbNegToken{}

// krbNegToken validates that a given token is a valid initialization token
type krbNegToken struct{}

// Description describes the validation in plain text formatting.
func (v krbNegToken) Description(_ context.Context) string {
	return "value must be a valid initialization token"
}

// MarkdownDescription describes the validation in Markdown formatting.
func (v krbNegToken) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateString performs the validation.
func (v krbNegToken) ValidateString(ctx context.Context, request validator.StringRequest, response *validator.StringResponse) {
	if request.ConfigValue.IsNull() || request.ConfigValue.IsUnknown() {
		return
	}

	value := request.ConfigValue.ValueString()
	if value == "" {
		response.Diagnostics.AddError("invalid token", "value cannot be empty")
		return
	}

	b, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		response.Diagnostics.AddError("invalid token", "value cannot be empty")
		return
	}

	isNeg, _, err := spnego.UnmarshalNegToken(b)
	if err != nil {
		response.Diagnostics.AddError("invalid token", fmt.Sprintf("failed to unmarshal token, err=%s", err))
		return
	}

	if !isNeg {
		response.Diagnostics.AddError("invalid token", "not an initialization token")
		return
	}
}

func KRBNegTokenValidator() validator.String {
	return krbNegToken{}
}
