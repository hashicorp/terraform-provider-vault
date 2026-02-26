// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package boolvalidator

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/helpers/validatordiag"
	"github.com/hashicorp/terraform-plugin-framework-validators/helpers/validatorfuncerr"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ validator.Bool = equalsValidator{}
var _ function.BoolParameterValidator = equalsValidator{}

type equalsValidator struct {
	value types.Bool
}

func (v equalsValidator) Description(ctx context.Context) string {
	return fmt.Sprintf("Value must be %q", v.value)
}

func (v equalsValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v equalsValidator) ValidateBool(ctx context.Context, req validator.BoolRequest, resp *validator.BoolResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	configValue := req.ConfigValue

	if !configValue.Equal(v.value) {
		resp.Diagnostics.Append(validatordiag.InvalidAttributeValueMatchDiagnostic(
			req.Path,
			v.Description(ctx),
			configValue.String(),
		))
	}
}

func (v equalsValidator) ValidateParameterBool(ctx context.Context, req function.BoolParameterValidatorRequest, resp *function.BoolParameterValidatorResponse) {
	if req.Value.IsNull() || req.Value.IsUnknown() {
		return
	}

	value := req.Value

	if !value.Equal(v.value) {
		resp.Error = validatorfuncerr.InvalidParameterValueMatchFuncError(
			req.ArgumentPosition,
			v.Description(ctx),
			value.String(),
		)
	}
}

// Equals returns an AttributeValidator which ensures that the configured boolean attribute or function parameter
// matches the given `value`. Null (unconfigured) and unknown (known after apply) values are skipped.
func Equals(value bool) equalsValidator {
	return equalsValidator{
		value: types.BoolValue(value),
	}
}
