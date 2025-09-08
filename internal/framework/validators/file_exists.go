// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/mitchellh/go-homedir"
)

var _ validator.String = fileExists{}

// fileExists validates that a given token is a valid initialization token
type fileExists struct{}

// Description describes the validation in plain text formatting.
func (v fileExists) Description(_ context.Context) string {
	return "value must be a valid path to an existing file"
}

// MarkdownDescription describes the validation in Markdown formatting.
func (v fileExists) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateString performs the validation.
func (v fileExists) ValidateString(ctx context.Context, request validator.StringRequest, response *validator.StringResponse) {
	if request.ConfigValue.IsNull() || request.ConfigValue.IsUnknown() {
		return
	}

	value := request.ConfigValue.ValueString()
	if value == "" {
		response.Diagnostics.AddError("invalid file", "value cannot be empty")
		return
	}

	filename, err := homedir.Expand(value)
	if err != nil {
		response.Diagnostics.AddError("invalid file", err.Error())
		return
	}

	st, err := os.Stat(filename)
	if err != nil {
		response.Diagnostics.AddError("invalid file", fmt.Sprintf("failed to stat path %q, err=%s", filename, err))
		return
	}

	if st.IsDir() {
		response.Diagnostics.AddError("invalid file", fmt.Sprintf("path %q is not a file", filename))
		return
	}
}

func FileExistsValidator() validator.String {
	return fileExists{}
}
