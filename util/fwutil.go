// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package util

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// SetToCommaSeparatedString converts a Terraform Set of strings to a comma-separated string.
// This is useful when Vault API accepts comma-separated strings but Terraform uses Set.
// Returns empty string if the set is null or unknown.
func SetToCommaSeparatedString(ctx context.Context, set types.Set) (string, diag.Diagnostics) {
	var diags diag.Diagnostics

	if set.IsNull() || set.IsUnknown() {
		return "", diags
	}

	var elements []string
	diags.Append(set.ElementsAs(ctx, &elements, false)...)
	if diags.HasError() {
		return "", diags
	}

	return strings.Join(elements, ","), diags
}

// StringSliceToSet converts a slice of strings to a Terraform Set of strings.
// Returns null Set if the slice is nil or empty.
func StringSliceToSet(ctx context.Context, slice []string) (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics

	if len(slice) == 0 {
		return types.SetNull(types.StringType), diags
	}

	set, setDiags := types.SetValueFrom(ctx, types.StringType, slice)
	diags.Append(setDiags...)
	return set, diags
}
