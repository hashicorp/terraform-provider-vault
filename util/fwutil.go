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

// CommaSeparatedStringToSet converts a comma-separated string to a Terraform Set of strings.
// This is useful when Vault API returns comma-separated strings but Terraform uses Set.
// Returns null Set if the input string is empty.
func CommaSeparatedStringToSet(ctx context.Context, s string) (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics

	if s == "" {
		return types.SetNull(types.StringType), diags
	}

	elements := strings.Split(s, ",")
	// Trim whitespace from each element
	for i, e := range elements {
		elements[i] = strings.TrimSpace(e)
	}

	set, setDiags := types.SetValueFrom(ctx, types.StringType, elements)
	diags.Append(setDiags...)
	return set, diags
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

// SetToStringSlice converts a Terraform Set of strings to a slice of strings.
// Returns nil if the set is null or unknown.
func SetToStringSlice(ctx context.Context, set types.Set) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics

	if set.IsNull() || set.IsUnknown() {
		return nil, diags
	}

	var elements []string
	diags.Append(set.ElementsAs(ctx, &elements, false)...)
	return elements, diags
}
