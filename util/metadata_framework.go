// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package util

import (
	"context"

	fwdiag "github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// FrameworkMetadataFromRead returns the metadata value to store in Plugin
// Framework state after reading an object. Vault omits metadata when no record
// exists and returns an empty map after a clear. Both mean "no metadata", so
// they map to null, which is what an omitted attribute plans as. The one
// exception is a prior value of {}, which is kept so that a configured {} does
// not produce a diff.
func FrameworkMetadataFromRead(ctx context.Context, prior types.Map, raw interface{}) (types.Map, fwdiag.Diagnostics) {
	if m, ok := raw.(map[string]interface{}); ok && len(m) > 0 {
		return types.MapValueFrom(ctx, types.StringType, m)
	}
	if !prior.IsNull() && !prior.IsUnknown() && len(prior.Elements()) == 0 {
		return prior, nil
	}
	return types.MapNull(types.StringType), nil
}
