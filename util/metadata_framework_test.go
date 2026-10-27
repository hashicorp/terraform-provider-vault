// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package util

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFrameworkMetadataFromRead verifies how a metadata value read from Vault
// maps to Plugin Framework state. Vault omits metadata when no record exists
// and returns {} after a clear; both must read back as null so a config that
// omits the attribute stays clean, except that a configured {} is kept so it
// does not diff against the read value.
func TestFrameworkMetadataFromRead(t *testing.T) {
	t.Parallel()

	empty := types.MapValueMust(types.StringType, map[string]attr.Value{})
	owner := types.MapValueMust(types.StringType, map[string]attr.Value{"owner": types.StringValue("a")})
	null := types.MapNull(types.StringType)

	tests := []struct {
		name  string
		prior types.Map
		raw   interface{}
		want  types.Map
	}{
		{name: "non-empty record", prior: null, raw: map[string]interface{}{"owner": "a"}, want: owner},
		{name: "non-empty record replaces prior", prior: empty, raw: map[string]interface{}{"owner": "a"}, want: owner},
		{name: "no record, null prior", prior: null, raw: nil, want: null},
		{name: "no record, non-empty prior is dropped", prior: owner, raw: nil, want: null},
		{name: "no record, empty prior is kept", prior: empty, raw: nil, want: empty},
		{name: "cleared record, null prior", prior: null, raw: map[string]interface{}{}, want: null},
		{name: "cleared record, empty prior is kept", prior: empty, raw: map[string]interface{}{}, want: empty},
		{name: "cleared record, non-empty prior is dropped", prior: owner, raw: map[string]interface{}{}, want: null},
		{name: "no record, unknown prior", prior: types.MapUnknown(types.StringType), raw: nil, want: null},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, diags := FrameworkMetadataFromRead(context.Background(), tt.prior, tt.raw)
			require.False(t, diags.HasError())
			assert.True(t, tt.want.Equal(got), "want %s, got %s", tt.want, got)
		})
	}
}
