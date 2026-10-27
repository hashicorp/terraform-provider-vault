// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package util

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMetadataWriteDiags verifies that Vault warnings are surfaced as Terraform
// warnings only when the write request carried metadata, so that a failed
// metadata write after a successful object write is visible to the user while
// unrelated plugin warnings stay unchanged.
func TestMetadataWriteDiags(t *testing.T) {
	t.Parallel()

	warned := &api.Secret{Warnings: []string{"metadata write failed"}}

	tests := []struct {
		name     string
		resp     *api.Secret
		data     map[string]interface{}
		wantWarn []string
	}{
		{
			name:     "warning with metadata in request",
			resp:     warned,
			data:     map[string]interface{}{"metadata": map[string]interface{}{"owner": "a"}},
			wantWarn: []string{"metadata write failed"},
		},
		{
			name:     "warning with empty metadata in request",
			resp:     warned,
			data:     map[string]interface{}{"metadata": map[string]interface{}{}},
			wantWarn: []string{"metadata write failed"},
		},
		{
			name: "warning without metadata in request",
			resp: warned,
			data: map[string]interface{}{"name": "r"},
		},
		{
			name: "nil response",
			resp: nil,
			data: map[string]interface{}{"metadata": map[string]interface{}{"owner": "a"}},
		},
		{
			name: "no warnings",
			resp: &api.Secret{},
			data: map[string]interface{}{"metadata": map[string]interface{}{"owner": "a"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			diags := MetadataWriteDiags(tt.resp, tt.data)
			require.Len(t, diags, len(tt.wantWarn))
			for i, w := range tt.wantWarn {
				assert.Equal(t, diag.Warning, diags[i].Severity)
				assert.Equal(t, w, diags[i].Detail)
			}
			assert.False(t, diags.HasError())

			fwDiags := MetadataWriteFrameworkDiags(tt.resp, tt.data)
			require.Len(t, fwDiags, len(tt.wantWarn))
			for i, w := range tt.wantWarn {
				assert.Equal(t, w, fwDiags.Warnings()[i].Detail())
			}
			assert.False(t, fwDiags.HasError())
		})
	}
}
