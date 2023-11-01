// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func TestAuthLoginGeneric_Namespace(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]interface{}
		want   string
		exists bool
	}{
		{
			name: "root-ns",
			params: map[string]interface{}{
				consts.FieldUseRootNamespace: true,
			},
			want:   "",
			exists: true,
		},
		{
			name: "other-ns",
			params: map[string]interface{}{
				consts.FieldNamespace: "ns1",
			},
			want:   "ns1",
			exists: true,
		},
		{
			name: "empty-ns",
			params: map[string]interface{}{
				consts.FieldNamespace: "",
			},
			want:   "",
			exists: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &AuthLoginGeneric{
				AuthLoginCommon: AuthLoginCommon{
					params:      tt.params,
					initialized: true,
				},
			}
			got, exists := l.Namespace()
			if got != tt.want {
				t.Errorf("Namespace() got = %v, want %v", got, tt.want)
			}
			if exists != tt.exists {
				t.Errorf("Namespace() exists = %v, want %v", exists, tt.exists)
			}
		})
	}
}
