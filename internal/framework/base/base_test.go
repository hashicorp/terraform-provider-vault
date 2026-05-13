// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package base

import (
	"testing"
)

func TestParseImportID(t *testing.T) {
	tests := []struct {
		name          string
		id            string
		wantNamespace string
		wantName      string
	}{
		{
			name:          "no namespace",
			id:            "my-resource",
			wantNamespace: "",
			wantName:      "my-resource",
		},
		{
			name:          "single namespace",
			id:            "ns1/my-resource",
			wantNamespace: "ns1",
			wantName:      "my-resource",
		},
		{
			name:          "nested namespace",
			id:            "parent/child/my-resource",
			wantNamespace: "parent/child",
			wantName:      "my-resource",
		},
		{
			name:          "deeply nested namespace",
			id:            "org/team/env/my-resource",
			wantNamespace: "org/team/env",
			wantName:      "my-resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotNamespace, gotName := ParseImportID(tt.id)
			if gotNamespace != tt.wantNamespace {
				t.Errorf("ParseImportID(%q) namespace = %q, want %q", tt.id, gotNamespace, tt.wantNamespace)
			}
			if gotName != tt.wantName {
				t.Errorf("ParseImportID(%q) name = %q, want %q", tt.id, gotName, tt.wantName)
			}
		})
	}
}
