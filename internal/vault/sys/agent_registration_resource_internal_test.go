// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"testing"
)

func TestImportIDIsUUID(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want bool
	}{
		{
			name: "lowercase uuid",
			id:   "550e8400-e29b-41d4-a716-446655440000",
			want: true,
		},
		{
			name: "uppercase uuid",
			id:   "550E8400-E29B-41D4-A716-446655440000",
			want: true,
		},
		{
			name: "display_name",
			id:   "my-agent",
			want: false,
		},
		{
			name: "display_name with slashes",
			id:   "team/app/my-agent",
			want: false,
		},
		{
			name: "uuid-like but wrong length",
			id:   "550e8400-e29b-41d4-a716-44665544",
			want: false,
		},
		{
			name: "empty",
			id:   "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := importIDIsUUID(tt.id); got != tt.want {
				t.Errorf("importIDIsUUID(%q) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}
