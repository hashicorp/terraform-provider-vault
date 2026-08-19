// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package rotate

import "testing"

func TestRotateRootPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		backend string
		conn    string
		want    string
	}{
		{
			name:    "database with connection name",
			backend: "database",
			conn:    "postgres",
			want:    "database/rotate-root/postgres",
		},
		{
			name:    "aws config without name",
			backend: "aws/config",
			conn:    "",
			want:    "aws/config/rotate-root",
		},
		{
			name:    "gcp config without name",
			backend: "gcp/config",
			conn:    "",
			want:    "gcp/config/rotate-root",
		},
		{
			name:    "azure without name",
			backend: "azure",
			conn:    "",
			want:    "azure/rotate-root",
		},
		{
			name:    "ad without name",
			backend: "ad",
			conn:    "",
			want:    "ad/rotate-root",
		},
		{
			name:    "ldap without name",
			backend: "ldap",
			conn:    "",
			want:    "ldap/rotate-root",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := rotateRootPath(tt.backend, tt.conn)
			if got != tt.want {
				t.Errorf("rotateRootPath(%q, %q) = %q, want %q", tt.backend, tt.conn, got, tt.want)
			}
		})
	}
}
