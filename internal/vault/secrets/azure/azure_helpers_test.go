// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package azure

import "testing"

// Test_normalizeTTL tests the normalizeTTL function with various input types.
// The function should correctly parse and convert the input to an int64 representing seconds.
func Test_normalizeTTL(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		want    int64
		wantErr bool
	}{
		{"nil", nil, 0, false},
		{"float64", float64(3600), 3600, false},
		{"duration string", "2h", 7200, false},
		{"numeric string", "31536000", 31536000, false},
		{"int", 1800, 1800, false},
		{"bad string", "not-a-duration", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeTTL(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %d, want %d", got, tt.want)
			}
		})
	}
}
