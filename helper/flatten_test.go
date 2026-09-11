// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package helper

import (
	"encoding/json"
	"testing"
)

func TestFlattenVaultDuration(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  string
	}{
		// Zero and nil inputs should return "" (unset), not "0s".
		{"nil", nil, ""},
		{"int zero", int(0), ""},
		{"int64 zero", int64(0), ""},
		{"json.Number zero", json.Number("0"), ""},

		// Non-zero values should be converted to short-form duration strings.
		{"int seconds", int(3600), "1h"},
		{"int64 seconds", int64(600), "10m"},
		{"json.Number seconds", json.Number("5400"), "1h30m"},
		{"json.Number minutes trimmed", json.Number("7200"), "2h"},

		// Unrecognized types return "".
		{"float64 unrecognized", float64(3600), ""},
		{"string unrecognized", "3600", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FlattenVaultDuration(tc.input)
			if got != tc.want {
				t.Errorf("FlattenVaultDuration(%v) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
