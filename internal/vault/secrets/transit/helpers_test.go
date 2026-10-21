// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"testing"
)

func TestParseTransitKeyID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		id      string
		want    parsedKeyID
		wantErr bool
	}{
		{
			name: "valid canonical path",
			id:   "transit/keys/my-key",
			want: parsedKeyID{Mount: "transit", Name: "my-key"},
		},
		{
			name: "valid shorthand path",
			id:   "transit/my-key",
			want: parsedKeyID{Mount: "transit", Name: "my-key"},
		},
		{
			name: "valid canonical nested mount",
			id:   "ns/sub/transit/keys/my-key",
			want: parsedKeyID{Mount: "ns/sub/transit", Name: "my-key"},
		},
		{
			name: "valid shorthand nested mount",
			id:   "ns/sub/transit/my-key",
			want: parsedKeyID{Mount: "ns/sub/transit", Name: "my-key"},
		},
		{
			name: "valid canonical with leading and trailing slashes",
			id:   "/transit/keys/my-key/",
			want: parsedKeyID{Mount: "transit", Name: "my-key"},
		},
		{
			name: "valid shorthand with leading and trailing slashes",
			id:   "/transit/my-key/",
			want: parsedKeyID{Mount: "transit", Name: "my-key"},
		},
		{
			name: "valid key with special characters",
			id:   "transit/keys/key_name-01.test",
			want: parsedKeyID{Mount: "transit", Name: "key_name-01.test"},
		},
		{
			name: "valid shorthand where key is named keys",
			id:   "transit/keys",
			want: parsedKeyID{Mount: "transit", Name: "keys"},
		},
		{
			name: "valid canonical where key is named keys",
			id:   "transit/keys/keys",
			want: parsedKeyID{Mount: "transit", Name: "keys"},
		},
		{
			name:    "incomplete canonical path ending in /keys/",
			id:      "transit/keys/",
			wantErr: true,
		},
		{
			name:    "incomplete canonical path with leading slash and trailing /keys/",
			id:      "/transit/keys/",
			wantErr: true,
		},
		{
			name:    "empty string",
			id:      "",
			wantErr: true,
		},
		{
			name:    "only mount without slash",
			id:      "transit",
			wantErr: true,
		},
		{
			name:    "slash only",
			id:      "/",
			wantErr: true,
		},
		{
			name:    "multiple slashes only",
			id:      "///",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseTransitKeyID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseTransitKeyID(%q) error = %v, wantErr %v", tt.id, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseTransitKeyID(%q) = %+v, want %+v", tt.id, got, tt.want)
			}
		})
	}
}

func TestParseTransitKeyVersionID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		id      string
		want    parsedKeyVersionID
		wantErr bool
	}{
		{
			name: "valid canonical path",
			id:   "transit/keys/my-key/version/1",
			want: parsedKeyVersionID{Mount: "transit", Name: "my-key", Version: 1},
		},
		{
			name: "valid shorthand path",
			id:   "transit/my-key/1",
			want: parsedKeyVersionID{Mount: "transit", Name: "my-key", Version: 1},
		},
		{
			name: "valid canonical multi-digit version",
			id:   "transit/keys/my-key/version/42",
			want: parsedKeyVersionID{Mount: "transit", Name: "my-key", Version: 42},
		},
		{
			name: "valid shorthand multi-digit version",
			id:   "transit/my-key/42",
			want: parsedKeyVersionID{Mount: "transit", Name: "my-key", Version: 42},
		},
		{
			name: "valid canonical nested mount",
			id:   "ns/sub/transit/keys/my-key/version/2",
			want: parsedKeyVersionID{Mount: "ns/sub/transit", Name: "my-key", Version: 2},
		},
		{
			name: "valid shorthand nested mount",
			id:   "ns/sub/transit/my-key/2",
			want: parsedKeyVersionID{Mount: "ns/sub/transit", Name: "my-key", Version: 2},
		},
		{
			name: "valid canonical with leading and trailing slashes",
			id:   "/transit/keys/my-key/version/3/",
			want: parsedKeyVersionID{Mount: "transit", Name: "my-key", Version: 3},
		},
		{
			name: "valid shorthand with leading and trailing slashes",
			id:   "/transit/my-key/3/",
			want: parsedKeyVersionID{Mount: "transit", Name: "my-key", Version: 3},
		},
		{
			name:    "empty string",
			id:      "",
			wantErr: true,
		},
		{
			name:    "missing version number in canonical format",
			id:      "transit/keys/my-key/version/",
			wantErr: true,
		},
		{
			name:    "non-numeric version in canonical format",
			id:      "transit/keys/my-key/version/abc",
			wantErr: true,
		},
		{
			name:    "non-numeric version in shorthand format",
			id:      "transit/my-key/abc",
			wantErr: true,
		},
		{
			name:    "unversioned key path",
			id:      "transit/keys/my-key",
			wantErr: true,
		},
		{
			name:    "only mount and version",
			id:      "transit/1",
			wantErr: true,
		},
		{
			name:    "slash only",
			id:      "/",
			wantErr: true,
		},
		{
			name:    "multiple slashes only",
			id:      "///",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseTransitKeyVersionID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseTransitKeyVersionID(%q) error = %v, wantErr %v", tt.id, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseTransitKeyVersionID(%q) = %+v, want %+v", tt.id, got, tt.want)
			}
		})
	}
}

func TestPathHelpers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		fn       func() string
		expected string
	}{
		{
			name:     "keyPath simple",
			fn:       func() string { return keyPath("transit", "my-key") },
			expected: "transit/keys/my-key",
		},
		{
			name:     "keyPath trimmed slashes",
			fn:       func() string { return keyPath("/transit/", "/my-key/") },
			expected: "transit/keys/my-key",
		},
		{
			name:     "importPath simple",
			fn:       func() string { return importPath("transit", "my-key") },
			expected: "transit/keys/my-key/import",
		},
		{
			name:     "importVersionPath simple",
			fn:       func() string { return importVersionPath("transit", "my-key") },
			expected: "transit/keys/my-key/import_version",
		},
		{
			name:     "configPath simple",
			fn:       func() string { return configPath("transit", "my-key") },
			expected: "transit/keys/my-key/config",
		},
		{
			name:     "wrappingKeyPath simple",
			fn:       func() string { return wrappingKeyPath("transit") },
			expected: "transit/wrapping_key",
		},
		{
			name:     "wrappingKeyPath trimmed slashes",
			fn:       func() string { return wrappingKeyPath("/transit/") },
			expected: "transit/wrapping_key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.fn(); got != tt.expected {
				t.Errorf("%s = %q, want %q", tt.name, got, tt.expected)
			}
		})
	}
}
