// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package transform

import (
	"testing"
)

func TestParseTransformationID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		id      string
		want    parsedTransformationID
		wantErr bool
	}{
		{
			name: "valid canonical path",
			id:   "transform/transformation/my-tf",
			want: parsedTransformationID{Mount: "transform", Name: "my-tf"},
		},
		{
			name: "valid shorthand path",
			id:   "transform/my-tf",
			want: parsedTransformationID{Mount: "transform", Name: "my-tf"},
		},
		{
			name: "valid canonical nested mount",
			id:   "ns/sub/transform/transformation/my-tf",
			want: parsedTransformationID{Mount: "ns/sub/transform", Name: "my-tf"},
		},
		{
			name: "valid shorthand nested mount",
			id:   "ns/sub/transform/my-tf",
			want: parsedTransformationID{Mount: "ns/sub/transform", Name: "my-tf"},
		},
		{
			name: "valid canonical with leading and trailing slashes",
			id:   "/transform/transformation/my-tf/",
			want: parsedTransformationID{Mount: "transform", Name: "my-tf"},
		},
		{
			name: "valid shorthand with leading and trailing slashes",
			id:   "/transform/my-tf/",
			want: parsedTransformationID{Mount: "transform", Name: "my-tf"},
		},
		{
			name: "valid shorthand where transformation is named transformation",
			id:   "transform/transformation",
			want: parsedTransformationID{Mount: "transform", Name: "transformation"},
		},
		{
			name: "valid canonical where transformation is named transformation",
			id:   "transform/transformation/transformation",
			want: parsedTransformationID{Mount: "transform", Name: "transformation"},
		},
		{
			name:    "incomplete canonical path ending in /transformation/",
			id:      "transform/transformation/",
			wantErr: true,
		},
		{
			name:    "empty string",
			id:      "",
			wantErr: true,
		},
		{
			name:    "only mount without slash",
			id:      "transform",
			wantErr: true,
		},
		{
			name:    "slash only",
			id:      "/",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseTransformationID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseTransformationID(%q) error = %v, wantErr %v", tt.id, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseTransformationID(%q) = %+v, want %+v", tt.id, got, tt.want)
			}
		})
	}
}

func TestPathHelpers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		got      string
		expected string
	}{
		{"readPath", readPath("transform", "my-tf"), "transform/transformation/my-tf"},
		{"readPath trimmed slashes", readPath("/transform/", "/my-tf/"), "transform/transformation/my-tf"},
		{"typedPath tokenization", typedPath("transform", typeTokenization, "my-tf"), "transform/transformations/tokenization/my-tf"},
		{"typedPath fpe", typedPath("transform", typeFPE, "my-tf"), "transform/transformations/fpe/my-tf"},
		{"importPath", importPath("transform", typeFPE, "my-tf"), "transform/transformations/fpe/my-tf/import"},
		{"importVersionPath", importVersionPath("transform", typeTokenization, "my-tf"), "transform/transformations/tokenization/my-tf/import_version"},
		{"tokenizationKeyPath", tokenizationKeyPath("/transform/", "my-tf"), "transform/tokenization/keys/my-tf"},
		{"keyConfigPath", keyConfigPath("transform", "my-tf"), "transform/tokenization/keys/my-tf/config"},
		{"wrappingKeyPath", wrappingKeyPath("transform"), "transform/wrapping_key"},
		{"wrappingKeyPath trimmed slashes", wrappingKeyPath("/transform/"), "transform/wrapping_key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.got != tt.expected {
				t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.expected)
			}
		})
	}
}
