// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import "testing"

func TestAddPrefixToVKVPath(t *testing.T) {
	tests := map[string]struct {
		path      string
		mountPath string
		apiPrefix string
		want      string
	}{
		"mount only": {
			path:      "kvv2/",
			mountPath: "kvv2/",
			apiPrefix: "data",
			want:      "kvv2/data",
		},
		"mount only without trailing slash": {
			path:      "kvv2",
			mountPath: "kvv2/",
			apiPrefix: "data",
			want:      "kvv2/data",
		},
		"secret": {
			path:      "kvv2/foo",
			mountPath: "kvv2/",
			apiPrefix: "data",
			want:      "kvv2/data/foo",
		},
		"nested secret": {
			path:      "kvv2/a/b/c",
			mountPath: "kvv2/",
			apiPrefix: "data",
			want:      "kvv2/data/a/b/c",
		},
		"nested mount": {
			path:      "ns/kvv2/foo",
			mountPath: "ns/kvv2/",
			apiPrefix: "metadata",
			want:      "ns/kvv2/metadata/foo",
		},
		"explicit data prefix": {
			path:      "kvv2/data/foo",
			mountPath: "kvv2/",
			apiPrefix: "data",
			want:      "kvv2/data/foo",
		},
		"explicit metadata prefix": {
			path:      "kvv2/metadata/apps/example",
			mountPath: "kvv2/",
			apiPrefix: "data",
			want:      "kvv2/metadata/apps/example",
		},
		"explicit prefix with mount path without trailing slash": {
			path:      "kvv2/metadata/foo",
			mountPath: "kvv2",
			apiPrefix: "data",
			want:      "kvv2/metadata/foo",
		},
		"secret named data": {
			path:      "kvv2/data",
			mountPath: "kvv2/",
			apiPrefix: "data",
			want:      "kvv2/data/data",
		},
		"mount named data": {
			path:      "data/foo",
			mountPath: "data/",
			apiPrefix: "data",
			want:      "data/data/foo",
		},
		"prefix not directly under mount": {
			path:      "kvv2/foo/metadata/bar",
			mountPath: "kvv2/",
			apiPrefix: "data",
			want:      "kvv2/data/foo/metadata/bar",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := addPrefixToVKVPath(tc.path, tc.mountPath, tc.apiPrefix); got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}
