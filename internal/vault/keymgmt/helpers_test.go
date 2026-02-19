// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package keymgmt

import (
	"strings"
	"testing"
)

func TestParseKeyPath(t *testing.T) {
	tests := []struct {
		name          string
		apiPath       string
		wantMount     string
		wantKeyName   string
		wantErr       bool
		errorContains string
	}{
		{
			name:        "valid key path",
			apiPath:     "keymgmt/key/mykey",
			wantMount:   "keymgmt",
			wantKeyName: "mykey",
			wantErr:     false,
		},
		{
			name:        "valid key path with nested mount",
			apiPath:     "nested/mount/path/key/mykey",
			wantMount:   "nested/mount/path",
			wantKeyName: "mykey",
			wantErr:     false,
		},
		{
			name:        "valid key path with leading slash",
			apiPath:     "/keymgmt/key/mykey",
			wantMount:   "keymgmt",
			wantKeyName: "mykey",
			wantErr:     false,
		},
		{
			name:        "valid key path with trailing slash",
			apiPath:     "keymgmt/key/mykey/",
			wantMount:   "keymgmt",
			wantKeyName: "mykey",
			wantErr:     false,
		},
		{
			name:          "invalid: path with /key/ but no key name (Comment 3 scenario)",
			apiPath:       "/kms/key/",
			wantMount:     "",
			wantKeyName:   "",
			wantErr:       true,
			errorContains: "invalid key path structure",
		},
		{
			name:          "invalid: path with /key/ but no key name - no slashes",
			apiPath:       "keymgmt/key/",
			wantMount:     "",
			wantKeyName:   "",
			wantErr:       true,
			errorContains: "invalid key path structure",
		},
		{
			name:          "invalid: missing key segment",
			apiPath:       "keymgmt/mykey",
			wantMount:     "",
			wantKeyName:   "",
			wantErr:       true,
			errorContains: "invalid key path structure",
		},
		{
			name:          "invalid: empty path",
			apiPath:       "",
			wantMount:     "",
			wantKeyName:   "",
			wantErr:       true,
			errorContains: "invalid key path structure",
		},
		{
			name:          "invalid: only /key/",
			apiPath:       "/key/",
			wantMount:     "",
			wantKeyName:   "",
			wantErr:       true,
			errorContains: "invalid key path structure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMount, gotKeyName, err := parseKeyPath(tt.apiPath)

			if !checkParseError(t, "parseKeyPath()", err, tt.wantErr, tt.errorContains) {
				return
			}

			if gotMount != tt.wantMount {
				t.Errorf("parseKeyPath() gotMount = %q, want %q", gotMount, tt.wantMount)
			}
			if gotKeyName != tt.wantKeyName {
				t.Errorf("parseKeyPath() gotKeyName = %q, want %q", gotKeyName, tt.wantKeyName)
			}
		})
	}
}

func TestParseKMSPath(t *testing.T) {
	tests := []struct {
		name          string
		apiPath       string
		wantMount     string
		wantKMSName   string
		wantErr       bool
		errorContains string
	}{
		{
			name:        "valid KMS path",
			apiPath:     "keymgmt/kms/mykms",
			wantMount:   "keymgmt",
			wantKMSName: "mykms",
			wantErr:     false,
		},
		{
			name:        "valid KMS path with nested mount",
			apiPath:     "nested/mount/path/kms/mykms",
			wantMount:   "nested/mount/path",
			wantKMSName: "mykms",
			wantErr:     false,
		},
		{
			name:        "valid KMS path with leading slash",
			apiPath:     "/keymgmt/kms/mykms",
			wantMount:   "keymgmt",
			wantKMSName: "mykms",
			wantErr:     false,
		},
		{
			name:        "valid KMS path with trailing slash",
			apiPath:     "keymgmt/kms/mykms/",
			wantMount:   "keymgmt",
			wantKMSName: "mykms",
			wantErr:     false,
		},
		{
			name:          "invalid: path with /kms/ but no KMS name",
			apiPath:       "/keymgmt/kms/",
			wantMount:     "",
			wantKMSName:   "",
			wantErr:       true,
			errorContains: "invalid KMS path structure",
		},
		{
			name:          "invalid: missing kms segment",
			apiPath:       "keymgmt/mykms",
			wantMount:     "",
			wantKMSName:   "",
			wantErr:       true,
			errorContains: "invalid KMS path structure",
		},
		{
			name:          "invalid: empty path",
			apiPath:       "",
			wantMount:     "",
			wantKMSName:   "",
			wantErr:       true,
			errorContains: "invalid KMS path structure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMount, gotKMSName, err := parseKMSPath(tt.apiPath)

			if !checkParseError(t, "parseKMSPath()", err, tt.wantErr, tt.errorContains) {
				return
			}

			if gotMount != tt.wantMount {
				t.Errorf("parseKMSPath() gotMount = %q, want %q", gotMount, tt.wantMount)
			}
			if gotKMSName != tt.wantKMSName {
				t.Errorf("parseKMSPath() gotKMSName = %q, want %q", gotKMSName, tt.wantKMSName)
			}
		})
	}
}

func TestParseDistributeKeyPath(t *testing.T) {
	tests := []struct {
		name          string
		apiPath       string
		wantMount     string
		wantKMSName   string
		wantKeyName   string
		wantErr       bool
		errorContains string
	}{
		{
			name:        "valid distribution path",
			apiPath:     "keymgmt/kms/mykms/key/mykey",
			wantMount:   "keymgmt",
			wantKMSName: "mykms",
			wantKeyName: "mykey",
			wantErr:     false,
		},
		{
			name:        "valid distribution path with nested mount",
			apiPath:     "nested/mount/path/kms/mykms/key/mykey",
			wantMount:   "nested/mount/path",
			wantKMSName: "mykms",
			wantKeyName: "mykey",
			wantErr:     false,
		},
		{
			name:        "valid distribution path with leading slash",
			apiPath:     "/keymgmt/kms/mykms/key/mykey",
			wantMount:   "keymgmt",
			wantKMSName: "mykms",
			wantKeyName: "mykey",
			wantErr:     false,
		},
		{
			name:        "valid distribution path with trailing slash",
			apiPath:     "keymgmt/kms/mykms/key/mykey/",
			wantMount:   "keymgmt",
			wantKMSName: "mykms",
			wantKeyName: "mykey",
			wantErr:     false,
		},
		{
			name:          "invalid: missing key name",
			apiPath:       "/keymgmt/kms/mykms/key/",
			wantMount:     "",
			wantKMSName:   "",
			wantKeyName:   "",
			wantErr:       true,
			errorContains: "invalid key distribution path structure",
		},
		{
			name:          "invalid: missing kms segment",
			apiPath:       "keymgmt/key/mykey",
			wantMount:     "",
			wantKMSName:   "",
			wantKeyName:   "",
			wantErr:       true,
			errorContains: "invalid key distribution path structure",
		},
		{
			name:          "invalid: empty path",
			apiPath:       "",
			wantMount:     "",
			wantKMSName:   "",
			wantKeyName:   "",
			wantErr:       true,
			errorContains: "invalid key distribution path structure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMount, gotKMSName, gotKeyName, err := parseDistributeKeyPath(tt.apiPath)

			if !checkParseError(t, "parseDistributeKeyPath()", err, tt.wantErr, tt.errorContains) {
				return
			}

			if gotMount != tt.wantMount {
				t.Errorf("parseDistributeKeyPath() gotMount = %q, want %q", gotMount, tt.wantMount)
			}
			if gotKMSName != tt.wantKMSName {
				t.Errorf("parseDistributeKeyPath() gotKMSName = %q, want %q", gotKMSName, tt.wantKMSName)
			}
			if gotKeyName != tt.wantKeyName {
				t.Errorf("parseDistributeKeyPath() gotKeyName = %q, want %q", gotKeyName, tt.wantKeyName)
			}
		})
	}
}

// checkParseError is a helper function to validate error cases in parse functions
func checkParseError(t *testing.T, funcName string, err error, wantErr bool, errorContains string) bool {
	t.Helper()
	if wantErr {
		if err == nil {
			t.Errorf("%s expected error but got none", funcName)
			return false
		}
		if errorContains != "" && !strings.Contains(err.Error(), errorContains) {
			t.Errorf("%s error = %v, want error containing %q", funcName, err, errorContains)
		}
		return false
	}
	if err != nil {
		t.Errorf("%s unexpected error = %v", funcName, err)
		return false
	}
	return true
}
