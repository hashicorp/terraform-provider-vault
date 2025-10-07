// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package helpers

import (
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"testing"
)

// SkipIfAPIVersionLT skips of the running vault version is less-than ver.
func SkipIfAPIVersionLT(t *testing.T, m interface{}, ver *version.Version) {
	t.Helper()
	f := func(curVer *version.Version) bool {
		return curVer.LessThan(ver)
	}
	SkipOnAPIVersion(t, m, f, "Vault version < %q", ver)
}

// SkipIfAPIVersionLTE skips if the running vault version is less-than-or-equal to ver.
func SkipIfAPIVersionLTE(t *testing.T, m interface{}, ver *version.Version) {
	t.Helper()
	f := func(curVer *version.Version) bool {
		return curVer.LessThanOrEqual(ver)
	}
	SkipOnAPIVersion(t, m, f, "Vault version <= %q", ver)
}

// SkipIfAPIVersionEQ skips if the running vault version is equal to ver.
func SkipIfAPIVersionEQ(t *testing.T, m interface{}, ver *version.Version) {
	t.Helper()
	f := func(curVer *version.Version) bool {
		return curVer.Equal(ver)
	}
	SkipOnAPIVersion(t, m, f, "Vault version == %q", ver)
}

// SkipIfAPIVersionGT skips if the running vault version is greater-than ver.
func SkipIfAPIVersionGT(t *testing.T, m interface{}, ver *version.Version) {
	t.Helper()
	f := func(curVer *version.Version) bool {
		return curVer.GreaterThan(ver)
	}
	SkipOnAPIVersion(t, m, f, "Vault version > %q", ver)
}

// SkipIfAPIVersionGTE skips if the running vault version is greater-than-or-equal to ver.
func SkipIfAPIVersionGTE(t *testing.T, m interface{}, ver *version.Version) {
	t.Helper()
	f := func(curVer *version.Version) bool {
		return curVer.GreaterThanOrEqual(ver)
	}
	SkipOnAPIVersion(t, m, f, "Vault version >= %q", ver)
}

func SkipOnAPIVersion(t *testing.T, m interface{}, cmp func(*version.Version) bool, format string, args ...interface{}) {
	t.Helper()

	p := m.(*provider.ProviderMeta)
	curVer := p.GetVaultVersion()
	if curVer == nil {
		t.Fatalf("vault version not set on %T", p)
	}

	t.Logf("Vault server version %q", curVer)
	if cmp(curVer) {
		t.Skipf(format, args...)
	}
}
