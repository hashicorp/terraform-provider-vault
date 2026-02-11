// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package acctestutil

import (
	"testing"

	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

type CompareVaultVersionFunc func(*version.Version) bool

// SkipIfAPIVersionLT skips of the running vault version is less-than ver.
func SkipIfAPIVersionLT(t *testing.T, ver *version.Version) {
	t.Helper()
	SkipIfAPIVersion(t, func(curVer *version.Version) bool {
		return curVer.LessThan(ver)
	}, "Vault version < %q", ver)
}

// SkipIfAPIVersionLTE skips if the running vault version is less-than-or-equal to ver.
func SkipIfAPIVersionLTE(t *testing.T, ver *version.Version) {
	t.Helper()
	SkipIfAPIVersion(t, func(curVer *version.Version) bool {
		return curVer.LessThanOrEqual(ver)
	}, "Vault version <= %q", ver)
}

// SkipIfAPIVersionEQ skips if the running vault version is equal to ver.
func SkipIfAPIVersionEQ(t *testing.T, ver *version.Version) {
	t.Helper()
	f := func(curVer *version.Version) bool {
		return curVer.Equal(ver)
	}
	SkipIfAPIVersion(t, f, "Vault version == %q", ver)
}

// SkipIfAPIVersionGT skips if the running vault version is greater-than ver.
func SkipIfAPIVersionGT(t *testing.T, ver *version.Version) {
	t.Helper()
	f := func(curVer *version.Version) bool {
		return curVer.GreaterThan(ver)
	}
	SkipIfAPIVersion(t, f, "Vault version > %q", ver)
}

// SkipIfAPIVersionGTE skips if the running vault version is greater-than-or-equal to ver.
func SkipIfAPIVersionGTE(t *testing.T, ver *version.Version) {
	t.Helper()
	f := func(curVer *version.Version) bool {
		return curVer.GreaterThanOrEqual(ver)
	}
	SkipIfAPIVersion(t, f, "Vault version >= %q", ver)
}

func SkipIfAPIVersion(t *testing.T, cmp CompareVaultVersionFunc, format string, args ...interface{}) {
	t.Helper()

	if TestProvider == nil {
		t.Fatalf("Provider is nil")
	}

	pm, ok := TestProvider.Meta().(*provider.ProviderMeta)
	if !ok {
		t.Fatalf("expected provider meta to be of type *provider.ProviderMeta, got %T", TestProvider.Meta())
	}

	curVersion := pm.GetVaultVersion()
	if curVersion == nil {
		t.Fatalf("vault version not set on %T", pm)
	}

	t.Logf("Vault server version %q", curVersion)
	if cmp(curVersion) {
		t.Skipf(format, args...)
	}
}
