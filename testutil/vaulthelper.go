package testutil

import (
	"testing"

	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

type CompareVaultVersionFunc func(*version.Version) bool

// SkipIfVaultVersionLT skips of the running vault version is less-than ver.
func SkipIfVaultVersionLT(t *testing.T, ver *version.Version) {
	t.Helper()
	SkipIfVaultVersion(t, func(curVer *version.Version) bool {
		return curVer.LessThan(ver)
	}, "Vault version < %q", ver)
}

// SkipIfVaultVersionLTE skips if the running vault version is less-than-or-equal to ver.
func SkipIfVaultVersionLTE(t *testing.T, ver *version.Version) {
	t.Helper()
	SkipIfVaultVersion(t, func(curVer *version.Version) bool {
		return curVer.LessThanOrEqual(ver)
	}, "Vault version <= %q", ver)
}

// SkipIfVaultVersionEQ skips if the running vault version is equal to ver.
func SkipIfVaultVersionEQ(t *testing.T, ver *version.Version) {
	t.Helper()
	f := func(curVer *version.Version) bool {
		return curVer.Equal(ver)
	}
	SkipIfVaultVersion(t, f, "Vault version == %q", ver)
}

// SkipIfVaultVersionGT skips if the running vault version is greater-than ver.
func SkipIfVaultVersionGT(t *testing.T, ver *version.Version) {
	t.Helper()
	f := func(curVer *version.Version) bool {
		return curVer.GreaterThan(ver)
	}
	SkipIfVaultVersion(t, f, "Vault version > %q", ver)
}

// SkipIfVaultVersionGTE skips if the running vault version is greater-than-or-equal to ver.
func SkipIfVaultVersionGTE(t *testing.T, ver *version.Version) {
	t.Helper()
	f := func(curVer *version.Version) bool {
		return curVer.GreaterThanOrEqual(ver)
	}
	SkipIfVaultVersion(t, f, "Vault version >= %q", ver)
}

func SkipIfVaultVersion(t *testing.T, cmp CompareVaultVersionFunc, format string, args ...interface{}) {
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
