// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package transform_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	vaultclient "github.com/hashicorp/vault/api"
)

// builtinTemplate is a template that ships with every Transform mount, so FPE tests don't need
// to create one.
const builtinTemplate = "builtin/creditcardnumber"

// importedKeyFields holds the arguments rendered by importedKeyConfig. Zero values are omitted
// from the configuration so tests only set what they exercise.
type importedKeyFields struct {
	mount               string
	name                string
	ciphertext          string
	ciphertextWOVersion int64
	hashFunction        string
	allowRotation       bool
	deletionAllowed     bool
	allowedRoles        string // e.g. `["role-a", "role-b"]`

	// tokenization
	mappingMode          string
	maxTTL               *int64
	stores               string // e.g. `["builtin/internal"]`
	minDecryptionVersion int64
	autoRotatePeriod     *int64

	// fpe
	template    string
	tweakSource string
	maxTweakLen *int64
}

func int64Ptr(v int64) *int64 {
	return &v
}

// mountTransformWithWrappingKey mounts Transform and returns the mount's public wrapping key,
// which is used to build wrapped ciphertexts for the BYOK tests. The mount is removed when the
// test finishes.
func mountTransformWithWrappingKey(t *testing.T, mount string) string {
	t.Helper()

	cli := acctestutil.TestProvider.Meta().(*provider.ProviderMeta).MustGetClient()
	if err := cli.Sys().Mount(mount, &vaultclient.MountInput{Type: "transform"}); err != nil {
		t.Fatalf("failed to mount transform: %v", err)
	}
	t.Cleanup(func() { cli.Sys().Unmount(mount) })

	secret, err := cli.Logical().Read(mount + "/wrapping_key")
	if err != nil || secret == nil {
		t.Fatalf("failed to read wrapping key: %v", err)
	}
	wrappingKey, ok := secret.Data["public_key"].(string)
	if !ok {
		t.Fatalf("failed to extract public key from wrapping key endpoint")
	}
	return wrappingKey
}

// importTransformationVaultSetup imports a transformation into an existing Transform mount
// through the Vault API. This is how a user's pre-existing imported transformation would have been
// created before Terraform supported BYOK, so tests can exercise adopting it with terraform import.
// deletion_allowed is enabled so the transformation can be destroyed at the end of the test.
func importTransformationVaultSetup(t *testing.T, mount, transformationType, name string, importBody map[string]any) {
	t.Helper()

	cli := acctestutil.TestProvider.Meta().(*provider.ProviderMeta).MustGetClient()
	base := mount + "/transformations/" + transformationType + "/" + name
	if _, err := cli.Logical().Write(base+"/import", importBody); err != nil {
		t.Fatalf("failed to import transformation outside Terraform: %v", err)
	}
	if _, err := cli.Logical().Write(base, map[string]any{"deletion_allowed": true}); err != nil {
		t.Fatalf("failed to enable deletion_allowed: %v", err)
	}
}

// importedKeyConfig renders the resource config. The mount is referenced by literal path because
// every test mounts Transform itself to read the wrapping key before the config runs.
func importedKeyConfig(transformationType string, f importedKeyFields) string {
	var optionalArgs string

	if f.ciphertext != "" {
		optionalArgs += fmt.Sprintf("  ciphertext_wo = %q\n", f.ciphertext)
		optionalArgs += fmt.Sprintf("  ciphertext_wo_version = %d\n", f.ciphertextWOVersion)
	}
	if f.hashFunction != "" {
		optionalArgs += fmt.Sprintf("  hash_function = %q\n", f.hashFunction)
	}
	if f.allowRotation {
		optionalArgs += "  allow_rotation = true\n"
	}
	if f.deletionAllowed {
		optionalArgs += "  deletion_allowed = true\n"
	}
	if f.allowedRoles != "" {
		optionalArgs += fmt.Sprintf("  allowed_roles = %s\n", f.allowedRoles)
	}
	if f.mappingMode != "" {
		optionalArgs += fmt.Sprintf("  mapping_mode = %q\n", f.mappingMode)
	}
	if f.maxTTL != nil {
		optionalArgs += fmt.Sprintf("  max_ttl = %d\n", *f.maxTTL)
	}
	if f.stores != "" {
		optionalArgs += fmt.Sprintf("  stores = %s\n", f.stores)
	}
	if f.minDecryptionVersion > 0 {
		optionalArgs += fmt.Sprintf("  min_decryption_version = %d\n", f.minDecryptionVersion)
	}
	if f.autoRotatePeriod != nil {
		optionalArgs += fmt.Sprintf("  auto_rotate_period = %d\n", *f.autoRotatePeriod)
	}
	if f.template != "" {
		optionalArgs += fmt.Sprintf("  template = %q\n", f.template)
	}
	if f.tweakSource != "" {
		optionalArgs += fmt.Sprintf("  tweak_source = %q\n", f.tweakSource)
	}
	if f.maxTweakLen != nil {
		optionalArgs += fmt.Sprintf("  max_tweak_len = %d\n", *f.maxTweakLen)
	}

	return fmt.Sprintf(`
resource "vault_transform_transformation_%s_imported_key" "test" {
  mount = %q
  name  = %q
%s}
`, transformationType, f.mount, f.name, optionalArgs)
}
