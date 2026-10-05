// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package pki_test

import (
	"context"
	"fmt"
	"testing"

	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	pki "github.com/hashicorp/terraform-provider-vault/internal/vault/secrets/pki"
)

// TestPKIWrappedKeyImportResourceSchema verifies the schema compiles and passes
// Terraform's internal consistency checks without a live Vault server.
func TestPKIWrappedKeyImportResourceSchema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaRequest := fwresource.SchemaRequest{}
	schemaResponse := &fwresource.SchemaResponse{}

	pki.NewPKIWrappedKeyImportResource().Schema(ctx, schemaRequest, schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("Schema method diagnostics: %+v", schemaResponse.Diagnostics)
	}

	diagnostics := schemaResponse.Schema.ValidateImplementation(ctx)
	if diagnostics.HasError() {
		t.Fatalf("Schema validation diagnostics: %+v", diagnostics)
	}
}

// TestAccPKIWrappedKeyImportResource exercises the full BYOK import flow
// end-to-end against a live Vault Enterprise instance:
//
//  1. Create — source mount + root CA, destination mount + wrapping key,
//     ephemeral CA export, import resource. Asserts key_id and key_type are set.
//  2. PlanOnly — verifies no spurious diff after apply (Read no-op + UseStateForUnknown
//     working correctly for computed fields).
func TestAccPKIWrappedKeyImportResource(t *testing.T) {
	srcMount := acctest.RandomWithPrefix("pki-src")
	dstMount := acctest.RandomWithPrefix("pki-dst")
	resourceAddress := "vault_pki_secret_backend_wrapped_key_import.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Full BYOK flow — create wrapping key, export CA key, import.
			// key_id and key_type must be populated from the Vault response.
			{
				Config: testAccPKIWrappedKeyImportConfig(srcMount, dstMount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceAddress, "key_id"),
					resource.TestCheckResourceAttr(resourceAddress, "key_type", "rsa"),
					resource.TestCheckResourceAttr(resourceAddress, "key_name", "migrated-ca"),
					resource.TestCheckResourceAttr(resourceAddress, "mount", dstMount),
				),
			},
			// No-diff check — Read is a no-op so plan must show No changes.
			{
				Config:   testAccPKIWrappedKeyImportConfig(srcMount, dstMount),
				PlanOnly: true,
			},
		},
	})
}

// testAccPKIWrappedKeyImportConfig produces the full three-resource BYOK config:
// source mount + root CA, destination mount + wrapping key (ec-p256),
// ephemeral CA export, and the wrapped key import resource under test.
func testAccPKIWrappedKeyImportConfig(srcMount, dstMount string) string {
	return fmt.Sprintf(`
resource "vault_mount" "src" {
  path = %q
  type = "pki"
}

resource "vault_pki_secret_backend_root_cert" "src_ca" {
  backend     = vault_mount.src.path
  type        = "internal"
  common_name = "BYOK Test Root CA"
  key_type    = "rsa"
  key_bits    = 2048
}

resource "vault_mount" "dst" {
  path = %q
  type = "pki"
}

resource "vault_pki_secret_backend_export_key" "wrapping_key" {
  mount    = vault_mount.dst.path
  key_type = "ec-p256"
}

ephemeral "vault_pki_secret_backend_ca_key_export" "wrapped" {
  mount       = vault_mount.src.path
  ca_key_uuid = vault_pki_secret_backend_root_cert.src_ca.key_id
  public_key  = vault_pki_secret_backend_export_key.wrapping_key.public_key
  mount_id    = vault_mount.src.id
}

resource "vault_pki_secret_backend_wrapped_key_import" "test" {
  mount           = vault_mount.dst.path
  key_name        = "migrated-ca"
  wrapped_key     = ephemeral.vault_pki_secret_backend_ca_key_export.wrapped.wrapped_key
  export_key_hmac = ephemeral.vault_pki_secret_backend_ca_key_export.wrapped.export_key_hmac
}
`, srcMount, dstMount)
}
