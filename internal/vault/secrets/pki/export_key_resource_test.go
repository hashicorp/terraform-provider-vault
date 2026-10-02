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
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	pki "github.com/hashicorp/terraform-provider-vault/internal/vault/secrets/pki"
)

// TestPKIExportKeyResourceSchema verifies the schema compiles and passes
// Terraform's internal consistency checks without needing a live Vault.
func TestPKIExportKeyResourceSchema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaRequest := fwresource.SchemaRequest{}
	schemaResponse := &fwresource.SchemaResponse{}

	pki.NewPKIExportKeyResource().Schema(ctx, schemaRequest, schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("Schema method diagnostics: %+v", schemaResponse.Diagnostics)
	}

	diagnostics := schemaResponse.Schema.ValidateImplementation(ctx)
	if diagnostics.HasError() {
		t.Fatalf("Schema validation diagnostics: %+v", diagnostics)
	}
}

// TestAccPKIExportKeyResource is a full acceptance test that runs against a
// live Vault Enterprise instance. It steps through create, update (name), and
// delete, then verifies import state round-trips cleanly.
func TestAccPKIExportKeyResource(t *testing.T) {
	mount := acctest.RandomWithPrefix("pki-byok")
	resourceAddress := "vault_pki_secret_backend_export_key.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Create with name and key_type set — all computed fields must be populated.
			{
				Config: testAccPKIExportKeyConfig(mount, "ec-p256", "my-wrapping-key"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "key_type", "ec-p256"),
					resource.TestCheckResourceAttr(resourceAddress, "name", "my-wrapping-key"),
					resource.TestCheckResourceAttrSet(resourceAddress, "export_key_uuid"),
					resource.TestCheckResourceAttrSet(resourceAddress, "public_key"),
					resource.TestCheckResourceAttrSet(resourceAddress, "export_key_hmac"),
					resource.TestCheckResourceAttrSet(resourceAddress, "created_at"),
				),
			},
			// Change key_type — must destroy and recreate (RequiresReplace).
			{
				Config: testAccPKIExportKeyConfig(mount, "ec-p384", "my-wrapping-key"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddress, "key_type", "ec-p384"),
					resource.TestCheckResourceAttr(resourceAddress, "name", "my-wrapping-key"),
					resource.TestCheckResourceAttrSet(resourceAddress, "export_key_uuid"),
					resource.TestCheckResourceAttrSet(resourceAddress, "export_key_hmac"),
				),
			},
			// Import by <mount>/export/<uuid> and verify full state is reconstructed.
			{
				ResourceName:                         resourceAddress,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccPKIExportKeyImportID(resourceAddress),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "export_key_uuid",
			},
		},
	})
}

func testAccPKIExportKeyConfig(mount, keyType, name string) string {
	nameAttr := ""
	if name != "" {
		nameAttr = fmt.Sprintf(`name = %q`, name)
	}
	return fmt.Sprintf(`
resource "vault_mount" "pki" {
  path = %q
  type = "pki"
}

resource "vault_pki_secret_backend_export_key" "test" {
  mount    = vault_mount.pki.path
  key_type = %q
  %s
}
`, mount, keyType, nameAttr)
}

func testAccPKIExportKeyImportID(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("resource not found: %s", resourceName)
		}
		mount := rs.Primary.Attributes["mount"]
		uuid := rs.Primary.Attributes["export_key_uuid"]
		return fmt.Sprintf("%s/export/%s", mount, uuid), nil
	}
}
