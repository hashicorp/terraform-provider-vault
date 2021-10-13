package vault

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func TestTransitSecretBackendKey_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("transit")
	name := acctest.RandomWithPrefix("key")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testTransitSecretBackendKeyCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testTransitSecretBackendKeyConfig_basic(name, backend),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "name", name),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "deletion_allowed", "true"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "convergent_encryption", "false"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "derived", "false"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "exportable", "false"),
					resource.TestCheckResourceAttrSet("vault_transit_secret_backend_key.test", "keys.#"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "latest_version", "1"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "type", "aes256-gcm96"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "supports_decryption", "true"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "supports_derivation", "true"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "supports_encryption", "true"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "supports_signing", "false"),
				),
			},
			{
				Config: testTransitSecretBackendKeyConfig_updated(name, backend),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "name", name),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "deletion_allowed", "true"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "convergent_encryption", "false"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "derived", "false"),
					resource.TestCheckResourceAttrSet("vault_transit_secret_backend_key.test", "keys.#"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "latest_version", "1"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "type", "aes256-gcm96"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "supports_decryption", "true"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "supports_derivation", "true"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "supports_encryption", "true"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "supports_signing", "false"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "min_decryption_version", "1"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "min_encryption_version", "1"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "deletion_allowed", "true"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "exportable", "true"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "allow_plaintext_backup", "true"),
				),
			},
			{
				Config:      testTransitSecretBackendKeyConfig_invalidUpdates(name, backend),
				ExpectError: regexp.MustCompile("cannot be disabled on a key that already has it enabled"),
			},
		},
	})
}

func TestTransitSecretBackendKey_rsa4096(t *testing.T) {
	backend := acctest.RandomWithPrefix("transit")
	name := acctest.RandomWithPrefix("key")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testTransitSecretBackendKeyCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testTransitSecretBackendKeyConfig_rsa4096(name, backend),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "name", name),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "deletion_allowed", "true"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "convergent_encryption", "false"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "derived", "false"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "exportable", "false"),
					resource.TestCheckResourceAttrSet("vault_transit_secret_backend_key.test", "keys.#"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "latest_version", "1"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "type", "rsa-4096"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "supports_decryption", "true"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "supports_derivation", "false"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "supports_encryption", "true"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "supports_signing", "true"),
				),
			},
			{
				Config: testTransitSecretBackendKeyConfig_rsa4096updated(name, backend),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "name", name),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "deletion_allowed", "true"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "convergent_encryption", "false"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "derived", "false"),
					resource.TestCheckResourceAttrSet("vault_transit_secret_backend_key.test", "keys.#"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "latest_version", "1"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "type", "rsa-4096"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "supports_decryption", "true"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "supports_derivation", "false"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "supports_encryption", "true"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "supports_signing", "true"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "min_decryption_version", "1"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "min_encryption_version", "1"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "deletion_allowed", "true"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "exportable", "true"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "allow_plaintext_backup", "true"),
				),
			},
		},
	})
}

func TestTransitSecretBackendKey_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("transit")
	name := acctest.RandomWithPrefix("key")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testTransitSecretBackendKeyCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testTransitSecretBackendKeyConfig_basic(name, backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_transit_secret_backend_key.test", "name", name),
					resource.TestCheckResourceAttrSet("vault_transit_secret_backend_key.test", "keys.#"),
				),
			},
			{
				ResourceName:      "vault_transit_secret_backend_key.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testTransitSecretBackendKeyConfig_basic(name, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transit" {
  path = "%s"
  type = "transit"
}

resource "vault_transit_secret_backend_key" "test" {
  backend = vault_mount.transit.path
  name = "%s"
  deletion_allowed = true
}
`, path, name)
}

func testTransitSecretBackendKeyConfig_rsa4096(name, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transit" {
  path = "%s"
  type = "transit"
}

resource "vault_transit_secret_backend_key" "test" {
  backend = vault_mount.transit.path
  name = "%s"
  deletion_allowed = true
  type = "rsa-4096"
}
`, path, name)
}

func testTransitSecretBackendKeyConfig_rsa4096updated(name, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transit" {
  path = "%s"
  type = "transit"
}

resource "vault_transit_secret_backend_key" "test" {
  backend = vault_mount.transit.path
  name = "%s"
  deletion_allowed = true
  type = "rsa-4096"
  min_decryption_version = 1
  min_encryption_version = 1
  exportable             = true
  allow_plaintext_backup = true
}
`, path, name)
}

func testTransitSecretBackendKeyConfig_updated(name, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transit" {
  path = "%s"
  type = "transit"
}

resource "vault_transit_secret_backend_key" "test" {
  backend = vault_mount.transit.path
  name = "%s"
  min_decryption_version = 1
  min_encryption_version = 1
  deletion_allowed       = true
  exportable             = true
  allow_plaintext_backup = true
}
`, path, name)
}

func testTransitSecretBackendKeyConfig_invalidUpdates(name, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "transit" {
  path = "%s"
  type = "transit"
}

resource "vault_transit_secret_backend_key" "test" {
  backend = vault_mount.transit.path
  name = "%s"
  min_decryption_version = 1
  min_encryption_version = 1
  deletion_allowed       = true
  exportable             = false
  allow_plaintext_backup = false
}
`, path, name)
}

func testTransitSecretBackendKeyCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_transit_secret_backend_key" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return err
		}
		if secret != nil {
			return fmt.Errorf("Key %s still exists", rs.Primary.ID)
		}
	}
	return nil
}
