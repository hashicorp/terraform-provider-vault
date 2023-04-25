// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestTransitSecretBackendKey_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("transit")
	name := acctest.RandomWithPrefix("key")
	resourceName := "vault_transit_secret_backend_key.test"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testTransitSecretBackendKeyCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testTransitSecretBackendKeyConfig_basic(name, backend),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "deletion_allowed", "true"),
					// auto_rotate_interval is deprecated,
					// it will be updated to auto_rotate_period in the next step below
					resource.TestCheckResourceAttr(resourceName, "auto_rotate_interval", "3600"),
					resource.TestCheckResourceAttr(resourceName, "convergent_encryption", "false"),
					resource.TestCheckResourceAttr(resourceName, "derived", "false"),
					resource.TestCheckResourceAttr(resourceName, "exportable", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "keys.#"),
					resource.TestCheckResourceAttr(resourceName, "latest_version", "1"),
					resource.TestCheckResourceAttr(resourceName, "type", "aes256-gcm96"),
					resource.TestCheckResourceAttr(resourceName, "supports_decryption", "true"),
					resource.TestCheckResourceAttr(resourceName, "supports_derivation", "true"),
					resource.TestCheckResourceAttr(resourceName, "supports_encryption", "true"),
					resource.TestCheckResourceAttr(resourceName, "supports_signing", "false"),
				),
			},
			{
				Config: testTransitSecretBackendKeyConfig_updated(name, backend),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "deletion_allowed", "true"),
					resource.TestCheckResourceAttr(resourceName, "auto_rotate_period", "7200"),
					resource.TestCheckResourceAttr(resourceName, "convergent_encryption", "false"),
					resource.TestCheckResourceAttr(resourceName, "derived", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "keys.#"),
					resource.TestCheckResourceAttr(resourceName, "latest_version", "1"),
					resource.TestCheckResourceAttr(resourceName, "type", "aes256-gcm96"),
					resource.TestCheckResourceAttr(resourceName, "supports_decryption", "true"),
					resource.TestCheckResourceAttr(resourceName, "supports_derivation", "true"),
					resource.TestCheckResourceAttr(resourceName, "supports_encryption", "true"),
					resource.TestCheckResourceAttr(resourceName, "supports_signing", "false"),
					resource.TestCheckResourceAttr(resourceName, "min_decryption_version", "1"),
					resource.TestCheckResourceAttr(resourceName, "min_encryption_version", "1"),
					resource.TestCheckResourceAttr(resourceName, "deletion_allowed", "true"),
					resource.TestCheckResourceAttr(resourceName, "exportable", "true"),
					resource.TestCheckResourceAttr(resourceName, "allow_plaintext_backup", "true"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"auto_rotate_interval"},
			},
			{
				Config:      testTransitSecretBackendKeyConfig_invalidUpdates(name, backend),
				ExpectError: regexp.MustCompile("cannot be disabled on a key that already has it enabled"),
			},
			{
				Config:      testTransitSecretBackendKeyConfig_conflicts(name, backend),
				Destroy:     false,
				ExpectError: regexp.MustCompile("Error: Conflicting configuration arguments"),
			},
			{
				Config:  testTransitSecretBackendKeyConfig_updated(name, backend),
				Destroy: true,
			},
		},
	})
}

func TestTransitSecretBackendKey_rsa4096(t *testing.T) {
	backend := acctest.RandomWithPrefix("transit")
	name := acctest.RandomWithPrefix("key")
	resourceName := "vault_transit_secret_backend_key.test"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testTransitSecretBackendKeyCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testTransitSecretBackendKeyConfig_rsa4096(name, backend),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "deletion_allowed", "true"),
					resource.TestCheckResourceAttr(resourceName, "convergent_encryption", "false"),
					resource.TestCheckResourceAttr(resourceName, "derived", "false"),
					resource.TestCheckResourceAttr(resourceName, "exportable", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "keys.#"),
					resource.TestCheckResourceAttr(resourceName, "latest_version", "1"),
					resource.TestCheckResourceAttr(resourceName, "type", "rsa-4096"),
					resource.TestCheckResourceAttr(resourceName, "supports_decryption", "true"),
					resource.TestCheckResourceAttr(resourceName, "supports_derivation", "false"),
					resource.TestCheckResourceAttr(resourceName, "supports_encryption", "true"),
					resource.TestCheckResourceAttr(resourceName, "supports_signing", "true"),
					resource.TestCheckResourceAttr(resourceName, "auto_rotate_period", "0"),
				),
			},
			{
				Config: testTransitSecretBackendKeyConfig_rsa4096updated(name, backend),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "deletion_allowed", "true"),
					resource.TestCheckResourceAttr(resourceName, "convergent_encryption", "false"),
					resource.TestCheckResourceAttr(resourceName, "derived", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "keys.#"),
					resource.TestCheckResourceAttr(resourceName, "latest_version", "1"),
					resource.TestCheckResourceAttr(resourceName, "type", "rsa-4096"),
					resource.TestCheckResourceAttr(resourceName, "supports_decryption", "true"),
					resource.TestCheckResourceAttr(resourceName, "supports_derivation", "false"),
					resource.TestCheckResourceAttr(resourceName, "supports_encryption", "true"),
					resource.TestCheckResourceAttr(resourceName, "supports_signing", "true"),
					resource.TestCheckResourceAttr(resourceName, "min_decryption_version", "1"),
					resource.TestCheckResourceAttr(resourceName, "min_encryption_version", "1"),
					resource.TestCheckResourceAttr(resourceName, "deletion_allowed", "true"),
					resource.TestCheckResourceAttr(resourceName, "exportable", "true"),
					resource.TestCheckResourceAttr(resourceName, "allow_plaintext_backup", "true"),
					resource.TestCheckResourceAttr(resourceName, "auto_rotate_period", "0"),
				),
			},
			{
				ResourceName:      resourceName,
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
  auto_rotate_interval = 3600
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
  auto_rotate_period     = 7200
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

func testTransitSecretBackendKeyConfig_conflicts(name, path string) string {
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
  # conflicts: auto_rotate_interval, auto_rotate_period
  auto_rotate_interval   = 3600
  auto_rotate_period     = 3600
}
`, path, name)
}

func testTransitSecretBackendKeyCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_transit_secret_backend_key" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
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
