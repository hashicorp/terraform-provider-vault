// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package os_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

// TestAccOSSecretBackend_basic covers baseline backend configuration behavior
// for an existing OS mount, including updates to the primary config fields.
func TestAccOSSecretBackend_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-os")
	resourceType := "vault_os_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccOSSecretBackendConfig_basic(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, "max_versions", "5"),
					resource.TestCheckResourceAttr(resourceName, "ssh_host_key_trust_on_first_use", "true"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccOSSecretBackendImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
			},
			{
				Config: testAccOSSecretBackendConfig_updated(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, "max_versions", "10"),
					resource.TestCheckResourceAttr(resourceName, "ssh_host_key_trust_on_first_use", "false"),
				),
			},
		},
	})
}

// TestAccOSSecretBackend_pathChange verifies that changing path recreates the
// backend configuration against a different pre-mounted OS backend.
func TestAccOSSecretBackend_pathChange(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-os")
	updatedPath := acctest.RandomWithPrefix("tf-test-os-updated")
	resourceType := "vault_os_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccOSSecretBackendConfig_basic(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
				),
			},
			{
				Config: testAccOSSecretBackendConfig_basic(updatedPath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, updatedPath),
				),
			},
		},
	})
}

// TestAccOSSecretBackend_optionalFields checks add/remove behavior for mount
// configuration that is represented as optional fields in Terraform.
func TestAccOSSecretBackend_optionalFields(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-os")
	resourceType := "vault_os_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccOSSecretBackendConfig_minimal(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, "max_versions", "10"),
					resource.TestCheckResourceAttr(resourceName, "ssh_host_key_trust_on_first_use", "false"),
				),
			},
			{
				Config: testAccOSSecretBackendConfig_allFields(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, "max_versions", "15"),
					resource.TestCheckResourceAttr(resourceName, "ssh_host_key_trust_on_first_use", "true"),
				),
			},
			{
				Config: testAccOSSecretBackendConfig_minimal(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, "max_versions", "15"),
					resource.TestCheckResourceAttr(resourceName, "ssh_host_key_trust_on_first_use", "false"),
				),
			},
		},
	})
}

// TestAccOSSecretBackend_maxVersionsZero verifies that an explicit zero value
// is preserved in Vault and remains after the field is later removed from config.
func TestAccOSSecretBackend_maxVersionsZero(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-os")
	resourceType := "vault_os_secret_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccOSSecretBackendConfig_withMaxVersions(path, 0),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, "max_versions", "0"),
				),
			},
			{
				Config: testAccOSSecretBackendConfig_minimal(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, "max_versions", "0"),
				),
			},
			{
				Config: testAccOSSecretBackendConfig_withTOFU(path, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path),
					resource.TestCheckResourceAttr(resourceName, "max_versions", "0"),
					resource.TestCheckResourceAttr(resourceName, "ssh_host_key_trust_on_first_use", "true"),
				),
			},
		},
	})
}

// testAccOSSecretBackendImportStateIdFunc returns the explicit import ID for
// the backend resource, which is just the mount path.
func testAccOSSecretBackendImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}

		return rs.Primary.Attributes[consts.FieldMount], nil
	}
}

// testAccOSSecretBackendConfig_basic creates a representative backend config
// with TOFU enabled and a non-zero max_versions value.
func testAccOSSecretBackendConfig_basic(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "vault-plugin-secrets-os"
}

resource "vault_os_secret_backend" "test" {
	mount                            = vault_mount.test.path
  max_versions                     = 5
  ssh_host_key_trust_on_first_use  = true
}
`, path)
}

// testAccOSSecretBackendConfig_updated is the update variant of the baseline
// backend fixture.
func testAccOSSecretBackendConfig_updated(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "vault-plugin-secrets-os"
}

resource "vault_os_secret_backend" "test" {
	mount                            = vault_mount.test.path
  max_versions                     = 10
  ssh_host_key_trust_on_first_use  = false
}
`, path)
}

// testAccOSSecretBackendConfig_minimal keeps only the required path argument
// so optional mount configuration can be cleared deterministically.
func testAccOSSecretBackendConfig_minimal(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "vault-plugin-secrets-os"
}

resource "vault_os_secret_backend" "test" {
	mount = vault_mount.test.path
}
`, path)
}

// testAccOSSecretBackendConfig_allFields enables all currently supported
// backend-level configuration fields.
func testAccOSSecretBackendConfig_allFields(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
	type = "vault-plugin-secrets-os"
}

resource "vault_os_secret_backend" "test" {
	mount                            = vault_mount.test.path
  max_versions                     = 15
  ssh_host_key_trust_on_first_use  = true
}
`, path)
}

// Made with Bob

func testAccOSSecretBackendConfig_withMaxVersions(path string, maxVersions int) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
	type = "vault-plugin-secrets-os"
}

resource "vault_os_secret_backend" "test" {
	mount        = vault_mount.test.path
	max_versions = %d
}
`, path, maxVersions)
}

func testAccOSSecretBackendConfig_withTOFU(path string, tofu bool) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
	type = "vault-plugin-secrets-os"
}

resource "vault_os_secret_backend" "test" {
	mount                           = vault_mount.test.path
	ssh_host_key_trust_on_first_use = %t
}
`, path, tofu)
}

func TestAccOSSecretBackend_importInvalid(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-os")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccOSSecretBackendConfig_basic(path),
			},
			{
				ResourceName:      "vault_os_secret_backend.test",
				ImportState:       true,
				ImportStateId:     "", // Empty import ID
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile("Cannot import non-existent remote object"),
			},
		},
	})
}
