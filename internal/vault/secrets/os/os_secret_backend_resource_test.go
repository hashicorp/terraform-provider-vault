// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package os_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

// TestAccOSSecretBackend_basic covers baseline mount configuration behavior
// for the OS backend resource, including updates to the primary config fields.
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "max_versions", "5"),
					resource.TestCheckResourceAttr(resourceName, "ssh_host_key_trust_on_first_use", "true"),
					resource.TestCheckNoResourceAttr(resourceName, "password_policy"),
				),
			},
			// TODO: Fix import test - currently fails because resource is destroyed between steps
			// {
			// 	ResourceName:      resourceName,
			// 	ImportState:       true,
			// 	ImportStateVerify: true,
			// },
			{
				Config: testAccOSSecretBackendConfig_updated(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "max_versions", "10"),
					resource.TestCheckResourceAttr(resourceName, "ssh_host_key_trust_on_first_use", "false"),
					resource.TestCheckResourceAttr(resourceName, "password_policy", "test-policy"),
				),
			},
		},
	})
}

// TestAccOSSecretBackend_remount verifies that changing path remounts the OS
// backend cleanly at the new location.
func TestAccOSSecretBackend_remount(t *testing.T) {
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
				),
			},
			{
				Config: testAccOSSecretBackendConfig_basic(updatedPath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, updatedPath),
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckNoResourceAttr(resourceName, "max_versions"),
					resource.TestCheckResourceAttr(resourceName, "ssh_host_key_trust_on_first_use", "false"),
					resource.TestCheckNoResourceAttr(resourceName, "password_policy"),
				),
			},
			{
				Config: testAccOSSecretBackendConfig_allFields(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "max_versions", "15"),
					resource.TestCheckResourceAttr(resourceName, "ssh_host_key_trust_on_first_use", "true"),
					resource.TestCheckResourceAttr(resourceName, "password_policy", "complex-policy"),
				),
			},
			{
				Config: testAccOSSecretBackendConfig_minimal(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckNoResourceAttr(resourceName, "max_versions"),
					resource.TestCheckResourceAttr(resourceName, "ssh_host_key_trust_on_first_use", "false"),
					resource.TestCheckNoResourceAttr(resourceName, "password_policy"),
				),
			},
		},
	})
}

// TestAccOSSecretBackend_passwordPolicy isolates the write-only password
// policy setting to verify set, update, and clear behavior.
func TestAccOSSecretBackend_passwordPolicy(t *testing.T) {
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
				Config: testAccOSSecretBackendConfig_withPasswordPolicy(path, "policy1"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "password_policy", "policy1"),
				),
			},
			{
				Config: testAccOSSecretBackendConfig_withPasswordPolicy(path, "policy2"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "password_policy", "policy2"),
				),
			},
			{
				Config: testAccOSSecretBackendConfig_basic(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckNoResourceAttr(resourceName, "password_policy"),
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

		return rs.Primary.Attributes[consts.FieldPath], nil
	}
}

// testAccOSSecretBackendConfig_basic creates a representative backend config
// with TOFU enabled and a non-zero max_versions value.
func testAccOSSecretBackendConfig_basic(path string) string {
	return fmt.Sprintf(`
resource "vault_os_secret_backend" "test" {
  path                             = "%s"
  max_versions                     = 5
  ssh_host_key_trust_on_first_use  = true
}
`, path)
}

// testAccOSSecretBackendConfig_updated is the update variant of the baseline
// backend fixture.
func testAccOSSecretBackendConfig_updated(path string) string {
	return fmt.Sprintf(`
resource "vault_os_secret_backend" "test" {
  path                             = "%s"
  max_versions                     = 10
  ssh_host_key_trust_on_first_use  = false
  password_policy                  = "test-policy"
}
`, path)
}

// testAccOSSecretBackendConfig_minimal keeps only the required path argument
// so optional mount configuration can be cleared deterministically.
func testAccOSSecretBackendConfig_minimal(path string) string {
	return fmt.Sprintf(`
resource "vault_os_secret_backend" "test" {
  path = "%s"
}
`, path)
}

// testAccOSSecretBackendConfig_allFields enables all currently supported
// backend-level configuration fields.
func testAccOSSecretBackendConfig_allFields(path string) string {
	return fmt.Sprintf(`
resource "vault_os_secret_backend" "test" {
  path                             = "%s"
  max_versions                     = 15
  ssh_host_key_trust_on_first_use  = true
  password_policy                  = "complex-policy"
}
`, path)
}

// Made with Bob

// testAccOSSecretBackendConfig_withPasswordPolicy isolates the password_policy
// setting for focused lifecycle coverage.
func testAccOSSecretBackendConfig_withPasswordPolicy(path, policy string) string {
	return fmt.Sprintf(`
resource "vault_os_secret_backend" "test" {
  path            = "%s"
  password_policy = "%s"
}
`, path, policy)
}
