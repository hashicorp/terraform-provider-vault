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
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccOSSecretBackend_basic tests the basic CRUD operations and import
// for the OS secrets backend resource
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
					resource.TestCheckResourceAttr(resourceName, "password_policy", ""),
					resource.TestCheckResourceAttr(resourceName, "description", "OS secrets engine"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
			{
				Config: testAccOSSecretBackendConfig_updated(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "max_versions", "10"),
					resource.TestCheckResourceAttr(resourceName, "ssh_host_key_trust_on_first_use", "false"),
					resource.TestCheckResourceAttr(resourceName, "password_policy", "test-policy"),
					resource.TestCheckResourceAttr(resourceName, "description", "Updated OS secrets engine"),
				),
			},
		},
	})
}

// TestAccOSSecretBackend_remount tests that the backend can be remounted
// to a different path
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

// TestAccOSSecretBackend_optionalFields tests that optional fields
// can be added and removed
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
					resource.TestCheckResourceAttr(resourceName, "max_versions", "0"),
					resource.TestCheckResourceAttr(resourceName, "ssh_host_key_trust_on_first_use", "false"),
					resource.TestCheckResourceAttr(resourceName, "password_policy", ""),
				),
			},
			{
				Config: testAccOSSecretBackendConfig_allFields(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "max_versions", "15"),
					resource.TestCheckResourceAttr(resourceName, "ssh_host_key_trust_on_first_use", "true"),
					resource.TestCheckResourceAttr(resourceName, "password_policy", "complex-policy"),
					resource.TestCheckResourceAttr(resourceName, "description", "Full configuration"),
				),
			},
			{
				Config: testAccOSSecretBackendConfig_minimal(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "max_versions", "0"),
					resource.TestCheckResourceAttr(resourceName, "ssh_host_key_trust_on_first_use", "false"),
					resource.TestCheckResourceAttr(resourceName, "password_policy", ""),
				),
			},
		},
	})
}

func testAccOSSecretBackendImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}

		return rs.Primary.Attributes[consts.FieldPath], nil
	}
}

func testAccOSSecretBackendConfig_basic(path string) string {
	return fmt.Sprintf(`
resource "vault_os_secret_backend" "test" {
  path                             = "%s"
  max_versions                     = 5
  ssh_host_key_trust_on_first_use  = true
  description                      = "OS secrets engine"
}
`, path)
}

func testAccOSSecretBackendConfig_updated(path string) string {
	return fmt.Sprintf(`
resource "vault_os_secret_backend" "test" {
  path                             = "%s"
  max_versions                     = 10
  ssh_host_key_trust_on_first_use  = false
  password_policy                  = "test-policy"
  description                      = "Updated OS secrets engine"
}
`, path)
}

func testAccOSSecretBackendConfig_minimal(path string) string {
	return fmt.Sprintf(`
resource "vault_os_secret_backend" "test" {
  path = "%s"
}
`, path)
}

func testAccOSSecretBackendConfig_allFields(path string) string {
	return fmt.Sprintf(`
resource "vault_os_secret_backend" "test" {
  path                             = "%s"
  max_versions                     = 15
  ssh_host_key_trust_on_first_use  = true
  password_policy                  = "complex-policy"
  description                      = "Full configuration"
}
`, path)
}

// Made with Bob
