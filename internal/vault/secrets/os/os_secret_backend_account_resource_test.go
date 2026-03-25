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

// TestAccOSSecretBackendAccount_basic tests the basic CRUD operations and import
// for the OS secrets backend account resource
func TestAccOSSecretBackendAccount_basic(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-os")
	hostName := acctest.RandomWithPrefix("test-host")
	accountName := acctest.RandomWithPrefix("test-account")
	resourceType := "vault_os_secret_backend_account"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccOSSecretBackendAccountConfig_basic(mount, hostName, accountName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, hostName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, accountName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, "testuser"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPassword, "initial-password-123"),
					resource.TestCheckResourceAttr(resourceName, "rotation_period", "86400"),
					resource.TestCheckResourceAttr(resourceName, "rotation_window", "3600"),
					resource.TestCheckResourceAttr(resourceName, "rotation_schedule", ""),
					// Computed fields should be set
					resource.TestCheckResourceAttrSet(resourceName, "last_vault_rotation"),
					resource.TestCheckResourceAttrSet(resourceName, "next_vault_rotation"),
				),
			},
			// Import test - password should be ignored since it's write-only
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldPassword),
			{
				Config: testAccOSSecretBackendAccountConfig_updated(mount, hostName, accountName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, hostName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, accountName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, "testuser"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPassword, "updated-password-456"),
					resource.TestCheckResourceAttr(resourceName, "rotation_period", "172800"),
					resource.TestCheckResourceAttr(resourceName, "rotation_window", "7200"),
					resource.TestCheckResourceAttrSet(resourceName, "last_vault_rotation"),
					resource.TestCheckResourceAttrSet(resourceName, "next_vault_rotation"),
				),
			},
		},
	})
}

// TestAccOSSecretBackendAccount_remount tests that the account resource
// handles backend remounting correctly
func TestAccOSSecretBackendAccount_remount(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-os")
	remountPath := acctest.RandomWithPrefix("tf-test-os-updated")
	hostName := acctest.RandomWithPrefix("test-host")
	accountName := acctest.RandomWithPrefix("test-account")
	resourceType := "vault_os_secret_backend_account"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccOSSecretBackendAccountConfig_basic(mount, hostName, accountName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, hostName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, accountName),
				),
			},
			{
				Config: testAccOSSecretBackendAccountConfig_basic(remountPath, hostName, accountName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, remountPath),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, hostName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, accountName),
				),
			},
		},
	})
}

// TestAccOSSecretBackendAccount_optionalFields tests that optional fields
// can be added and removed
func TestAccOSSecretBackendAccount_optionalFields(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-os")
	hostName := acctest.RandomWithPrefix("test-host")
	accountName := acctest.RandomWithPrefix("test-account")
	resourceType := "vault_os_secret_backend_account"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccOSSecretBackendAccountConfig_minimal(mount, hostName, accountName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, hostName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, accountName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, "minimaluser"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPassword, "minimal-pass-789"),
				),
			},
			{
				Config: testAccOSSecretBackendAccountConfig_allFields(mount, hostName, accountName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, hostName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, accountName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldUsername, "fulluser"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPassword, "full-pass-abc"),
					resource.TestCheckResourceAttr(resourceName, "rotation_period", "259200"),
					resource.TestCheckResourceAttr(resourceName, "rotation_window", "10800"),
					resource.TestCheckResourceAttr(resourceName, "rotation_schedule", "0 3 * * *"),
					resource.TestCheckResourceAttrSet(resourceName, "last_vault_rotation"),
					resource.TestCheckResourceAttrSet(resourceName, "next_vault_rotation"),
				),
			},
			{
				Config: testAccOSSecretBackendAccountConfig_minimal(mount, hostName, accountName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, hostName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, accountName),
				),
			},
		},
	})
}

// TestAccOSSecretBackendAccount_passwordWriteOnly tests that password
// is write-only and not read back from Vault
func TestAccOSSecretBackendAccount_passwordWriteOnly(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-os")
	hostName := acctest.RandomWithPrefix("test-host")
	accountName := acctest.RandomWithPrefix("test-account")
	resourceType := "vault_os_secret_backend_account"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccOSSecretBackendAccountConfig_basic(mount, hostName, accountName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPassword, "initial-password-123"),
				),
			},
			{
				// Refresh should keep password in state even though it's not returned by API
				RefreshState: true,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPassword, "initial-password-123"),
				),
			},
		},
	})
}

// TestAccOSSecretBackendAccount_rotationSchedule tests rotation schedule configuration
func TestAccOSSecretBackendAccount_rotationSchedule(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-os")
	hostName := acctest.RandomWithPrefix("test-host")
	accountName := acctest.RandomWithPrefix("test-account")
	resourceType := "vault_os_secret_backend_account"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccOSSecretBackendAccountConfig_withSchedule(mount, hostName, accountName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHost, hostName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, accountName),
					resource.TestCheckResourceAttr(resourceName, "rotation_schedule", "0 0 * * 0"),
					resource.TestCheckResourceAttrSet(resourceName, "next_vault_rotation"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldPassword),
		},
	})
}

func testAccOSSecretBackendAccountImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}

		return fmt.Sprintf("%s/host/%s/account/%s",
			rs.Primary.Attributes[consts.FieldMount],
			rs.Primary.Attributes[consts.FieldHost],
			rs.Primary.Attributes[consts.FieldName]), nil
	}
}

func testAccOSSecretBackendAccountConfig_basic(mount, hostName, accountName string) string {
	return fmt.Sprintf(`
resource "vault_os_secret_backend" "test" {
  path = "%s"
}

resource "vault_os_secret_backend_host" "test" {
  mount   = vault_os_secret_backend.test.path
  name    = "%s"
  type    = "ssh"
  address = "192.168.1.100"
  port    = 22
}

resource "vault_os_secret_backend_account" "test" {
  mount           = vault_os_secret_backend.test.path
  host            = vault_os_secret_backend_host.test.name
  name            = "%s"
  username        = "testuser"
  password        = "initial-password-123"
  rotation_period = 86400
  rotation_window = 3600
}
`, mount, hostName, accountName)
}

func testAccOSSecretBackendAccountConfig_updated(mount, hostName, accountName string) string {
	return fmt.Sprintf(`
resource "vault_os_secret_backend" "test" {
  path = "%s"
}

resource "vault_os_secret_backend_host" "test" {
  mount   = vault_os_secret_backend.test.path
  name    = "%s"
  type    = "ssh"
  address = "192.168.1.100"
  port    = 22
}

resource "vault_os_secret_backend_account" "test" {
  mount           = vault_os_secret_backend.test.path
  host            = vault_os_secret_backend_host.test.name
  name            = "%s"
  username        = "testuser"
  password        = "updated-password-456"
  rotation_period = 172800
  rotation_window = 7200
}
`, mount, hostName, accountName)
}

func testAccOSSecretBackendAccountConfig_minimal(mount, hostName, accountName string) string {
	return fmt.Sprintf(`
resource "vault_os_secret_backend" "test" {
  path = "%s"
}

resource "vault_os_secret_backend_host" "test" {
  mount   = vault_os_secret_backend.test.path
  name    = "%s"
  type    = "ssh"
  address = "192.168.1.100"
  port    = 22
}

resource "vault_os_secret_backend_account" "test" {
  mount    = vault_os_secret_backend.test.path
  host     = vault_os_secret_backend_host.test.name
  name     = "%s"
  username = "minimaluser"
  password = "minimal-pass-789"
}
`, mount, hostName, accountName)
}

func testAccOSSecretBackendAccountConfig_allFields(mount, hostName, accountName string) string {
	return fmt.Sprintf(`
resource "vault_os_secret_backend" "test" {
  path = "%s"
}

resource "vault_os_secret_backend_host" "test" {
  mount   = vault_os_secret_backend.test.path
  name    = "%s"
  type    = "ssh"
  address = "192.168.1.100"
  port    = 22
}

resource "vault_os_secret_backend_account" "test" {
  mount             = vault_os_secret_backend.test.path
  host              = vault_os_secret_backend_host.test.name
  name              = "%s"
  username          = "fulluser"
  password          = "full-pass-abc"
  rotation_period   = 259200
  rotation_window   = 10800
  rotation_schedule = "0 3 * * *"
}
`, mount, hostName, accountName)
}

func testAccOSSecretBackendAccountConfig_withSchedule(mount, hostName, accountName string) string {
	return fmt.Sprintf(`
resource "vault_os_secret_backend" "test" {
  path = "%s"
}

resource "vault_os_secret_backend_host" "test" {
  mount   = vault_os_secret_backend.test.path
  name    = "%s"
  type    = "ssh"
  address = "192.168.1.100"
  port    = 22
}

resource "vault_os_secret_backend_account" "test" {
  mount             = vault_os_secret_backend.test.path
  host              = vault_os_secret_backend_host.test.name
  name              = "%s"
  username          = "scheduleuser"
  password          = "schedule-pass-xyz"
  rotation_schedule = "0 0 * * 0"
}
`, mount, hostName, accountName)
}

// Made with Bob
