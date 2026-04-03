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

// TestAccOSSecretBackendHost_basic covers CRUD and import for the host resource.
func TestAccOSSecretBackendHost_basic(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-os")
	name := acctest.RandomWithPrefix("test-host")
	resourceType := "vault_os_secret_backend_host"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccOSSecretBackendHostConfig_basic(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "address", "127.0.0.1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPort, "2222"),
					resource.TestCheckResourceAttr(resourceName, "rotation_period", "86400"),
					resource.TestCheckNoResourceAttr(resourceName, "rotation_window"),
					resource.TestCheckNoResourceAttr(resourceName, "rotation_schedule"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.env", "test"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.team", "platform"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccOSSecretBackendHostImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
			},
			{
				Config: testAccOSSecretBackendHostConfig_updated(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "address", "127.0.0.1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPort, "2222"),
					resource.TestCheckResourceAttr(resourceName, "rotation_period", "172800"),
					resource.TestCheckNoResourceAttr(resourceName, "rotation_window"),
					resource.TestCheckNoResourceAttr(resourceName, "rotation_schedule"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.%", "3"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.env", "production"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.team", "platform"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.region", "us-west"),
				),
			},
		},
	})
}

// TestAccOSSecretBackendHost_remount verifies that hosts track backend remounts
// correctly when the mount path changes.
func TestAccOSSecretBackendHost_remount(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-os")
	remountPath := acctest.RandomWithPrefix("tf-test-os-updated")
	name := acctest.RandomWithPrefix("test-host")
	resourceType := "vault_os_secret_backend_host"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccOSSecretBackendHostConfig_basic(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
				),
			},
			{
				Config: testAccOSSecretBackendHostConfig_basic(remountPath, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, remountPath),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
				),
			},
		},
	})
}

// TestAccOSSecretBackendHost_optionalFields checks add/remove behavior for the
// optional host rotation, metadata, and SSH settings.
func TestAccOSSecretBackendHost_optionalFields(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-os")
	name := acctest.RandomWithPrefix("test-host")
	resourceType := "vault_os_secret_backend_host"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccOSSecretBackendHostConfig_minimal(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "address", "127.0.0.1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPort, "2222"),
					resource.TestCheckNoResourceAttr(resourceName, "rotation_period"),
					resource.TestCheckNoResourceAttr(resourceName, "rotation_window"),
					resource.TestCheckNoResourceAttr(resourceName, "rotation_schedule"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.%", "0"),
				),
			},
			{
				Config: testAccOSSecretBackendHostConfig_allFields(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "address", "127.0.0.1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPort, "2222"),
					resource.TestCheckNoResourceAttr(resourceName, "rotation_period"),
					resource.TestCheckResourceAttr(resourceName, "rotation_window", "10800"),
					resource.TestCheckResourceAttr(resourceName, "rotation_schedule", "0 2 * * *"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.%", "3"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.env", "staging"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.owner", "devops"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.criticality", "high"),
				),
			},
			{
				Config: testAccOSSecretBackendHostConfig_minimal(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.%", "0"),
					// Verify rotation fields are cleared when removed from config
					resource.TestCheckNoResourceAttr(resourceName, "rotation_period"),
					resource.TestCheckNoResourceAttr(resourceName, "rotation_window"),
					resource.TestCheckNoResourceAttr(resourceName, "rotation_schedule"),
				),
			},
		},
	})
}

// TestAccOSSecretBackendHost_sshHostKey isolates explicit host-key pinning so
// it can be verified independently of TOFU-based host onboarding.
func TestAccOSSecretBackendHost_sshHostKey(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-os")
	name := acctest.RandomWithPrefix("test-host")
	resourceType := "vault_os_secret_backend_host"
	resourceName := resourceType + ".test"

	sshHostKey := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7/n+wNKpUxXpRKOA+QZwcz1fcQ22AxTgAWsoAwJXzmpsaGBHD3Mmu68jFPr3n/SQsftSp4R8zGVjhcG4eRZG5TgON3lwAt6UcnzOYb5mVpFytCNVEzQ++fYPcFCxNJYghZLMuYu5pg4YEyuuAGUYOtUtbzymSxiI9OvgF3Gor9PM7AspiPCVP5dXcdAvGvprv5IeTf/89apCGEhmz65o5KyDnFIG5THoQYkipJYFSIGEHo8nmd0ZUNFmSJKa6XqWn/hZy68CReIqocJEKc0BwEACEVQScvQmpD2DlCYjAQZz4vi2De/hCL4hTCWTwtGSStwSACPGLTgk7ZdcE/OUZ test@terraform-vault-provider.local"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccOSSecretBackendHostConfig_withSSHKey(mount, name, sshHostKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSSHHostKey, sshHostKey),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccOSSecretBackendHostImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
			},
		},
	})
}

// testAccOSSecretBackendHostImportStateIdFunc returns the explicit host import
// ID because the framework resource state ID is not directly reusable here.
func testAccOSSecretBackendHostImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}

		return fmt.Sprintf("%s/hosts/%s",
			rs.Primary.Attributes[consts.FieldMount],
			rs.Primary.Attributes[consts.FieldName]), nil
	}
}

// testAccOSSecretBackendHostConfig_basic creates a host using the simplest
// valid period-based rotation configuration.
func testAccOSSecretBackendHostConfig_basic(mount, name string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "vault-plugin-secrets-os"
}

resource "vault_os_secret_backend" "test" {
	mount = vault_mount.test.path
}

# Note: verify_connection defaults to true in production.
# For testing without actual SSH connectivity, it can be set to false.
resource "vault_os_secret_backend_host" "test" {
	mount           = vault_os_secret_backend.test.mount
	name            = "%s"
	address         = "127.0.0.1"
	port            = 2222
	rotation_period = 86400

  custom_metadata = {
    env  = "test"
    team = "platform"
  }
}
`, mount, name)
}

// testAccOSSecretBackendHostConfig_updated is the update variant of the basic
// host fixture.
func testAccOSSecretBackendHostConfig_updated(mount, name string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "vault-plugin-secrets-os"
}

resource "vault_os_secret_backend" "test" {
	mount = vault_mount.test.path
}

resource "vault_os_secret_backend_host" "test" {
	mount           = vault_os_secret_backend.test.mount
	name            = "%s"
	address         = "127.0.0.1"
	port            = 2222
	rotation_period = 172800

  custom_metadata = {
    env    = "production"
    team   = "platform"
    region = "us-west"
  }
}
`, mount, name)
}

// testAccOSSecretBackendHostConfig_minimal keeps only the required host fields
// so optional settings can be cleared deterministically.
func testAccOSSecretBackendHostConfig_minimal(mount, name string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "vault-plugin-secrets-os"
}

resource "vault_os_secret_backend" "test" {
	mount = vault_mount.test.path
}

resource "vault_os_secret_backend_host" "test" {
  mount   = vault_os_secret_backend.test.mount
  name    = "%s"
	address = "127.0.0.1"
	port    = 2222
}
`, mount, name)
}

// testAccOSSecretBackendHostConfig_allFields exercises the schedule/window path
// accepted by the beta plugin while also covering metadata updates.
func testAccOSSecretBackendHostConfig_allFields(mount, name string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "vault-plugin-secrets-os"
}

resource "vault_os_secret_backend" "test" {
	mount = vault_mount.test.path
}

resource "vault_os_secret_backend_host" "test" {
  mount             = vault_os_secret_backend.test.mount
  name              = "%s"
	address           = "127.0.0.1"
  port              = 2222
	rotation_period   = null
	rotation_window   = 10800
  rotation_schedule = "0 2 * * *"

  custom_metadata = {
    env         = "staging"
    owner       = "devops"
    criticality = "high"
  }
}
`, mount, name)
}

func testAccOSSecretBackendHostConfig_withSSHKey(mount, name, sshHostKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "vault-plugin-secrets-os"
}

resource "vault_os_secret_backend" "test" {
	mount = vault_mount.test.path
}

resource "vault_os_secret_backend_host" "test" {
  mount        = vault_os_secret_backend.test.mount
  name         = "%s"
	address      = "127.0.0.1"
	port         = 2222
  ssh_host_key = "%s"
}
`, mount, name, sshHostKey)
}

func TestAccOSSecretBackendHost_importInvalid(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-os")
	name := acctest.RandomWithPrefix("test-host")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccOSSecretBackendHostConfig_basic(mount, name),
			},
			{
				ResourceName:      "vault_os_secret_backend_host.test",
				ImportState:       true,
				ImportStateId:     "invalid-id-format",
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile("(?s)invalid.*host ID"),
			},
			{
				ResourceName:      "vault_os_secret_backend_host.test",
				ImportState:       true,
				ImportStateId:     mount, // Missing host name
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile("(?s)invalid.*host ID"),
			},
		},
	})
}

// Made with Bob
