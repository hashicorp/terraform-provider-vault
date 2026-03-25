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

// TestAccOSSecretBackendHost_basic tests the basic CRUD operations and import
// for the OS secrets backend host resource
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "ssh"),
					resource.TestCheckResourceAttr(resourceName, "address", "192.168.1.100"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPort, "22"),
					resource.TestCheckResourceAttr(resourceName, "rotation_period", "86400"),
					resource.TestCheckResourceAttr(resourceName, "rotation_window", "3600"),
					resource.TestCheckResourceAttr(resourceName, "rotation_schedule", ""),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.env", "test"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.team", "platform"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
			{
				Config: testAccOSSecretBackendHostConfig_updated(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "ssh"),
					resource.TestCheckResourceAttr(resourceName, "address", "192.168.1.101"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPort, "2222"),
					resource.TestCheckResourceAttr(resourceName, "rotation_period", "172800"),
					resource.TestCheckResourceAttr(resourceName, "rotation_window", "7200"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.%", "3"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.env", "production"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.team", "platform"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.region", "us-west"),
				),
			},
		},
	})
}

// TestAccOSSecretBackendHost_remount tests that the host resource
// handles backend remounting correctly
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

// TestAccOSSecretBackendHost_optionalFields tests that optional fields
// can be added and removed
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "ssh"),
					resource.TestCheckResourceAttr(resourceName, "address", "192.168.1.100"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPort, "22"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.%", "0"),
				),
			},
			{
				Config: testAccOSSecretBackendHostConfig_allFields(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "ssh"),
					resource.TestCheckResourceAttr(resourceName, "address", "192.168.1.100"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPort, "2222"),
					resource.TestCheckResourceAttr(resourceName, "rotation_period", "259200"),
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
				),
			},
		},
	})
}

// TestAccOSSecretBackendHost_sshHostKey tests SSH host key configuration
func TestAccOSSecretBackendHost_sshHostKey(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-test-os")
	name := acctest.RandomWithPrefix("test-host")
	resourceType := "vault_os_secret_backend_host"
	resourceName := resourceType + ".test"

	// Sample SSH host key (this is a test key, not a real one)
	sshHostKey := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC..."

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
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

func testAccOSSecretBackendHostImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}

		return fmt.Sprintf("%s/host/%s",
			rs.Primary.Attributes[consts.FieldMount],
			rs.Primary.Attributes[consts.FieldName]), nil
	}
}

func testAccOSSecretBackendHostConfig_basic(mount, name string) string {
	return fmt.Sprintf(`
resource "vault_os_secret_backend" "test" {
  path = "%s"
}

resource "vault_os_secret_backend_host" "test" {
  mount           = vault_os_secret_backend.test.path
  name            = "%s"
  type            = "ssh"
  address         = "192.168.1.100"
  port            = 22
  rotation_period = 86400
  rotation_window = 3600

  custom_metadata = {
    env  = "test"
    team = "platform"
  }
}
`, mount, name)
}

func testAccOSSecretBackendHostConfig_updated(mount, name string) string {
	return fmt.Sprintf(`
resource "vault_os_secret_backend" "test" {
  path = "%s"
}

resource "vault_os_secret_backend_host" "test" {
  mount           = vault_os_secret_backend.test.path
  name            = "%s"
  type            = "ssh"
  address         = "192.168.1.101"
  port            = 2222
  rotation_period = 172800
  rotation_window = 7200

  custom_metadata = {
    env    = "production"
    team   = "platform"
    region = "us-west"
  }
}
`, mount, name)
}

func testAccOSSecretBackendHostConfig_minimal(mount, name string) string {
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
`, mount, name)
}

func testAccOSSecretBackendHostConfig_allFields(mount, name string) string {
	return fmt.Sprintf(`
resource "vault_os_secret_backend" "test" {
  path = "%s"
}

resource "vault_os_secret_backend_host" "test" {
  mount             = vault_os_secret_backend.test.path
  name              = "%s"
  type              = "ssh"
  address           = "192.168.1.100"
  port              = 2222
  rotation_period   = 259200
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
resource "vault_os_secret_backend" "test" {
  path = "%s"
}

resource "vault_os_secret_backend_host" "test" {
  mount        = vault_os_secret_backend.test.path
  name         = "%s"
  type         = "ssh"
  address      = "192.168.1.100"
  port         = 22
  ssh_host_key = "%s"
}
`, mount, name, sshHostKey)
}

// Made with Bob
