package vault

import (
	"testing"

	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccNomadSecretBackend_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-nomad")
	address, token := getTestNomadCreds(t)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccNomadSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccNomadSecretBackendConfig_basic(path, address, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "address", address),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "token", token),
				),
			},
			{
				Config: testAccNomadSecretBackendConfig_updated(path, address, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "default_lease_ttl_seconds", "1800"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "max_lease_ttl_seconds", "43200"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "address", address),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "token", token),
				),
			},
		},
	})
}

func TestAccNomadSecretBackend_import(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-nomad")
	address, token := getTestNomadCreds(t)
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccNomadSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccNomadSecretBackendConfig_basic(path, address, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "address", address),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "token", token),
				),
			},
			{
				ResourceName:      "vault_nomad_secret_backend.test",
				ImportState:       true,
				ImportStateVerify: true,
				// the API can't serve these fields, so ignore them
				ImportStateVerifyIgnore: []string{"address", "token", "verify_connection"},
			},
		},
	})
}

func testAccNomadSecretBackendCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_nomad_secret_backend" {
			continue
		}
		for path, mount := range mounts {
			path = strings.Trim(path, "/")
			rsPath := strings.Trim(rs.Primary.Attributes["path"], "/")
			if mount.Type == "nomad" && path == rsPath {
				return fmt.Errorf("mount %q still exists", path)
			}
		}
	}
	return nil
}

func testAccNomadSecretBackendConfig_basic(path, address, token string) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  address = "%s"
  token = "%s"
}`, path, address, token)
}

func testAccNomadSecretBackendConfig_updated(path, address, token string) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 1800
  max_lease_ttl_seconds = 43200
  address = "%s"
  token = "%s"
}`, path, address, token)
}
