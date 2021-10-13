package vault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
	"strconv"
)

func TestPkiSecretBackend_basic(t *testing.T) {
	path := "pki-" + strconv.Itoa(acctest.RandInt())

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendConfig_basic(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_pki_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_pki_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend.test", "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend.test", "max_lease_ttl_seconds", "86400"),
				),
			},
			{
				Config: testPkiSecretBackendConfig_updated(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_pki_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_pki_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend.test", "default_lease_ttl_seconds", "1800"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend.test", "max_lease_ttl_seconds", "43200"),
				),
			},
		},
	})
}

func TestPkiSecretBackend_import(t *testing.T) {
	path := "pki-" + strconv.Itoa(acctest.RandInt())

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testPkiSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendConfig_basic(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_pki_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_pki_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend.test", "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend.test", "max_lease_ttl_seconds", "86400"),
				),
			},
			{
				ResourceName:      "vault_pki_secret_backend.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testPkiSecretBackendCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_pki_secret_backend" {
			continue
		}
		for path, mount := range mounts {
			path = strings.Trim(path, "/")
			rsPath := strings.Trim(rs.Primary.Attributes["path"], "/")
			if mount.Type == "pki" && path == rsPath {
				return fmt.Errorf("Mount %q still exists", path)
			}
		}
	}
	return nil
}

func testPkiSecretBackendConfig_basic(path string) string {
	return fmt.Sprintf(`
resource "vault_pki_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
}`, path)
}

func testPkiSecretBackendConfig_updated(path string) string {
	return fmt.Sprintf(`
resource "vault_pki_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 1800
  max_lease_ttl_seconds = 43200
}`, path)
}
