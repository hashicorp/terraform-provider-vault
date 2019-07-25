package vault

import (
	"fmt"
	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
	"strconv"
	"strings"
	"testing"
)

func TestTransitSecretBackend_basic(t *testing.T) {
	path := "transit-" + strconv.Itoa(acctest.RandInt())

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testTransitSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testTransitSecretBackendConfig_basic(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transit_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_transit_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend.test", "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend.test", "max_lease_ttl_seconds", "86400"),
				),
			},
			{
				Config: testTransitSecretBackendConfig_updated(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transit_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_transit_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend.test", "default_lease_ttl_seconds", "1800"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend.test", "max_lease_ttl_seconds", "43200"),
				),
			},
		},
	})
}
func TestTransitSecretBackend_import(t *testing.T) {
	path := "transit-" + strconv.Itoa(acctest.RandInt())

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testTransitSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testTransitSecretBackendConfig_basic(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_transit_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_transit_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend.test", "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_transit_secret_backend.test", "max_lease_ttl_seconds", "86400"),
				),
			},
			{
				ResourceName:      "vault_transit_secret_backend.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testTransitSecretBackendCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_transit_secret_backend" {
			continue
		}
		for path, mount := range mounts {
			path = strings.Trim(path, "/")
			rsPath := strings.Trim(rs.Primary.Attributes["path"], "/")
			if mount.Type == "transit" && path == rsPath {
				return fmt.Errorf("Mount %q still exists", path)
			}
		}
	}
	return nil
}

func testTransitSecretBackendConfig_basic(path string) string {
	return fmt.Sprintf(`
resource "vault_transit_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
}`, path)
}

func testTransitSecretBackendConfig_updated(path string) string {
	return fmt.Sprintf(`
resource "vault_transit_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 1800
  max_lease_ttl_seconds = 43200
}`, path)
}
