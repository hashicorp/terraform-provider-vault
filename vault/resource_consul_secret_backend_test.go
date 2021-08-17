package vault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func TestConsulSecretBackend(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-consul")
	token := "026a0c16-87cd-4c2d-b3f3-fb539f592b7e"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccConsulSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testConsulSecretBackend_initialConfig(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "address", "127.0.0.1:8500"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "token", token),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "scheme", "http"),
				),
			},
			{
				Config: testConsulSecretBackend_updateConfig(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "default_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "max_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "address", "consul.domain.tld:8501"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "token", token),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "scheme", "https"),
				),
			},
		},
	})
}

func testAccConsulSecretBackendCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_consul_secret_backend" {
			continue
		}
		for path, mount := range mounts {
			path = strings.Trim(path, "/")
			rsPath := strings.Trim(rs.Primary.Attributes["path"], "/")
			if mount.Type == "consul" && path == rsPath {
				return fmt.Errorf("Mount %q still exists", path)
			}
		}
	}
	return nil
}

func testConsulSecretBackend_initialConfig(path, token string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  address = "127.0.0.1:8500"
  token = "%s"
}`, path, token)
}

func testConsulSecretBackend_updateConfig(path, token string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path = "%s"
  description = "test description"
  address = "consul.domain.tld:8501"
  token = "%s"
  scheme = "https"
}`, path, token)
}
