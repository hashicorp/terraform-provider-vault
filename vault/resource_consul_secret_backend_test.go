package vault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
)

func TestConsulSecretBackend(t *testing.T) {
	//path := acctest.RandomWithPrefix("tf-test-consul")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccConsulSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testConsulSecretBackend_initialConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "path", "tf-test-consul"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "address", "127.0.0.1:8500"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "secret_key", "e58a4b09-a4a4-4e67-859b-a9162607c85e"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "scheme", "http"),
				),
			},
			{
				Config: testConsulSecretBackend_updateConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "path", "tf-test-consul"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "default_lease_ttl_seconds", "1800"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "max_lease_ttl_seconds", "43200"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "address", "consul.domain.tld:8501"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "token", "e58a4b09-a4a4-4e67-859b-a9162607c85e"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "scheme", "httpbla"),
				),
			},
		},
	})
}

func TestAccConsulSecretBackend_import(t *testing.T) {
	// path := acctest.RandomWithPrefix("tf-test-consul")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccConsulSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testConsulSecretBackend_initialConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "path", "tf-test-consul"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "address", "127.0.0.1:8500"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "token", "e58a4b09-a4a4-4e67-859b-a9162607c85e"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "scheme", "http"),
				),
			},
			{
				ResourceName:      "vault_consul_secret_backend.test",
				ImportState:       true,
				ImportStateVerify: true,
				// the API can't serve these fields, so ignore them
				ImportStateVerifyIgnore: []string{"token"},
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

var testConsulSecretBackend_initialConfig = `
resource "vault_consul_secret_backend" "test" {
  path = "tf-test-consul"
  description = "test description"
  default_lease_ttl_seconds = 0
  max_lease_ttl_seconds = 0
  address = "127.0.0.1:8500"
  token = "e58a4b09-a4a4-4e67-859b-a9162607c85e"
}
`

var testConsulSecretBackend_updateConfig = `
resource "vault_consul_secret_backend" "test" {
  path = "tf-test-consul"
  description = "test description"
  default_lease_ttl_seconds = 1800
  max_lease_ttl_seconds = 43200
  address = "consul.domain.tld:8501"
  token = "e58a4b09-a4a4-4e67-859b-a9162607c85e"
  scheme = "https"
}
`
