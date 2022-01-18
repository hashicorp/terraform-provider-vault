package vault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKMIPSecretBackend_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-kmip")
	resourceName := "vault_kmip_secret_backend.test"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestEntPreCheck(t) },
		CheckDestroy: testAccKMIPSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testKMIPSecretBackend_initialConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "listen_addrs.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "listen_addrs.0", "127.0.0.1:5696"),
					resource.TestCheckResourceAttr(resourceName, "listen_addrs.1", "127.0.0.1:8080"),
					resource.TestCheckResourceAttr(resourceName, "tls_ca_key_type", "ec"),
					resource.TestCheckResourceAttr(resourceName, "tls_ca_key_bits", "256"),
					resource.TestCheckResourceAttr(resourceName, "tls_min_version", "tls12"),
					resource.TestCheckResourceAttr(resourceName, "default_tls_client_key_type", "ec"),
					resource.TestCheckResourceAttr(resourceName, "default_tls_client_key_bits", "256"),
					resource.TestCheckResourceAttr(resourceName, "default_tls_client_ttl", "86400"),
				),
			},
			{
				Config: testKMIPSecretBackend_updateConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "listen_addrs.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "listen_addrs.0", "127.0.0.1:5696"),
					resource.TestCheckResourceAttr(resourceName, "listen_addrs.1", "127.0.0.1:8080"),
					resource.TestCheckResourceAttr(resourceName, "tls_ca_key_type", "rsa"),
					resource.TestCheckResourceAttr(resourceName, "tls_ca_key_bits", "4096"),
					resource.TestCheckResourceAttr(resourceName, "tls_min_version", "tls12"),
					resource.TestCheckResourceAttr(resourceName, "default_tls_client_key_type", "rsa"),
					resource.TestCheckResourceAttr(resourceName, "default_tls_client_key_bits", "4096"),
					resource.TestCheckResourceAttr(resourceName, "default_tls_client_ttl", "86400"),
				),
			},
		},
	})
}

func testAccKMIPSecretBackendCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_kmip_secret_backend_config" {
			continue
		}
		for path, mount := range mounts {
			path = strings.Trim(path, "/")
			rsPath := strings.Trim(rs.Primary.Attributes["path"], "/")
			if mount.Type == "kmip" && path == rsPath {
				return fmt.Errorf("mount %q still exists", path)
			}
		}
	}
	return nil
}

func testKMIPSecretBackend_initialConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path = "%s"
  description = "test description"
  listen_addrs = ["127.0.0.1:5696", "127.0.0.1:8080"]
  server_ips = ["127.0.0.1", "192.168.1.1"]
  tls_ca_key_type = "ec"
  tls_ca_key_bits = 256
  default_tls_client_key_type = "ec"
  default_tls_client_key_bits = 256
  default_tls_client_ttl = 86400
}`, path)
}

func testKMIPSecretBackend_updateConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path = "%s"
  description = "test description"
  listen_addrs = ["127.0.0.1:5696", "127.0.0.1:8080"]
  server_ips = ["127.0.0.1", "192.168.1.1"]
  tls_ca_key_type = "rsa"
  tls_ca_key_bits = 4096
  default_tls_client_key_type = "rsa"
  default_tls_client_key_bits = 4096
  default_tls_client_ttl = 86400
}`, path)
}
