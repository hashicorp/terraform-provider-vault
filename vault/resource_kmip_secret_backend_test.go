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
	resourceName := "vault_kmip_secret_backend_config.test"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
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
					resource.TestCheckResourceAttr(resourceName, "tls_ca_key_bits", "128"),
					resource.TestCheckResourceAttr(resourceName, "tls_min_version", "2"),
					resource.TestCheckResourceAttr(resourceName, "default_tls_client_key_type", "ec"),
					resource.TestCheckResourceAttr(resourceName, "default_tls_client_key_bits", "256"),
					resource.TestCheckResourceAttr(resourceName, "default_tls_client_key_bits", "256"),
					resource.TestCheckResourceAttr(resourceName, "default_tls_client_ttl", "60s"),
				),
			},
			// {
			// 	Config: testKMIPSecretBackend_initialConfig(path),
			// 	Check: resource.ComposeTestCheckFunc(
			// 		resource.TestCheckResourceAttr(resourceName, "path", path),
			// 		resource.TestCheckResourceAttr(resourceName, "description", "test description"),
			// 		resource.TestCheckResourceAttr(resourceName, "listen_addrs.#", "2"),
			// 		resource.TestCheckResourceAttr(resourceName, "listen_addrs.0", "127.0.0.1:5696"),
			// 		resource.TestCheckResourceAttr(resourceName, "listen_addrs.1", "127.0.0.1:8080"),
			// 		resource.TestCheckResourceAttr(resourceName, "tls_ca_key_type", "ec"),
			// 		resource.TestCheckResourceAttr(resourceName, "tls_ca_key_bits", "128"),
			// 		resource.TestCheckResourceAttr(resourceName, "tls_min_version", "2"),
			// 		resource.TestCheckResourceAttr(resourceName, "default_tls_client_key_type", "ec"),
			// 		resource.TestCheckResourceAttr(resourceName, "default_tls_client_key_bits", "256"),
			// 		resource.TestCheckResourceAttr(resourceName, "default_tls_client_key_bits", "256"),
			// 		resource.TestCheckResourceAttr(resourceName, "default_tls_client_ttl", "60s"),
			// 	),
			// },
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
resource "vault_kmip_secret_backend_config" "test" {
  path = "%s"
  description = "test description"
  listen_addrs = ["127.0.0.1:5696", "127.0.0.1:8080"]
  server_ips = ["127.0.0.1:9696"]
  tls_ca_key_type = "ec"
  tls_ca_key_bits = 128
  tls_min_version = 2
  default_tls_client_key_type = "ec"
  default_tls_client_key_bits = 256
  default_tls_client_ttl = "60s"
}`, path)
}

func testKMIPSecretBackend_updateConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_gcp_secret_backend" "test" {
  path = "%s"
  credentials = <<EOF
{
  "how": "goes"
}
EOF
  description = "test description"
  default_lease_ttl_seconds = 1800
  max_lease_ttl_seconds = 43200
  local = true
}`, path)
}
