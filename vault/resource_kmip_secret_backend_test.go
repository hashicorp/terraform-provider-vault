package vault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKMIPSecretBackend_basic(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	path := acctest.RandomWithPrefix("tf-test-kmip")
	resourceName := "vault_kmip_secret_backend.test"

	lns, closer, err := testutil.GetDynamicTCPListeners("127.0.0.1", 2)
	if err != nil {
		t.Fatal(err)
	}

	addr1, addr2 := lns[0].Addr().String(), lns[1].Addr().String()

	if err = closer(); err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestEntPreCheck(t) },
		CheckDestroy: testAccKMIPSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testKMIPSecretBackend_initialConfig(path, addr1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "listen_addrs.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "listen_addrs.*", addr1),
					resource.TestCheckResourceAttr(resourceName, "server_ips.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "server_ips.0", "127.0.0.1"),
					resource.TestCheckResourceAttr(resourceName, "tls_ca_key_type", "ec"),
					resource.TestCheckResourceAttr(resourceName, "tls_ca_key_bits", "256"),
					resource.TestCheckResourceAttr(resourceName, "tls_min_version", "tls12"),
					resource.TestCheckResourceAttr(resourceName, "default_tls_client_key_type", "ec"),
					resource.TestCheckResourceAttr(resourceName, "default_tls_client_key_bits", "256"),
					resource.TestCheckResourceAttr(resourceName, "default_tls_client_ttl", "86400"),
				),
			},
			{
				Config: testKMIPSecretBackend_updateConfig(path, addr1, addr2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "listen_addrs.#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, "listen_addrs.*", addr1),
					resource.TestCheckTypeSetElemAttr(resourceName, "listen_addrs.*", addr2),
					resource.TestCheckResourceAttr(resourceName, "server_ips.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "server_ips.0", "127.0.0.1"),
					resource.TestCheckResourceAttr(resourceName, "server_ips.1", "192.168.1.1"),
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

func TestAccKMIPSecretBackend_remount(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	path := acctest.RandomWithPrefix("tf-test-kmip")
	remountPath := acctest.RandomWithPrefix("tf-test-kmip-updated")
	resourceName := "vault_kmip_secret_backend.test"

	lns, closer, err := testutil.GetDynamicTCPListeners("127.0.0.1", 1)
	if err != nil {
		t.Fatal(err)
	}

	addr1 := lns[0].Addr().String()

	if err = closer(); err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestEntPreCheck(t) },
		CheckDestroy: testAccKMIPSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testKMIPSecretBackend_initialConfig(path, addr1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "listen_addrs.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "listen_addrs.*", addr1),
					resource.TestCheckResourceAttr(resourceName, "server_ips.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "server_ips.0", "127.0.0.1"),
					resource.TestCheckResourceAttr(resourceName, "tls_ca_key_type", "ec"),
					resource.TestCheckResourceAttr(resourceName, "tls_ca_key_bits", "256"),
					resource.TestCheckResourceAttr(resourceName, "tls_min_version", "tls12"),
					resource.TestCheckResourceAttr(resourceName, "default_tls_client_key_type", "ec"),
					resource.TestCheckResourceAttr(resourceName, "default_tls_client_key_bits", "256"),
					resource.TestCheckResourceAttr(resourceName, "default_tls_client_ttl", "86400"),
				),
			},
			{
				Config: testKMIPSecretBackend_initialConfig(remountPath, addr1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", remountPath),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "listen_addrs.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "listen_addrs.*", addr1),
					resource.TestCheckResourceAttr(resourceName, "server_ips.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "server_ips.0", "127.0.0.1"),
					resource.TestCheckResourceAttr(resourceName, "tls_ca_key_type", "ec"),
					resource.TestCheckResourceAttr(resourceName, "tls_ca_key_bits", "256"),
					resource.TestCheckResourceAttr(resourceName, "tls_min_version", "tls12"),
					resource.TestCheckResourceAttr(resourceName, "default_tls_client_key_type", "ec"),
					resource.TestCheckResourceAttr(resourceName, "default_tls_client_key_bits", "256"),
					resource.TestCheckResourceAttr(resourceName, "default_tls_client_ttl", "86400"),
				),
			},
		},
	})
}

func testAccKMIPSecretBackendCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*ProviderMeta).GetClient()

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_kmip_secret_backend" {
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

func testKMIPSecretBackend_initialConfig(path, addr string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path = "%s"
  description = "test description"
  listen_addrs = ["%s"]
  server_ips = ["127.0.0.1"]
  tls_ca_key_type = "ec"
  tls_ca_key_bits = 256
  default_tls_client_key_type = "ec"
  default_tls_client_key_bits = 256
  default_tls_client_ttl = 86400
}`, path, addr)
}

func testKMIPSecretBackend_updateConfig(path, addr1, addr2 string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path = "%s"
  description = "test description"
  listen_addrs = ["%s", "%s"]
  server_ips = ["127.0.0.1", "192.168.1.1"]
  tls_ca_key_type = "rsa"
  tls_ca_key_bits = 4096
  default_tls_client_key_type = "rsa"
  default_tls_client_key_bits = 4096
  default_tls_client_ttl = 86400
}`, path, addr1, addr2)
}
