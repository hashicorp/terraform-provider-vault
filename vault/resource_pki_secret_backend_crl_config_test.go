package vault

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
)

func TestPkiSecretBackendCrlConfig_basic(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())

	expiry := "72h"
	disable := true

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendCrlConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendCrlConfigConfig_basic(rootPath, expiry, disable),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_pki_secret_backend_crl_config.test", "expiry.0", expiry),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_crl_config.test", "disable", "true"),
				),
			},
		},
	})
}

func testPkiSecretBackendCrlConfigDestroy(s *terraform.State) error {
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
				return fmt.Errorf("mount %q still exists", path)
			}
		}
	}
	return nil
}

func testPkiSecretBackendCrlConfigConfig_basic(rootPath string, expiry string, disable bool) string {
	return fmt.Sprintf(`
resource "vault_pki_secret_backend" "test-root" {
  path = "%s"
  description = "test root"
  default_lease_ttl_seconds = "8640000"
  max_lease_ttl_seconds = "8640000"
}

resource "vault_pki_secret_backend_crl_config" "test" {
  depends_on = [ "vault_pki_secret_backend.test-root" ]

  backend = "${vault_pki_secret_backend.test-root.path}"

  expiry = ["%s"]
  disable = ["%t"]
} 

`, rootPath, expiry, disable)
}
