package vault

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestPkiSecretBackendRootCertificate_basic(t *testing.T) {
	path := "pki-" + strconv.Itoa(acctest.RandInt())

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendRootCertificateDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRootCertificateConfig_basic(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_cert.test", "backend", path),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_cert.test", "type", "internal"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_cert.test", "common_name", "test Root CA"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_cert.test", "ttl", "86400"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_cert.test", "format", "pem"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_cert.test", "private_key_format", "der"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_cert.test", "key_type", "rsa"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_cert.test", "key_bits", "4096"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_cert.test", "ou", "test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_cert.test", "organization", "test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_cert.test", "country", "test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_cert.test", "locality", "test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_cert.test", "province", "test"),
					resource.TestCheckResourceAttrSet("vault_pki_secret_backend_root_cert.test", "serial"),
				),
			},
		},
	})
}

func testPkiSecretBackendRootCertificateDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_mount" {
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

func testPkiSecretBackendRootCertificateConfig_basic(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "pki"
  description = "test"
  default_lease_ttl_seconds = "86400"
  max_lease_ttl_seconds     = "86400"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  depends_on = [ "vault_mount.test" ]
  backend = vault_mount.test.path
  type = "internal"
  common_name = "test Root CA"
  ttl = "86400"
  format = "pem"
  private_key_format = "der"
  key_type = "rsa"
  key_bits = 4096
  exclude_cn_from_sans = true
  ou = "test"
  organization = "test"
  country = "test"
  locality = "test"
  province = "test"
}`, path)
}
