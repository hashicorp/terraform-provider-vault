package vault

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDataSourcePkiSecretBackendCert_basic(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendCertDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourcePkiSecretBackendCertConfig_basic(rootPath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_pki_access_credentials.test", "backend", rootPath),
					resource.TestCheckResourceAttr("data.vault_pki_access_credentials.test", "common_name", "cert.test.my.domain"),
					resource.TestCheckResourceAttr("data.vault_pki_access_credentials.test", "ttl", "720h"),
					resource.TestCheckResourceAttr("data.vault_pki_access_credentials.test", "uri_sans.#", "1"),
					resource.TestCheckResourceAttr("data.vault_pki_access_credentials.test", "uri_sans.0", "spiffe://test.my.domain"),
				),
			},
		},
	})
}

func testAccDataSourcePkiSecretBackendCertConfig_basic(rootPath string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test-root" {
  path = "%s"
  type = "pki"
  description = "test root"
  default_lease_ttl_seconds = "8640000"
  max_lease_ttl_seconds = "8640000"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  depends_on = [ "vault_mount.test-root" ]
  backend = vault_mount.test-root.path
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
}

resource "vault_pki_secret_backend_role" "test" {
  backend = vault_mount.test-root.path
  name = "test"
  allowed_domains  = ["test.my.domain"]
  allow_subdomains = true
  allowed_uri_sans = ["spiffe://test.my.domain"]
  max_ttl = "3600"
  key_usage = ["DigitalSignature", "KeyAgreement", "KeyEncipherment"]
}

data "vault_pki_access_credentials" "test" {
  depends_on = ["vault_pki_secret_backend_root_cert.test"]
  backend = vault_mount.test-root.path
  name = vault_pki_secret_backend_role.test.name
  common_name = "cert.test.my.domain"
  uri_sans = ["spiffe://test.my.domain"]
  ttl = "720h"
}`, rootPath)
}
