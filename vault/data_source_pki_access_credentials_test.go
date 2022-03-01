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
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendCertDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendCertConfig_basic(rootPath, intermediatePath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_pki_secret_backend_cert.test", "backend", intermediatePath),
					resource.TestCheckResourceAttr("data.vault_pki_secret_backend_cert.test", "common_name", "cert.test.my.domain"),
					resource.TestCheckResourceAttr("data.vault_pki_secret_backend_cert.test", "ttl", "720h"),
					resource.TestCheckResourceAttr("data.vault_pki_secret_backend_cert.test", "uri_sans.#", "1"),
					resource.TestCheckResourceAttr("data.vault_pki_secret_backend_cert.test", "uri_sans.0", "spiffe://test.my.domain"),
				),
			},
		},
	})
}

func testAccDataSourcePkiSecretBackendCertConfig_basic(rootPath string, intermediatePath string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test-root" {
  path = "%s"
  type = "pki"
  description = "test root"
  default_lease_ttl_seconds = "8640000"
  max_lease_ttl_seconds = "8640000"
}

resource "vault_mount" "test-intermediate" {
  depends_on = [ "vault_mount.test-root" ]
  path = "%s"
  type = "pki"
  description = "test intermediate"
  default_lease_ttl_seconds = "86400"
  max_lease_ttl_seconds = "86400"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  depends_on = [ "vault_mount.test-intermediate" ]
  backend = vault_mount.test-root.path
  type = "internal"
  common_name = "my.domain"
  ttl = "86400"
  format = "pem"
  private_key_format = "der"
  key_type = "rsa"
  key_bits = 4096
  ou = "test"
  organization = "test"
  country = "test"
  locality = "test"
  province = "test"
}

resource "vault_pki_secret_backend_intermediate_cert_request" "test" {
  depends_on = [ "vault_pki_secret_backend_root_cert.test" ]
  backend = vault_mount.test-intermediate.path
  type = "internal"
  common_name = "test.my.domain"
}

resource "vault_pki_secret_backend_root_sign_intermediate" "test" {
  depends_on = [ "vault_pki_secret_backend_intermediate_cert_request.test" ]
  backend = vault_mount.test-root.path
  csr = vault_pki_secret_backend_intermediate_cert_request.test.csr
  common_name = "test.my.domain"
  permitted_dns_domains = [".test.my.domain"]
  ou = "test"
  organization = "test"
  country = "test"
  locality = "test"
  province = "test"
}

resource "vault_pki_secret_backend_intermediate_set_signed" "test" {
  depends_on = [ "vault_pki_secret_backend_root_sign_intermediate.test" ]
  backend = vault_mount.test-intermediate.path
  certificate = vault_pki_secret_backend_root_sign_intermediate.test.certificate
}

resource "vault_pki_secret_backend_role" "test" {
  depends_on = [ "vault_pki_secret_backend_intermediate_set_signed.test" ]
  backend = vault_mount.test-intermediate.path
  name = "test"
  allowed_domains  = ["test.my.domain"]
  allow_subdomains = true
  allowed_uri_sans = ["spiffe://test.my.domain"]
  max_ttl = "3600"
  key_usage = ["DigitalSignature", "KeyAgreement", "KeyEncipherment"]
}

data "vault_pki_secret_backend_cert" "test" {
  depends_on = [ "vault_pki_secret_backend_role.test" ]
  backend = vault_mount.test-intermediate.path
  name = vault_pki_secret_backend_role.test.name
  common_name = "cert.test.my.domain"
  uri_sans = ["spiffe://test.my.domain"]
  ttl = "720h"
  min_seconds_remaining = 60
}`, rootPath, intermediatePath)
}
