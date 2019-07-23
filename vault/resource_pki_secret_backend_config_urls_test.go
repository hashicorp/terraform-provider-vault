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

func TestPkiSecretBackendConfigUrls_basic(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())

	issuingCertificates := "http://127.0.0.1:8200/v1/pki/ca"
	crlDistributionPoints := "http://127.0.0.1:8200/v1/pki/crl"
	ocspServers := "http://127.0.0.1:8200/v1/pki/oscp"

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendConfigUrlsDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendCertConfigUrlsConfig_basic(rootPath, issuingCertificates, crlDistributionPoints, ocspServers),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_pki_secret_backend_config_urls.test", "issuing_certificates.0", issuingCertificates),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_config_urls.test", "crl_distribution_points.0", crlDistributionPoints),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_config_urls.test", "ocsp_servers.0", ocspServers),
				),
			},
		},
	})
}

func testPkiSecretBackendConfigUrlsDestroy(s *terraform.State) error {
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

func testPkiSecretBackendCertConfigUrlsConfig_basic(rootPath string, issuingCertificates string, crlDistributionPoints string, ocspServers string) string {
	return fmt.Sprintf(`
resource "vault_pki_secret_backend" "test-root" {
  path = "%s"
  description = "test root"
  default_lease_ttl_seconds = "8640000"
  max_lease_ttl_seconds = "8640000"
}

resource "vault_pki_secret_backend_config_urls" "test" {
  depends_on = [ "vault_pki_secret_backend.test-root" ]

  backend = "${vault_pki_secret_backend.test-root.path}"

  issuing_certificates = ["%s"]
  crl_distribution_points = ["%s"]
  ocsp_servers = ["%s"]
} 

`, rootPath, issuingCertificates, crlDistributionPoints, ocspServers)
}
