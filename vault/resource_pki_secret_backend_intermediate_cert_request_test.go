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
)

func TestPkiSecretBackendIntermediateCertRequest_basic(t *testing.T) {
	path := "pki-" + strconv.Itoa(acctest.RandInt())

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendIntermediateCertRequestDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendIntermediateCertRequestConfig_basic(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_pki_secret_backend_intermediate_cert_request.test", "backend", path),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_intermediate_cert_request.test", "type", "internal"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_intermediate_cert_request.test", "common_name", "test.my.domain"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_intermediate_cert_request.test", "uri_sans.#", "1"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_intermediate_cert_request.test", "uri_sans.0", "spiffe://test.my.domain"),
				),
			},
		},
	})
}

func testPkiSecretBackendIntermediateCertRequestDestroy(s *terraform.State) error {
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

func testPkiSecretBackendIntermediateCertRequestConfig_basic(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "pki"
  description = "test"
  default_lease_ttl_seconds = "86400"
  max_lease_ttl_seconds = "86400"
}

resource "vault_pki_secret_backend_intermediate_cert_request" "test" {
  depends_on = [ "vault_mount.test" ]
  backend = vault_mount.test.path
  type = "internal"
  common_name = "test.my.domain"
  uri_sans = ["spiffe://test.my.domain"]
}`, path)
}
