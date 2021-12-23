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

func TestPkiSecretBackendRootSignIntermediate_basic(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendRootSignIntermediateDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendRootSignIntermediateConfig_basic(rootPath, intermediatePath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_sign_intermediate.test", "backend", rootPath),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_sign_intermediate.test", "common_name", "test Intermediate CA"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_sign_intermediate.test", "ou", "test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_sign_intermediate.test", "organization", "test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_sign_intermediate.test", "country", "test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_sign_intermediate.test", "locality", "test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_root_sign_intermediate.test", "province", "test"),
					resource.TestCheckResourceAttrSet("vault_pki_secret_backend_root_sign_intermediate.test", "serial"),
				),
			},
		},
	})
}

func testPkiSecretBackendRootSignIntermediateDestroy(s *terraform.State) error {
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

func testPkiSecretBackendRootSignIntermediateConfig_basic(rootPath string, intermediatePath string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test-root" {
  path = "%s"
  type = "pki"
  description = "test root"
  default_lease_ttl_seconds = "8640000"
  max_lease_ttl_seconds  = "8640000"
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

resource "vault_pki_secret_backend_intermediate_cert_request" "test" {
  depends_on = [ "vault_pki_secret_backend_root_cert.test" ]
  backend = vault_mount.test-intermediate.path
  type = "internal"
  common_name = "test Intermediate CA"
}

resource "vault_pki_secret_backend_root_sign_intermediate" "test" {
  depends_on = [ "vault_pki_secret_backend_intermediate_cert_request.test" ]
  backend = vault_mount.test-root.path
  csr = vault_pki_secret_backend_intermediate_cert_request.test.csr
  common_name = "test Intermediate CA"
  exclude_cn_from_sans = true
  ou = "test"
  organization = "test"
  country = "test"
  locality = "test"
  province = "test"
}`, rootPath, intermediatePath)
}
