package vault

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestPkiSecretBackendCrlConfig_basic(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendCrlConfigConfig_basic(rootPath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_pki_secret_backend_crl_config.test", "expiry", "72h"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_crl_config.test", "disable", "true"),
				),
			},
		},
	})
}

func testPkiSecretBackendCrlConfigConfig_basic(rootPath string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test-root" {
  path = "%s"
  type = "pki"
  description = "test root"
  default_lease_ttl_seconds = "8640000"
  max_lease_ttl_seconds = "8640000"
}

resource "vault_pki_secret_backend_root_cert" "test-ca" {
	backend    = vault_mount.test-root.path
	depends_on = ["vault_mount.test-root"]

	type                 = "internal"
	common_name          = "test-ca.example.com"
	ttl                  = "8640000"
	format               = "pem"
	private_key_format   = "der"
	key_type             = "rsa"
	key_bits             = 4096
	ou                   = "Test OU"
	organization         = "ACME Ltd"
}

resource "vault_pki_secret_backend_crl_config" "test" {
  depends_on = ["vault_mount.test-root","vault_pki_secret_backend_root_cert.test-ca"]

  backend = vault_mount.test-root.path

  expiry = "72h"
  disable = true
} 

`, rootPath)
}
