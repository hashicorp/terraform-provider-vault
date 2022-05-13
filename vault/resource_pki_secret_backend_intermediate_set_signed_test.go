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

func TestPkiSecretBackendIntermediateSetSigned_basic(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())

	resourceName := "vault_pki_secret_backend_intermediate_set_signed.test"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendIntermediateSetSignedDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendIntermediateSetSignedConfig_basic(rootPath, intermediatePath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", intermediatePath),
				),
			},
		},
	})
}

func testPkiSecretBackendIntermediateSetSignedDestroy(s *terraform.State) error {
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

func testPkiSecretBackendIntermediateSetSignedConfig_basic(rootPath string, intermediatePath string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test-root" {
  path                      = "%s"
  type                      = "pki"
  description               = "test root"
  default_lease_ttl_seconds = "8640000"
  max_lease_ttl_seconds     = "8640000"
}

resource "vault_mount" "test-intermediate" {
  path                      = "%s"
  type                      = "pki"
  description               = "test intermediate"
  default_lease_ttl_seconds = "86400"
  max_lease_ttl_seconds     = "86400"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend              = vault_mount.test-root.path
  type                 = "internal"
  common_name          = "test Root CA"
  ttl                  = "86400"
  format               = "pem"
  private_key_format   = "der"
  key_type             = "rsa"
  key_bits             = 4096
  exclude_cn_from_sans = true
  ou                   = "test"
  organization         = "test"
  country              = "test"
  locality             = "test"
  province             = "test"
}

resource "vault_pki_secret_backend_intermediate_cert_request" "test" {
  backend     = vault_mount.test-intermediate.path
  type        = vault_pki_secret_backend_root_cert.test.type
  common_name = "test Root CA"
}

resource "vault_pki_secret_backend_root_sign_intermediate" "test" {
  backend              = vault_mount.test-root.path
  csr                  = vault_pki_secret_backend_intermediate_cert_request.test.csr
  common_name          = "test Intermediate CA"
  exclude_cn_from_sans = true
  ou                   = "test"
  organization         = "test"
  country              = "test"
  locality             = "test"
  province             = "test"
}

resource "vault_pki_secret_backend_intermediate_set_signed" "test" {
  backend     = vault_mount.test-intermediate.path
  certificate = vault_pki_secret_backend_root_sign_intermediate.test.certificate
}
`, rootPath, intermediatePath)
}
