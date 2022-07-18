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

func TestPkiSecretBackendIntermediateCertRequest_basic(t *testing.T) {
	path := "pki-" + strconv.Itoa(acctest.RandInt())

	resourceName := "vault_pki_secret_backend_intermediate_cert_request.test"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendIntermediateCertRequestConfig_basic(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", path),
					resource.TestCheckResourceAttr(resourceName, "type", "internal"),
					resource.TestCheckResourceAttr(resourceName, "common_name", "test.my.domain"),
					resource.TestCheckResourceAttr(resourceName, "uri_sans.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "uri_sans.0", "spiffe://test.my.domain"),
				),
			},
		},
	})
}

func testPkiSecretBackendIntermediateCertRequestConfig_basic(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path                      = "%s"
  type                      = "pki"
  description               = "test"
  default_lease_ttl_seconds = 86400
  max_lease_ttl_seconds     = 86400
}

resource "vault_pki_secret_backend_intermediate_cert_request" "test" {
  backend     = vault_mount.test.path
  type        = "internal"
  common_name = "test.my.domain"
  uri_sans    = ["spiffe://test.my.domain"]
}
`, path)
}

func TestPkiSecretBackendIntermediateCertRequest_existing(t *testing.T) {
	path := "pki-" + strconv.Itoa(acctest.RandInt())

	resourceName := "vault_pki_secret_backend_intermediate_cert_request.existing"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendIntermediateCertRequestConfig_existing(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", path),
					resource.TestCheckResourceAttr(resourceName, "type", "existing"),
					resource.TestCheckResourceAttr(resourceName, "common_name", "test2.my.domain"),
				),
			},
		},
	})
}

func testPkiSecretBackendIntermediateCertRequestConfig_existing(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path                      = "%s"
  type                      = "pki"
  description               = "test"
  default_lease_ttl_seconds = 86400
  max_lease_ttl_seconds     = 86400
}

resource "vault_pki_secret_backend_intermediate_cert_request" "internal" {
  backend     = vault_mount.test.path
  type        = "internal"
  key_name    = "test_key"
  key_type    = "rsa"
  key_bits    = "4096"
  common_name = "test.my.domain"
}

resource "vault_pki_secret_backend_intermediate_cert_request" "existing" {
  backend     = vault_mount.test.path
  type        = "existing"
  key_ref     = vault_pki_secret_backend_intermediate_cert_request.internal.key_name
  common_name = "test2.my.domain"
}
`, path)
}
