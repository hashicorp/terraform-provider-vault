// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-provider-vault/internal/helpers"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestPkiSecretBackendIntermediateSetSigned_basic(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())

	resourceName := "vault_pki_secret_backend_intermediate_set_signed.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
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

func TestPkiSecretBackendIntermediateSetSigned_multiIssuers(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())

	resourceName := "vault_pki_secret_backend_intermediate_set_signed.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			helpers.SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion111)
		},
		CheckDestroy: testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendIntermediateSetSignedConfig_multiIssuers(rootPath, intermediatePath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, intermediatePath),
					resource.TestCheckResourceAttr(resourceName, "imported_issuers.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "imported_keys.#", "0"),
				),
			},
		},
	})
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

func testPkiSecretBackendIntermediateSetSignedConfig_multiIssuers(rootPath string, intermediatePath string) string {
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
  issuer_name          = "my-new-issuer"
  key_name             = "my-new-key"
}

resource "vault_pki_secret_backend_intermediate_cert_request" "test" {
  backend     = vault_mount.test-intermediate.path
  type        = vault_pki_secret_backend_root_cert.test.type
  common_name = "test Root CA"
  key_ref     = vault_pki_secret_backend_root_cert.test.key_id
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
  issuer_ref           = vault_pki_secret_backend_root_cert.test.issuer_id
}

resource "vault_pki_secret_backend_intermediate_set_signed" "test" {
  backend     = vault_mount.test-intermediate.path
  certificate = vault_pki_secret_backend_root_sign_intermediate.test.certificate
}
`, rootPath, intermediatePath)
}
