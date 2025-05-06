// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDataSourcePKISecretIssuer(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki-backend")
	issuerName := acctest.RandomWithPrefix("tf-test-pki-issuer")
	dataName := "data.vault_pki_secret_backend_issuer.test"
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion111)
		},
		Steps: []resource.TestStep{
			{
				Config: testPKISecretIssuerDataSource(backend, issuerName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(dataName, consts.FieldIssuerName, issuerName),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldIssuerID),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldKeyID),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldCertificate),
				),
			},
		},
	})
}

func TestAccDataSourcePKISecretIssuer_verify_disable_fields(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki-backend")
	issuerName := acctest.RandomWithPrefix("tf-test-pki-issuer")
	dataName := "data.vault_pki_secret_backend_issuer.test"
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		Steps: []resource.TestStep{
			{
				Config: testPKISecretIssuerDataSource(backend, issuerName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(dataName, consts.FieldIssuerName, issuerName),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldIssuerID),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldKeyID),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldCertificate),

					resource.TestCheckResourceAttr(dataName, consts.FieldDisableCriticalExtensionChecks, "false"),
					resource.TestCheckResourceAttr(dataName, consts.FieldDisablePathLengthChecks, "false"),
					resource.TestCheckResourceAttr(dataName, consts.FieldDisableNameChecks, "false"),
					resource.TestCheckResourceAttr(dataName, consts.FieldDisableNameConstraintChecks, "false"),
				),
			},
			{
				Config: testPKISecretIssuerDataSource_verify_disable_fields(backend, issuerName, "true"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(dataName, consts.FieldIssuerName, issuerName),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldIssuerID),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldKeyID),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldCertificate),

					resource.TestCheckResourceAttr(dataName, consts.FieldDisableCriticalExtensionChecks, "true"),
					resource.TestCheckResourceAttr(dataName, consts.FieldDisablePathLengthChecks, "true"),
					resource.TestCheckResourceAttr(dataName, consts.FieldDisableNameChecks, "true"),
					resource.TestCheckResourceAttr(dataName, consts.FieldDisableNameConstraintChecks, "true"),
				),
			},
			// As above, but leave FieldDisableNameChecks false as a spot check
			{
				Config: testPKISecretIssuerDataSource_verify_disable_fields(backend, issuerName, "false"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(dataName, consts.FieldIssuerName, issuerName),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldIssuerID),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldKeyID),
					resource.TestCheckResourceAttrSet(dataName, consts.FieldCertificate),

					resource.TestCheckResourceAttr(dataName, consts.FieldDisableCriticalExtensionChecks, "true"),
					resource.TestCheckResourceAttr(dataName, consts.FieldDisablePathLengthChecks, "true"),
					resource.TestCheckResourceAttr(dataName, consts.FieldDisableNameChecks, "false"),
					resource.TestCheckResourceAttr(dataName, consts.FieldDisableNameConstraintChecks, "true"),
				),
			},
		},
	})
}

func testPKISecretIssuerDataSource(path, issuerName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path        = "%s"
	type        = "pki"
    description = "PKI secret engine mount"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend     = vault_mount.test.path
  type        = "internal"
  common_name = "test"
  ttl         = "86400"
  issuer_name = "%s"
}

data "vault_pki_secret_backend_issuer" "test" {
  backend     = vault_mount.test.path
  issuer_ref  = vault_pki_secret_backend_root_cert.test.issuer_id
}`, path, issuerName)
}

func testPKISecretIssuerDataSource_verify_disable_fields(path, issuerName, disableNameChecks string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path        = "%s"
	type        = "pki"
    description = "PKI secret engine mount"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend     = vault_mount.test.path
  type        = "internal"
  common_name = "test"
  ttl         = "86400"
  issuer_name = "%s"
}

resource "vault_pki_secret_backend_issuer" "test" {
  backend     = vault_mount.test.path
  issuer_ref  = vault_pki_secret_backend_root_cert.test.issuer_id
  issuer_name = "%s"

  disable_critical_extension_checks = "true"
  disable_path_length_checks        = "true"
  disable_name_checks               = "%s"
  disable_name_constraint_checks    = "true"
}

data "vault_pki_secret_backend_issuer" "test" {
  backend     = vault_mount.test.path
  issuer_ref  = vault_pki_secret_backend_root_cert.test.issuer_id

  # Depend on vault_pki_secret_backend_issuer.test so that the data
  # is gathered after the issuer is updated.
  depends_on  = [vault_pki_secret_backend_issuer.test]
}`, path, issuerName, issuerName, disableNameChecks)
}
