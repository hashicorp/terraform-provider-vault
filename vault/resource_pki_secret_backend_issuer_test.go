// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccPKISecretBackendIssuer_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki")
	resourceType := "vault_pki_secret_backend_issuer"
	resourceName := resourceType + ".test"

	issuerName := acctest.RandomWithPrefix("tf-pki-issuer")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion111)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypePKI, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testAccPKISecretBackendIssuer_basic(backend, ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIssuerName, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLeafNotAfterBehavior, "err"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldIssuerRef),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldIssuerID),
				),
			},
			{
				Config: testAccPKISecretBackendIssuer_basic(backend,
					fmt.Sprintf(`issuer_name = "%s"`, issuerName)),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIssuerName, issuerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLeafNotAfterBehavior, "err"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldIssuerRef),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldIssuerID),
				),
			},
			// confirm error case when updating issuer by sending invalid option
			{
				Config: testAccPKISecretBackendIssuer_basic(backend,
					fmt.Sprintf(`issuer_name = "%s"
										leaf_not_after_behavior = "invalid"`, issuerName)),
				ExpectError: regexp.MustCompile("error updating issuer data"),
			},
			// ensure JSON merge patch functions as expected. No overwrites
			{
				Config: testAccPKISecretBackendIssuer_basic(backend,
					fmt.Sprintf(`issuer_name = "%s"
										leaf_not_after_behavior = "truncate"`, issuerName)),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIssuerName, issuerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLeafNotAfterBehavior, "truncate"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldIssuerRef),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldIssuerID),
				),
			},
			// ignore changes in 'usage' field since it can be returned in any order
			// example, error in attribute equivalence in following
			// Import returns "crl-signing,read-only,issuing-certificates"
			// TF state returns "read-only,issuing-certificates,crl-signing"
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldUsage),
		},
	})
}

func TestAccPKISecretBackendIssuer_verify_disable_fields(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki")
	resourceType := "vault_pki_secret_backend_issuer"
	resourceName := resourceType + ".test"

	issuerName := acctest.RandomWithPrefix("tf-pki-issuer")

	config_disable_all := fmt.Sprintf(`%s = "true"
									%s = "true"
									%s = "true"
									%s = "true"`,
		consts.FieldDisableCriticalExtensionChecks,
		consts.FieldDisablePathLengthChecks,
		consts.FieldDisableNameChecks,
		consts.FieldDisableNameConstraintChecks)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			testutil.SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypePKI, consts.FieldBackend),
		Steps: []resource.TestStep{
			// Check all disable_ fields default to false
			{
				Config: testAccPKISecretBackendIssuer_basic(backend, ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIssuerName, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLeafNotAfterBehavior, "err"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldIssuerRef),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldIssuerID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableCriticalExtensionChecks, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisablePathLengthChecks, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableNameChecks, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableNameConstraintChecks, "false"),
				),
			},
			// Set all the certificate verification check disable_ fields to true
			{
				Config: testAccPKISecretBackendIssuer_basic(backend, config_disable_all),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIssuerName, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLeafNotAfterBehavior, "err"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldIssuerRef),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldIssuerID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableCriticalExtensionChecks, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisablePathLengthChecks, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableNameChecks, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableNameConstraintChecks, "true"),
				),
			},
			{
				Config: testAccPKISecretBackendIssuer_basic(backend,
					fmt.Sprintf(`issuer_name = "%s"`, issuerName)),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIssuerName, issuerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLeafNotAfterBehavior, "err"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldIssuerRef),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldIssuerID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableCriticalExtensionChecks, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisablePathLengthChecks, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableNameChecks, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableNameConstraintChecks, "false"),
				),
			},
			{
				Config: testAccPKISecretBackendIssuer_basic(backend,
					fmt.Sprintf(`issuer_name = "%s"
									%s`, issuerName, config_disable_all)),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIssuerName, issuerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLeafNotAfterBehavior, "err"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldIssuerRef),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldIssuerID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableCriticalExtensionChecks, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisablePathLengthChecks, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableNameChecks, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableNameConstraintChecks, "true"),
				),
			},
			// confirm error case when updating issuer by sending invalid option
			{
				Config: testAccPKISecretBackendIssuer_basic(backend,
					fmt.Sprintf(`issuer_name = "%s"
										leaf_not_after_behavior = "invalid"`, issuerName)),
				ExpectError: regexp.MustCompile("error updating issuer data"),
			},
			// ensure JSON merge patch functions as expected. No overwrites
			{
				Config: testAccPKISecretBackendIssuer_basic(backend,
					fmt.Sprintf(`issuer_name = "%s"
										leaf_not_after_behavior = "truncate"`, issuerName)),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIssuerName, issuerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLeafNotAfterBehavior, "truncate"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldIssuerRef),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldIssuerID),
				),
			},
			// ignore changes in 'usage' field since it can be returned in any order
			// example, error in attribute equivalence in following
			// Import returns "crl-signing,read-only,issuing-certificates"
			// TF state returns "read-only,issuing-certificates,crl-signing"
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldUsage),
		},
	})
}

func testAccPKISecretBackendIssuer_basic(path, extraFields string) string {
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
}

resource "vault_pki_secret_backend_issuer" "test" {
  backend     = vault_mount.test.path
  issuer_ref  = vault_pki_secret_backend_root_cert.test.issuer_id
  %s
}`, path, extraFields)
}
