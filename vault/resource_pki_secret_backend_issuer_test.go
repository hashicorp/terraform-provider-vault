// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

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
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion111)
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
			// ensure JSON merge patch functions as expected. No overwrites
			{
				Config: testAccPKISecretBackendIssuer_basic(backend,
					fmt.Sprintf(`issuer_name = "%s"
										leaf_not_after_behavior = "truncate"
										crl_distribution_points = ["http://example.com/crl.crl"]`, issuerName)),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIssuerName, issuerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLeafNotAfterBehavior, "truncate"),
					resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("%s.#", consts.FieldCRLDistributionPoints), "1"),
					resource.TestCheckResourceAttr(resourceName, fmt.Sprintf("%s.0", consts.FieldCRLDistributionPoints), "http://example.com/crl.crl"),
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
