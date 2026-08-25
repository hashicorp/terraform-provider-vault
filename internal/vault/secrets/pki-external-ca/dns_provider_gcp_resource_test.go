// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package pki_external_ca_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

func TestAccPKIExternalCADNSProviderGCP_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki-ext-ca")
	providerName := acctest.RandomWithPrefix("test-dns-provider")
	resourceName := "vault_pki_external_ca_secret_backend_dns_provider_gcp.test"

	acctestutil.SkipTestAccEnt(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion210)
		},
		Steps: []resource.TestStep{
			// create — credentials is write-only so we omit it; Vault will use
			// Application Default Credentials at challenge time if not provided.
			{
				Config: testAccPKIDNSProviderGCPConfig(backend, providerName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, providerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldProject, "my-gcp-project"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldZoneName, "example-com"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldCreationDate),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldLastUpdatedDate),
				),
			},
			// import
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccPKIDNSProviderGCPImportIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				// credentials is write-only — not returned by Vault
				ImportStateVerifyIgnore: []string{consts.FieldCredentials},
			},
			// update — also exercises nameserver field
			{
				Config: testAccPKIDNSProviderGCPConfigUpdated(backend, providerName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldProject, "my-gcp-project-v2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldZoneName, "example-com-v2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNameserver, "8.8.4.4:53"),
				),
			},
		},
	})
}

func testAccPKIDNSProviderGCPImportIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		return fmt.Sprintf("%s/config/dns/google-cloud-dns/%s",
			rs.Primary.Attributes[consts.FieldMount],
			rs.Primary.Attributes[consts.FieldName],
		), nil
	}
}

func testAccPKIDNSProviderGCPConfig(backend, providerName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "pki-external-ca"
  description = "PKI External CA test"
}

resource "vault_pki_external_ca_secret_backend_dns_provider_gcp" "test" {
  mount       = vault_mount.test.path
  name        = "%s"
  identifiers = ["example.com"]
  project     = "my-gcp-project"
  zone_name   = "example-com"
}
`, backend, providerName)
}

func testAccPKIDNSProviderGCPConfigUpdated(backend, providerName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "pki-external-ca"
  description = "PKI External CA test"
}

resource "vault_pki_external_ca_secret_backend_dns_provider_gcp" "test" {
  mount       = vault_mount.test.path
  name        = "%s"
  identifiers = ["example.com"]
  project     = "my-gcp-project-v2"
  zone_name   = "example-com-v2"
  nameserver  = "8.8.4.4:53"
}
`, backend, providerName)
}
