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

func TestAccPKIExternalCADNSProviderRFC2136_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki-ext-ca")
	providerName := acctest.RandomWithPrefix("test-dns-provider")
	resourceName := "vault_pki_external_ca_secret_backend_dns_provider_rfc2136.test"

	acctestutil.SkipTestAccEnt(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion210)
		},
		Steps: []resource.TestStep{
			// create
			{
				Config: testAccPKIDNSProviderRFC2136Config(backend, providerName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, providerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNameserver, "ns1.example.com:53"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTsigKeyName, "vault-tsig-key"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTsigAlgorithm, "hmac-sha256"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "120"),
					// tsig_secret is write-only — not stored in state, cannot be checked
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldCreationDate),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldLastUpdatedDate),
				),
			},
			// import
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccPKIDNSProviderRFC2136ImportIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				// tsig_secret_wo is write-only — not returned by Vault
				ImportStateVerifyIgnore: []string{consts.FieldTsigSecretWO},
			},
			// update
			{
				Config: testAccPKIDNSProviderRFC2136ConfigUpdated(backend, providerName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldNameserver, "ns2.example.com:53"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTsigKeyName, "vault-tsig-key-v2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTsigAlgorithm, "hmac-sha512"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "300"),
				),
			},
		},
	})
}

func testAccPKIDNSProviderRFC2136ImportIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		return fmt.Sprintf("%s/config/dns/rfc2136/%s",
			rs.Primary.Attributes[consts.FieldMount],
			rs.Primary.Attributes[consts.FieldName],
		), nil
	}
}

func testAccPKIDNSProviderRFC2136Config(backend, providerName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "pki-external-ca"
  description = "PKI External CA test"
}

resource "vault_pki_external_ca_secret_backend_dns_provider_rfc2136" "test" {
  mount          = vault_mount.test.path
  name           = "%s"
  identifiers    = ["example.com"]
  ttl            = 120
  nameserver     = "ns1.example.com:53"
  tsig_key_name  = "vault-tsig-key"
  tsig_secret_wo = "supersecret"
  tsig_algorithm = "hmac-sha256"
}
`, backend, providerName)
}

func testAccPKIDNSProviderRFC2136ConfigUpdated(backend, providerName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "pki-external-ca"
  description = "PKI External CA test"
}

resource "vault_pki_external_ca_secret_backend_dns_provider_rfc2136" "test" {
  mount          = vault_mount.test.path
  name           = "%s"
  identifiers    = ["example.com"]
  ttl            = 300
  nameserver     = "ns2.example.com:53"
  tsig_key_name  = "vault-tsig-key-v2"
  tsig_secret_wo = "newsecret"
  tsig_algorithm = "hmac-sha512"
}
`, backend, providerName)
}
