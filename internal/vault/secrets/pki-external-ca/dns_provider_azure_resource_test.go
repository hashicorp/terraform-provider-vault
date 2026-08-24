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

func TestAccPKIExternalCADNSProviderAzure_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki-ext-ca")
	providerName := acctest.RandomWithPrefix("test-dns-provider")
	resourceName := "vault_pki_external_ca_secret_backend_dns_provider_azure.test"

	acctestutil.SkipTestAccEnt(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion201)
		},
		Steps: []resource.TestStep{
			// create — client_secret is write-only so we use client_id + tenant_id
			// only; Vault stores the config without validating Azure connectivity.
			{
				Config: testAccPKIDNSProviderAzureConfig(backend, providerName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, providerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldClientID, "00000000-0000-0000-0000-000000000001"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTenantID, "00000000-0000-0000-0000-000000000002"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSubscriptionID, "00000000-0000-0000-0000-000000000003"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldResourceGroupName, "my-dns-rg"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldZoneName, "example.com"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldCreationDate),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldLastUpdatedDate),
				),
			},
			// import
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccPKIDNSProviderAzureImportIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				// client_secret is write-only — not returned by Vault
				ImportStateVerifyIgnore: []string{consts.FieldClientSecret},
			},
			// update
			{
				Config: testAccPKIDNSProviderAzureConfigUpdated(backend, providerName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldResourceGroupName, "my-dns-rg-v2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldZoneName, "updated.example.com"),
				),
			},
		},
	})
}

func testAccPKIDNSProviderAzureImportIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		return fmt.Sprintf("%s/config/dns/azure-dns/%s",
			rs.Primary.Attributes[consts.FieldMount],
			rs.Primary.Attributes[consts.FieldName],
		), nil
	}
}

func testAccPKIDNSProviderAzureConfig(backend, providerName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "pki-external-ca"
  description = "PKI External CA test"
}

resource "vault_pki_external_ca_secret_backend_dns_provider_azure" "test" {
  mount               = vault_mount.test.path
  name                = "%s"
  identifiers         = ["example.com"]
  client_id           = "00000000-0000-0000-0000-000000000001"
  tenant_id           = "00000000-0000-0000-0000-000000000002"
  subscription_id     = "00000000-0000-0000-0000-000000000003"
  resource_group_name = "my-dns-rg"
  zone_name           = "example.com"
}
`, backend, providerName)
}

func testAccPKIDNSProviderAzureConfigUpdated(backend, providerName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "pki-external-ca"
  description = "PKI External CA test"
}

resource "vault_pki_external_ca_secret_backend_dns_provider_azure" "test" {
  mount               = vault_mount.test.path
  name                = "%s"
  identifiers         = ["example.com"]
  client_id           = "00000000-0000-0000-0000-000000000001"
  tenant_id           = "00000000-0000-0000-0000-000000000002"
  subscription_id     = "00000000-0000-0000-0000-000000000003"
  resource_group_name = "my-dns-rg-v2"
  zone_name           = "updated.example.com"
}
`, backend, providerName)
}
