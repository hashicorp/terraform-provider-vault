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

// TestAccPKIExternalCADNSProviderConfig_rfc2136 tests create, read, update, import
// for the rfc2136 provider type. RFC2136 is used because it has no external cloud
// dependency — only a nameserver address and TSIG key are required, and Vault accepts
// any non-empty string for those fields without actually contacting the nameserver
// at config time.
func TestAccPKIExternalCADNSProviderConfig_rfc2136(t *testing.T) {
	backend      := acctest.RandomWithPrefix("tf-test-pki-ext-ca")
	providerName := acctest.RandomWithPrefix("test-dns-provider")
	resourceName := "vault_pki_external_ca_secret_backend_dns_provider.test"

	acctestutil.SkipTestAccEnt(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			// Step 1: create
			{
				Config: testAccPKIDNSProviderConfig_rfc2136(backend, providerName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, providerName),
					resource.TestCheckResourceAttr(resourceName, "type", "rfc2136"),
					resource.TestCheckResourceAttr(resourceName, "nameserver", "ns1.example.com:53"),
					resource.TestCheckResourceAttr(resourceName, "tsig_key_name", "vault-tsig-key"),
					resource.TestCheckResourceAttr(resourceName, "tsig_algorithm", "hmac-sha256"),
					// tsig_secret is write-only — Vault does not return it, so we only
					// check that the attribute exists in state with its configured value.
					resource.TestCheckResourceAttr(resourceName, "tsig_secret", "supersecret"),
					resource.TestCheckResourceAttrSet(resourceName, "creation_date"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated_date"),
				),
			},
			// Step 2: import
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccPKIDNSProviderImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				// tsig_secret is write-only — Vault does not return it on read,
				// so import cannot restore it. This is expected behaviour.
				ImportStateVerifyIgnore: []string{"tsig_secret"},
			},
			// Step 3: update mutable fields (nameserver, tsig_key_name, tsig_algorithm,
			// tsig_secret can all be updated in-place without recreation).
			{
				Config: testAccPKIDNSProviderConfig_rfc2136Updated(backend, providerName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "nameserver", "ns2.example.com:53"),
					resource.TestCheckResourceAttr(resourceName, "tsig_key_name", "vault-tsig-key-v2"),
					resource.TestCheckResourceAttr(resourceName, "tsig_algorithm", "hmac-sha512"),
				),
			},
		},
	})
}

// TestAccPKIExternalCADNSProviderConfig_awsRoute53 tests the aws_route53 provider type.
// It uses assume-role fields only (no real AWS credentials needed at config time —
// Vault stores the configuration but does not validate AWS connectivity until an
// ACME order is placed).
func TestAccPKIExternalCADNSProviderConfig_awsRoute53(t *testing.T) {
	backend      := acctest.RandomWithPrefix("tf-test-pki-ext-ca")
	providerName := acctest.RandomWithPrefix("test-dns-provider")
	resourceName := "vault_pki_external_ca_secret_backend_dns_provider.test"

	acctestutil.SkipTestAccEnt(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccPKIDNSProviderConfig_awsRoute53(backend, providerName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, providerName),
					resource.TestCheckResourceAttr(resourceName, "type", "aws_route53"),
					resource.TestCheckResourceAttr(resourceName, "region", "us-east-1"),
					resource.TestCheckResourceAttr(resourceName, "hosted_zone_id", "Z1234567890ABC"),
					resource.TestCheckResourceAttr(resourceName, "assume_role_arn", "arn:aws:iam::123456789012:role/vault-dns-role"),
					resource.TestCheckResourceAttrSet(resourceName, "creation_date"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated_date"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccPKIDNSProviderImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
			},
		},
	})
}

// testAccPKIDNSProviderImportStateIdFunc builds the import ID in the form
// <mount>/config/dns-provider/<name>, matching the dnsProviderAffix constant
// in dns_provider_config_resource.go.
func testAccPKIDNSProviderImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}

		return fmt.Sprintf(
			"%s/config/dns-provider/%s",
			rs.Primary.Attributes[consts.FieldMount],
			rs.Primary.Attributes[consts.FieldName],
		), nil
	}
}

// --- HCL config helpers ---

func testAccPKIDNSProviderConfig_rfc2136(backend, providerName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "pki-external-ca"
  description = "PKI External CA test"
}

resource "vault_pki_external_ca_secret_backend_dns_provider" "test" {
  mount          = vault_mount.test.path
  name           = "%s"
  type           = "rfc2136"
  identifiers    = ["example.com"]
  nameserver     = "ns1.example.com:53"
  tsig_key_name  = "vault-tsig-key"
  tsig_secret    = "supersecret"
  tsig_algorithm = "hmac-sha256"
}
`, backend, providerName)
}

func testAccPKIDNSProviderConfig_rfc2136Updated(backend, providerName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "pki-external-ca"
  description = "PKI External CA test"
}

resource "vault_pki_external_ca_secret_backend_dns_provider" "test" {
  mount          = vault_mount.test.path
  name           = "%s"
  type           = "rfc2136"
  identifiers    = ["example.com"]
  nameserver     = "ns2.example.com:53"
  tsig_key_name  = "vault-tsig-key-v2"
  tsig_secret    = "newsecret"
  tsig_algorithm = "hmac-sha512"
}
`, backend, providerName)
}

func testAccPKIDNSProviderConfig_awsRoute53(backend, providerName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "pki-external-ca"
  description = "PKI External CA test"
}

resource "vault_pki_external_ca_secret_backend_dns_provider" "test" {
  mount           = vault_mount.test.path
  name            = "%s"
  type            = "aws_route53"
  identifiers     = ["example.com"]
  region          = "us-east-1"
  hosted_zone_id  = "Z1234567890ABC"
  assume_role_arn = "arn:aws:iam::123456789012:role/vault-dns-role"
}
`, backend, providerName)
}
