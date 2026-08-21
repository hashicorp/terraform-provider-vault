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

// ---------------------------------------------------------------------------
// AWS Route53
// ---------------------------------------------------------------------------

func TestAccPKIExternalCADNSProviderAWSRoute53_basic(t *testing.T) {
	backend      := acctest.RandomWithPrefix("tf-test-pki-ext-ca")
	providerName := acctest.RandomWithPrefix("test-dns-provider")
	resourceName := "vault_pki_external_ca_secret_backend_dns_provider_aws_route53.test"

	acctestutil.SkipTestAccEnt(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccPKIDNSProviderAWSRoute53Config(backend, providerName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, providerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, "us-east-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHostedZoneId, "Z1234567890ABC"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAssumeRoleArn, "arn:aws:iam::123456789012:role/vault-dns-role"),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldCreationDate),
					resource.TestCheckResourceAttrSet(resourceName, consts.FieldLastUpdatedDate),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccPKIDNSProviderAWSRoute53ImportIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				// secret_access_key is write-only — not returned by Vault
				ImportStateVerifyIgnore: []string{consts.FieldSecretAccessKey},
			},
		},
	})
}

func testAccPKIDNSProviderAWSRoute53ImportIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		return fmt.Sprintf("%s/config/dns/aws-route53/%s",
			rs.Primary.Attributes[consts.FieldMount],
			rs.Primary.Attributes[consts.FieldName],
		), nil
	}
}

func testAccPKIDNSProviderAWSRoute53Config(backend, providerName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "pki-external-ca"
  description = "PKI External CA test"
}

resource "vault_pki_external_ca_secret_backend_dns_provider_aws_route53" "test" {
  mount           = vault_mount.test.path
  name            = "%s"
  identifiers     = ["example.com"]
  region          = "us-east-1"
  hosted_zone_id  = "Z1234567890ABC"
  assume_role_arn = "arn:aws:iam::123456789012:role/vault-dns-role"
}
`, backend, providerName)
}

// ---------------------------------------------------------------------------
// RFC2136
// ---------------------------------------------------------------------------

func TestAccPKIExternalCADNSProviderRFC2136_basic(t *testing.T) {
	backend      := acctest.RandomWithPrefix("tf-test-pki-ext-ca")
	providerName := acctest.RandomWithPrefix("test-dns-provider")
	resourceName := "vault_pki_external_ca_secret_backend_dns_provider_rfc2136.test"

	acctestutil.SkipTestAccEnt(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
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
					resource.TestCheckResourceAttr(resourceName, consts.FieldTsigSecret, "supersecret"),
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
				// tsig_secret is write-only — not returned by Vault
				ImportStateVerifyIgnore: []string{consts.FieldTsigSecret},
			},
			// update
			{
				Config: testAccPKIDNSProviderRFC2136ConfigUpdated(backend, providerName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldNameserver, "ns2.example.com:53"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTsigKeyName, "vault-tsig-key-v2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTsigAlgorithm, "hmac-sha512"),
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
  nameserver     = "ns1.example.com:53"
  tsig_key_name  = "vault-tsig-key"
  tsig_secret    = "supersecret"
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
  nameserver     = "ns2.example.com:53"
  tsig_key_name  = "vault-tsig-key-v2"
  tsig_secret    = "newsecret"
  tsig_algorithm = "hmac-sha512"
}
`, backend, providerName)
}

// ---------------------------------------------------------------------------
// GCP
// ---------------------------------------------------------------------------

func TestAccPKIExternalCADNSProviderGCP_basic(t *testing.T) {
	backend      := acctest.RandomWithPrefix("tf-test-pki-ext-ca")
	providerName := acctest.RandomWithPrefix("test-dns-provider")
	resourceName := "vault_pki_external_ca_secret_backend_dns_provider_gcp.test"

	acctestutil.SkipTestAccEnt(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
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
			// update
			{
				Config: testAccPKIDNSProviderGCPConfigUpdated(backend, providerName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldProject, "my-gcp-project-v2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldZoneName, "example-com-v2"),
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
}
`, backend, providerName)
}

// ---------------------------------------------------------------------------
// Azure
// ---------------------------------------------------------------------------

func TestAccPKIExternalCADNSProviderAzure_basic(t *testing.T) {
	backend      := acctest.RandomWithPrefix("tf-test-pki-ext-ca")
	providerName := acctest.RandomWithPrefix("test-dns-provider")
	resourceName := "vault_pki_external_ca_secret_backend_dns_provider_azure.test"

	acctestutil.SkipTestAccEnt(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
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
