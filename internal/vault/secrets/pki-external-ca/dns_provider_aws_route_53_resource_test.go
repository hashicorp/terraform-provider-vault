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

func TestAccPKIExternalCADNSProviderAWSRoute53_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki-ext-ca")
	providerName := acctest.RandomWithPrefix("test-dns-provider")
	resourceName := "vault_pki_external_ca_secret_backend_dns_provider_aws_route53.test"

	acctestutil.SkipTestAccEnt(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion210)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccPKIDNSProviderAWSRoute53Config(backend, providerName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, providerName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, "us-east-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHostedZoneID, "Z1234567890ABC"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAssumeRoleArn, "arn:aws:iam::123456789012:role/vault-dns-role"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "120"),
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
				// secret_access_key_wo is write-only — not returned by Vault
				ImportStateVerifyIgnore: []string{consts.FieldSecretAccessKeyWO},
			},
			// update — change TTL, also exercises nameserver field
			{
				Config: testAccPKIDNSProviderAWSRoute53ConfigUpdated(backend, providerName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldRegion, "eu-west-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldHostedZoneID, "ZXYZ9876543210"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAssumeRoleArn, "arn:aws:iam::123456789012:role/vault-dns-role-v2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNameserver, "8.8.8.8:53"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "300"),
				),
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
  ttl             = 120
  region          = "us-east-1"
  hosted_zone_id  = "Z1234567890ABC"
  assume_role_arn = "arn:aws:iam::123456789012:role/vault-dns-role"
}
`, backend, providerName)
}

func testAccPKIDNSProviderAWSRoute53ConfigUpdated(backend, providerName string) string {
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
  ttl             = 300
  region          = "eu-west-1"
  hosted_zone_id  = "ZXYZ9876543210"
  assume_role_arn = "arn:aws:iam::123456789012:role/vault-dns-role-v2"
  nameserver      = "8.8.8.8:53"
}
`, backend, providerName)
}
