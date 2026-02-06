// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki_external_ca_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

func TestAccPKIExternalCAOrderChallengeDataSource_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki-ext-ca")
	roleName := acctest.RandomWithPrefix("tf-role")
	accountName := acctest.RandomWithPrefix("tf-acme-account")
	identifier := "example.com"

	dataSourceName1 := "data.vault_pki_secret_backend_external_ca_order_challenge.http01"
	dataSourceName2 := "data.vault_pki_secret_backend_external_ca_order_challenge.dns01"

	ca, directoryUrl := setupVaultAndPebble(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.PreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion118)
		},
		Steps: []resource.TestStep{
			{
				Config: testPKIExternalCAOrderChallengeDataSource_config(backend, accountName, roleName, identifier, directoryUrl, ca),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName1, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(dataSourceName1, "role_name", roleName),
					resource.TestCheckResourceAttr(dataSourceName1, "challenge_type", "http-01"),
					resource.TestCheckResourceAttr(dataSourceName1, "identifier", identifier),
					resource.TestCheckResourceAttrSet(dataSourceName1, "order_id"),
					resource.TestCheckResourceAttrSet(dataSourceName1, "token"),
					resource.TestCheckResourceAttrSet(dataSourceName1, "key_authorization"),
					resource.TestCheckResourceAttrSet(dataSourceName1, "status"),
					resource.TestCheckResourceAttrSet(dataSourceName1, consts.FieldID),

					resource.TestCheckResourceAttr(dataSourceName2, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(dataSourceName2, "role_name", roleName),
					resource.TestCheckResourceAttr(dataSourceName2, "challenge_type", "dns-01"),
					resource.TestCheckResourceAttr(dataSourceName2, "identifier", identifier),
					resource.TestCheckResourceAttrSet(dataSourceName2, "order_id"),
					resource.TestCheckResourceAttrSet(dataSourceName2, "token"),
					resource.TestCheckResourceAttrSet(dataSourceName2, "key_authorization"),
					resource.TestCheckResourceAttrSet(dataSourceName2, "status"),
					resource.TestCheckResourceAttrSet(dataSourceName2, consts.FieldID),
				),
			},
		},
	})
}

func testPKIExternalCAOrderChallengeDataSource_config(backend, accountName, roleName, identifier, directoryUrl, ca string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "pki-external-ca"
  description = "PKI External CA test"
}

resource "vault_pki_secret_backend_acme_account" "test" {
  backend        = vault_mount.test.path
  name           = "%s"
  directory_url  = "%s"
  email_contacts = ["test@example.com"]
  key_type       = "ec-256"
  trusted_ca     = <<EOT
%s
EOT
}

resource "vault_pki_secret_backend_external_ca_role" "test" {
  backend                     = vault_mount.test.path
  name                        = "%s"
  acme_account_name           = vault_pki_secret_backend_acme_account.test.name
  allowed_domains             = ["example.com", "*.example.com"]
  allowed_domains_options     = ["bare_domains", "subdomains", "wildcards"]
  allowed_challenge_types     = ["http-01", "dns-01", "tls-alpn-01"]
  csr_generate_key_type       = "ec-256"
  csr_identifier_population   = "cn_first"
  force                       = "true"
}

resource "vault_pki_secret_backend_external_ca_order" "test" {
  backend     = vault_mount.test.path
  role_name   = vault_pki_secret_backend_external_ca_role.test.name
  identifiers = ["%s"]
}

data "vault_pki_secret_backend_external_ca_order_challenge" "http01" {
  backend        = vault_mount.test.path
  role_name      = vault_pki_secret_backend_external_ca_role.test.name
  order_id       = vault_pki_secret_backend_external_ca_order.test.order_id
  challenge_type = "http-01"
  identifier     = "%s"
}

data "vault_pki_secret_backend_external_ca_order_challenge" "dns01" {
  backend        = vault_mount.test.path
  role_name      = vault_pki_secret_backend_external_ca_role.test.name
  order_id       = vault_pki_secret_backend_external_ca_order.test.order_id
  challenge_type = "dns-01"
  identifier     = "%s"
}
`, backend, accountName, directoryUrl, ca, roleName, identifier, identifier, identifier)
}
