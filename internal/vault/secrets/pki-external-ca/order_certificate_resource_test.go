// Copyright (c) HashiCorp, Inc.
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

func TestAccPKIExternalCAOrderCertificateResource_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki-ext-ca")
	roleName := acctest.RandomWithPrefix("tf-role")
	accountName := acctest.RandomWithPrefix("tf-acme-account")
	identifier := "host.docker.internal"

	resourceName := "vault_pki_secret_backend_external_ca_order_certificate.test"

	ca, directoryUrl := setupVaultAndPebble(t)

	resource.Test(t, resource.TestCase{
		ExternalProviders: map[string]resource.ExternalProvider{
			"null": {
				Source:            "hashicorp/null",
				VersionConstraint: "3.2.4",
			},
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testPKIExternalCAOrderCertificateResource_config(backend, accountName, roleName, identifier, directoryUrl, ca),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, "role_name", roleName),
					resource.TestCheckResourceAttrSet(resourceName, "order_id"),
					resource.TestCheckResourceAttrSet(resourceName, "certificate"),
					resource.TestCheckResourceAttrSet(resourceName, "ca_chain.#"),
					resource.TestCheckResourceAttrSet(resourceName, "serial_number"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateIdFunc:                    testAccPKIExternalCAOrderCertificateImportStateIdFunc(resourceName),
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
			},
		},
	})
}

func testPKIExternalCAOrderCertificateResource_config(backend, accountName, roleName, identifier, directoryUrl, ca string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "pki-external-ca"
  description = "PKI External CA test"
}

resource "vault_pki_secret_backend_acme_account" "test" {
  mount          = vault_mount.test.path
  name           = "%s"
  directory_url  = "%s"
  email_contacts = ["test@host.docker.internal"]
  key_type       = "ec-256"
  trusted_ca     = <<EOT
%s
EOT
}

resource "vault_pki_secret_backend_external_ca_role" "test" {
  mount                       = vault_mount.test.path
  name                        = "%s"
  acme_account_name           = vault_pki_secret_backend_acme_account.test.name
  allowed_domains             = ["host.docker.internal"]
  allowed_domain_options      = ["bare_domains", "subdomains", "wildcards"]
  allowed_challenge_types     = ["http-01", "dns-01", "tls-alpn-01"]
  csr_generate_key_type       = "ec-256"
  csr_identifier_population   = "cn_first"
  force                       = "true"
}

resource "vault_pki_secret_backend_external_ca_order" "test" {
  mount       = vault_mount.test.path
  role_name   = vault_pki_secret_backend_external_ca_role.test.name
  identifiers = ["%s"]
}

data "vault_pki_secret_backend_external_ca_order_challenge" "test" {
  mount          = vault_mount.test.path
  role_name      = vault_pki_secret_backend_external_ca_role.test.name
  order_id       = vault_pki_secret_backend_external_ca_order.test.order_id
  challenge_type = "http-01"
  identifier     = "%s"
}

resource "vault_acme_challenge_server" "test" {
  port = 5002
  token = data.vault_pki_secret_backend_external_ca_order_challenge.test.token
  key_authorization = data.vault_pki_secret_backend_external_ca_order_challenge.test.key_authorization
}

resource "vault_pki_secret_backend_external_ca_order_challenge_fulfilled" "test" {
  mount          = vault_mount.test.path
  role_name      = vault_pki_secret_backend_external_ca_role.test.name
  order_id       = vault_pki_secret_backend_external_ca_order.test.order_id
  challenge_type = "http-01"
  identifier     = "%s"
  
  depends_on = [vault_acme_challenge_server.test]
}

resource "vault_pki_secret_backend_external_ca_order_certificate" "test" {
  mount     = vault_mount.test.path
  role_name = vault_pki_secret_backend_external_ca_role.test.name
  order_id  = vault_pki_secret_backend_external_ca_order.test.order_id
  
  depends_on = [vault_pki_secret_backend_external_ca_order_challenge_fulfilled.test]
}
`, backend, accountName, directoryUrl, ca, roleName, identifier, identifier, identifier)
}

func testAccPKIExternalCAOrderCertificateImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}

		mount := rs.Primary.Attributes[consts.FieldMount]
		roleName := rs.Primary.Attributes["role_name"]
		orderId := rs.Primary.Attributes["order_id"]

		return fmt.Sprintf("%s/role/%s/order/%s/certificate", mount, roleName, orderId), nil
	}
}
