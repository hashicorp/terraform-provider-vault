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
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccPKIExternalCARoleResource_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki-ext-ca")
	accountName := acctest.RandomWithPrefix("test-account")
	roleName := acctest.RandomWithPrefix("test-role")
	resourceName := "vault_pki_secret_backend_external_ca_role.test"

	ca, directoryUrl := setupVaultAndPebble(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.PreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion118)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccPKIExternalCARoleConfig_basic(backend, accountName, roleName, directoryUrl, ca),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, roleName),
					resource.TestCheckResourceAttr(resourceName, "acme_account_name", accountName),
					resource.TestCheckResourceAttr(resourceName, "allowed_domains.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_domains.0", "example.com"),
					resource.TestCheckResourceAttr(resourceName, "allowed_domains.1", "test.com"),
					resource.TestCheckResourceAttr(resourceName, "allowed_domains_options.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_challenge_types.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "csr_generate_key_type", "ec-256"),
					resource.TestCheckResourceAttr(resourceName, "csr_identifier_population", "cn_first"),
					resource.TestCheckResourceAttrSet(resourceName, "creation_date"),
					resource.TestCheckResourceAttrSet(resourceName, "last_update_date"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "force"),
		},
	})
}

func TestAccPKIExternalCARoleResource_update(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki-ext-ca")
	accountName := acctest.RandomWithPrefix("test-account")
	roleName := acctest.RandomWithPrefix("test-role")
	resourceName := "vault_pki_secret_backend_external_ca_role.test"

	ca, directoryUrl := setupVaultAndPebble(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.PreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion118)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccPKIExternalCARoleConfig_basic(backend, accountName, roleName, directoryUrl, ca),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "allowed_domains.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "csr_generate_key_type", "ec-256"),
				),
			},
			{
				Config: testAccPKIExternalCARoleConfig_updated(backend, accountName, roleName, directoryUrl, ca),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "allowed_domains.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "allowed_domains.0", "example.com"),
					resource.TestCheckResourceAttr(resourceName, "allowed_domains.1", "test.com"),
					resource.TestCheckResourceAttr(resourceName, "allowed_domains.2", "updated.com"),
					resource.TestCheckResourceAttr(resourceName, "csr_generate_key_type", "rsa-2048"),
					resource.TestCheckResourceAttr(resourceName, "csr_identifier_population", "sans_only"),
					resource.TestCheckResourceAttr(resourceName, "allowed_challenge_types.#", "2"),
				),
			},
		},
	})
}

func testAccPKIExternalCARoleConfig_basic(backend, accountName, roleName, directoryUrl, ca string) string {
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
  allowed_domains             = ["example.com", "test.com"]
  allowed_domains_options     = ["bare_domains", "subdomains"]
  allowed_challenge_types     = ["http-01", "dns-01", "tls-alpn-01"]
  csr_generate_key_type       = "ec-256"
  csr_identifier_population   = "cn_first"
}
`, backend, accountName, directoryUrl, ca, roleName)
}

func testAccPKIExternalCARoleConfig_updated(backend, accountName, roleName, directoryUrl, ca string) string {
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
  allowed_domains             = ["example.com", "test.com", "updated.com"]
  allowed_domains_options     = ["bare_domains", "subdomains", "wildcards"]
  allowed_challenge_types     = ["http-01", "dns-01"]
  csr_generate_key_type       = "rsa-2048"
  csr_identifier_population   = "sans_only"
}
`, backend, accountName, directoryUrl, ca, roleName)
}
