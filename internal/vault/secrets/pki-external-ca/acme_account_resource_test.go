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

func TestAccPKIACMEAccount_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki")
	accountName := acctest.RandomWithPrefix("tf-acme-account")
	resourceType := "vault_pki_secret_backend_acme_account"
	resourceName := resourceType + ".test"

	ca, directoryUrl := setupVaultAndPebble(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testPKIACMEAccount_initialConfig(backend, accountName, directoryUrl, ca),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, accountName),
					resource.TestCheckResourceAttr(resourceName, "directory_url", directoryUrl),
					resource.TestCheckResourceAttr(resourceName, "email_contacts.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "email_contacts.0", "test@example.com"),
					resource.TestCheckResourceAttr(resourceName, "key_type", "ec-256"),
					resource.TestCheckResourceAttr(resourceName, "force", "false"),
					resource.TestCheckResourceAttr(resourceName, "trusted_ca", ca+"\n"),
					resource.TestCheckResourceAttr(resourceName, "active_key_version", "0"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccPKIACMEAccountImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore:              []string{"eab_kid", "eab_key", "force"},
			},
			{
				// Only trusted_ca can be updated without re-creation
				Config: testPKIACMEAccount_initialConfig(backend, accountName, directoryUrl, "\n"+ca),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, accountName),
					resource.TestCheckResourceAttr(resourceName, "directory_url", directoryUrl),
					resource.TestCheckResourceAttr(resourceName, "email_contacts.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "email_contacts.0", "test@example.com"),
					resource.TestCheckResourceAttr(resourceName, "key_type", "ec-256"),
					resource.TestCheckResourceAttr(resourceName, "trusted_ca", "\n"+ca+"\n"),
					resource.TestCheckResourceAttr(resourceName, "active_key_version", "0"),
				),
			},
			{
				// Because we change email contacts and key type this will be a re-creation
				Config: testPKIACMEAccount_updateConfig(backend, accountName, directoryUrl, ca),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, accountName),
					resource.TestCheckResourceAttr(resourceName, "directory_url", directoryUrl),
					resource.TestCheckResourceAttr(resourceName, "email_contacts.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "email_contacts.0", "test@example.com"),
					resource.TestCheckResourceAttr(resourceName, "email_contacts.1", "admin@example.com"),
					resource.TestCheckResourceAttr(resourceName, "key_type", "rsa-2048"),
					resource.TestCheckResourceAttr(resourceName, "trusted_ca", ca+"\n"),
					resource.TestCheckResourceAttr(resourceName, "active_key_version", "0"),
				),
			},
		},
	})
}

func testPKIACMEAccount_initialConfig(backend, accountName, directoryURL, trustedCA string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "pki-external-ca"
  description = "PKI External CA secret engine mount"
}

resource "vault_pki_secret_backend_acme_account" "test" {
  mount           = vault_mount.test.path
  name            = "%s"
  directory_url   = "%s"
  email_contacts  = ["test@example.com"]
  key_type        = "ec-256"
  force           = false
  trusted_ca      = <<EOT
%s
EOT
}
`, backend, accountName, directoryURL, trustedCA)
}

func testPKIACMEAccount_updateConfig(backend, accountName, directoryURL, trustedCA string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "pki-external-ca"
  description = "PKI External CA secret engine mount"
}

resource "vault_pki_secret_backend_acme_account" "test" {
  mount           = vault_mount.test.path
  name            = "%s"
  directory_url   = "%s"
  email_contacts  = ["test@example.com", "admin@example.com"]
  key_type        = "rsa-2048"
  trusted_ca      = <<EOT
%s
EOT
}
`, backend, accountName, directoryURL, trustedCA)
}

// TODO not sure how I should test eab_kid/eab_key
/*
func TestAccPKIACMEAccount_withEAB(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki")
	accountName := acctest.RandomWithPrefix("tf-acme-account")
	resourceType := "vault_pki_secret_backend_acme_account"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion200)
		},
		Steps: []resource.TestStep{
			{
				Config: testPKIACMEAccount_withEABConfig(backend, accountName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, accountName),
					resource.TestCheckResourceAttr(resourceName, "directory_url", "https://acme-staging-v02.api.letsencrypt.org/directory"),
					resource.TestCheckResourceAttr(resourceName, "email_contacts.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "email_contacts.0", "test@example.com"),
					resource.TestCheckResourceAttr(resourceName, "key_type", "ec-256"),
					resource.TestCheckResourceAttrSet(resourceName, "eab_kid"),
					resource.TestCheckResourceAttrSet(resourceName, "eab_key"),
				),
			},
		},
	})
}

func testPKIACMEAccount_withEABConfig(backend, accountName string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "pki-external-ca"
  description = "PKI External CA secret engine mount"
}

resource "vault_pki_secret_backend_acme_account" "test" {
  mount           = vault_mount.test.path
  name            = "%s"
  directory_url   = "https://acme-staging-v02.api.letsencrypt.org/directory"
  email_contacts  = ["test@example.com"]
  key_type        = "ec-256"
  eab_kid         = "test-eab-kid"
  eab_key         = "test-eab-key-value"
}
`, backend, accountName)
}
*/

func testAccPKIACMEAccountImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}

		return fmt.Sprintf("%s/config/acme-account/%s", rs.Primary.Attributes[consts.FieldMount], rs.Primary.Attributes[consts.FieldName]), nil
	}
}
