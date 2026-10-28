// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

// This test uses vault_acme_challenge_server which is a test only resource.
// If you see a failure that the resource doesn't exist you need to run the
// test with -tags testonly

package pki_external_ca_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
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

	resourceName := "vault_pki_external_ca_secret_backend_order_certificate.test"

	acctestutil.SkipTestAccEnt(t)
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
				Config: testPKIExternalCAOrderCertificateResource_config(backend, accountName, roleName, identifier, directoryUrl, ca, "2m"),
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
				ImportStateVerifyIgnore:              []string{"timeouts"},
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
			},
		},
	})
}

// TestAccPKIExternalCAOrderCertificateResource_timeoutUpdate verifies that adding,
// changing, and removing the timeouts block updates the resource in-place and
// preserves the computed certificate fields.
func TestAccPKIExternalCAOrderCertificateResource_timeoutUpdate(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki-ext-ca")
	roleName := acctest.RandomWithPrefix("tf-role")
	accountName := acctest.RandomWithPrefix("tf-acme-account")
	identifier := "host.docker.internal"

	resourceName := "vault_pki_external_ca_secret_backend_order_certificate.test"

	acctestutil.SkipTestAccEnt(t)
	ca, directoryUrl := setupVaultAndPebble(t)

	computedAttrs := []string{"certificate", "ca_chain.#", "private_key", "serial_number"}
	initial := map[string]string{}

	// captureComputed records the computed attributes after the first step.
	captureComputed := func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("not found: %s", resourceName)
		}
		for _, k := range computedAttrs {
			initial[k] = rs.Primary.Attributes[k]
		}
		return nil
	}

	// checkComputedUnchanged asserts the computed attributes match those captured earlier.
	checkComputedUnchanged := func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("not found: %s", resourceName)
		}
		for _, k := range computedAttrs {
			if got := rs.Primary.Attributes[k]; got != initial[k] {
				return fmt.Errorf("attribute %q changed after timeout-only update", k)
			}
		}
		return nil
	}

	expectUpdate := resource.ConfigPlanChecks{
		PreApply: []plancheck.PlanCheck{
			plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
		},
	}

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
				// no timeouts block
				Config: testPKIExternalCAOrderCertificateResource_config(backend, accountName, roleName, identifier, directoryUrl, ca, ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "certificate"),
					resource.TestCheckResourceAttrSet(resourceName, "serial_number"),
					captureComputed,
				),
			},
			{
				// add timeouts
				Config:           testPKIExternalCAOrderCertificateResource_config(backend, accountName, roleName, identifier, directoryUrl, ca, "2m"),
				ConfigPlanChecks: expectUpdate,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "timeouts.create", "2m"),
					checkComputedUnchanged,
				),
			},
			{
				// change timeouts
				Config:           testPKIExternalCAOrderCertificateResource_config(backend, accountName, roleName, identifier, directoryUrl, ca, "3m"),
				ConfigPlanChecks: expectUpdate,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "timeouts.create", "3m"),
					checkComputedUnchanged,
				),
			},
			{
				// remove timeouts
				Config:           testPKIExternalCAOrderCertificateResource_config(backend, accountName, roleName, identifier, directoryUrl, ca, ""),
				ConfigPlanChecks: expectUpdate,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckNoResourceAttr(resourceName, "timeouts.create"),
					checkComputedUnchanged,
				),
			},
		},
	})
}

// testPKIExternalCAOrderCertificateResource_config returns the test configuration.
// When createTimeout is empty, no timeouts block is rendered.
func testPKIExternalCAOrderCertificateResource_config(backend, accountName, roleName, identifier, directoryUrl, ca, createTimeout string) string {
	timeouts := ""
	if createTimeout != "" {
		timeouts = fmt.Sprintf(`
  timeouts {
    create = "%s"
  }
`, createTimeout)
	}

	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "pki-external-ca"
  description = "PKI External CA test"
}

resource "vault_pki_external_ca_secret_backend_acme_account" "test" {
  mount          = vault_mount.test.path
  name           = "%s"
  directory_url  = "%s"
  email_contacts = ["test@host.docker.internal"]
  key_type       = "ec-256"
  trusted_ca     = <<EOT
%s
EOT
}

resource "vault_pki_external_ca_secret_backend_role" "test" {
  mount                       = vault_mount.test.path
  name                        = "%s"
  acme_account_name           = vault_pki_external_ca_secret_backend_acme_account.test.name
  allowed_domains             = ["host.docker.internal"]
  allowed_domain_options      = ["bare_domains", "subdomains", "wildcards"]
  allowed_challenge_types     = ["http-01", "dns-01", "tls-alpn-01"]
  csr_generate_key_type       = "ec-256"
  csr_identifier_population   = "cn_first"
  force                       = "true"
}

resource "vault_pki_external_ca_secret_backend_order" "test" {
  mount       = vault_mount.test.path
  role_name   = vault_pki_external_ca_secret_backend_role.test.name
  identifiers = ["%s"]
}

data "vault_pki_external_ca_secret_backend_order_challenge" "test" {
  mount          = vault_mount.test.path
  role_name      = vault_pki_external_ca_secret_backend_role.test.name
  order_id       = vault_pki_external_ca_secret_backend_order.test.order_id
  challenge_type = "http-01"
  identifier     = "%s"
}

resource "vault_acme_challenge_server" "test" {
  port = 5002
  token = data.vault_pki_external_ca_secret_backend_order_challenge.test.token
  key_authorization = data.vault_pki_external_ca_secret_backend_order_challenge.test.key_authorization
}

resource "vault_pki_external_ca_secret_backend_order_challenge_fulfilled" "test" {
  mount          = vault_mount.test.path
  role_name      = vault_pki_external_ca_secret_backend_role.test.name
  order_id       = vault_pki_external_ca_secret_backend_order.test.order_id
  challenge_type = "http-01"
  identifier     = "%s"
  
  depends_on = [vault_acme_challenge_server.test]
}

resource "vault_pki_external_ca_secret_backend_order_certificate" "test" {
  mount     = vault_mount.test.path
  role_name = vault_pki_external_ca_secret_backend_role.test.name
  order_id  = vault_pki_external_ca_secret_backend_order.test.order_id

  depends_on = [vault_pki_external_ca_secret_backend_order_challenge_fulfilled.test]
%s}
`, backend, accountName, directoryUrl, ca, roleName, identifier, identifier, identifier, timeouts)
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
