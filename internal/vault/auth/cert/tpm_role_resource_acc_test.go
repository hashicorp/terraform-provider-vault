// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package cert_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

// TestAccAuthCertTPMRole tests the full CRUD lifecycle, token-field round-trip,
// and import for the vault_cert_auth_backend_tpm_role resource.
func TestAccAuthCertTPMRole(t *testing.T) {
	backend := acctest.RandomWithPrefix("cert")
	roleName := acctest.RandomWithPrefix("tpm-role")
	resourceName := "vault_cert_auth_backend_tpm_role.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion203)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create a minimal role with only backend and name.
			{
				Config: testAccAuthCertTPMRoleMinimalConfig(backend, roleName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "name", roleName),
					resource.TestCheckNoResourceAttr(resourceName, "display_name"),
					resource.TestCheckResourceAttr(resourceName, "entity_ids.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "group_ids.#", "0"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 2: Add bindings (display_name, entity_ids, group_ids).
			{
				Config: testAccAuthCertTPMRoleWithBindingsConfig(backend, roleName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "name", roleName),
					resource.TestCheckResourceAttr(resourceName, "display_name", "Example TPM Role"),
					resource.TestCheckResourceAttr(resourceName, "entity_ids.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "group_ids.#", "1"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 3: Set token fields.
			{
				Config: testAccAuthCertTPMRoleWithTokenFieldsConfig(backend, roleName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "name", roleName),
					resource.TestCheckResourceAttr(resourceName, "token_ttl", "3600"),
					resource.TestCheckResourceAttr(resourceName, "token_max_ttl", "7200"),
					resource.TestCheckResourceAttr(resourceName, "token_policies.#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, "token_policies.*", "policy-a"),
					resource.TestCheckTypeSetElemAttr(resourceName, "token_policies.*", "policy-b"),
					resource.TestCheckResourceAttr(resourceName, "token_type", "service"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 4: Clear token fields, revert to minimal.
			{
				Config: testAccAuthCertTPMRoleMinimalConfig(backend, roleName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "name", roleName),
					resource.TestCheckNoResourceAttr(resourceName, "token_ttl"),
					resource.TestCheckNoResourceAttr(resourceName, "token_max_ttl"),
					resource.TestCheckNoResourceAttr(resourceName, "token_policies"),
					resource.TestCheckResourceAttr(resourceName, "token_type", "default"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 5: Import state.
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccAuthCertTPMRoleImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "backend",
			},
			// Step 6: Destroy the role (keep the mount).
			{
				Config: testAccAuthCertTPMRoleMountOnlyConfig(backend),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectNonEmptyPlan(),
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionDestroy),
					},
				},
			},
		},
	})
}

// TestAccAuthCertTPMRoleNamespace verifies that the role resource works correctly
// when deployed inside a Vault namespace (Enterprise only).
func TestAccAuthCertTPMRoleNamespace(t *testing.T) {
	backend := acctest.RandomWithPrefix("cert")
	ns := acctest.RandomWithPrefix("ns")
	roleName := acctest.RandomWithPrefix("tpm-role")
	resourceName := "vault_cert_auth_backend_tpm_role.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion203)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the role inside a namespace.
			{
				Config: testAccAuthCertTPMRoleNamespaceConfig(ns, backend, roleName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "namespace", ns),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "name", roleName),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
		},
	})
}

func testAccAuthCertTPMRoleImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		return fmt.Sprintf("auth/%s/tpmrole/%s", rs.Primary.Attributes["backend"], rs.Primary.Attributes["name"]), nil
	}
}

func testAccAuthCertTPMRoleMountOnlyConfig(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "cert" {
  type = "cert"
  path = %q
}
`, backend)
}

func testAccAuthCertTPMRoleMinimalConfig(backend, roleName string) string {
	return fmt.Sprintf(`
%s

resource "vault_cert_auth_backend_tpm_role" "test" {
  backend = vault_auth_backend.cert.path
  name    = %q
}
`, testAccAuthCertTPMRoleMountOnlyConfig(backend), roleName)
}

func testAccAuthCertTPMRoleWithBindingsConfig(backend, roleName string) string {
	return fmt.Sprintf(`
%s

resource "vault_identity_entity" "entity" {
  name = %q
}

resource "vault_identity_group" "group" {
  name = %q
  type = "internal"
}

resource "vault_cert_auth_backend_tpm_role" "test" {
  backend      = vault_auth_backend.cert.path
  name         = %q
  display_name = "Example TPM Role"
  entity_ids   = [vault_identity_entity.entity.id]
  group_ids    = [vault_identity_group.group.id]
}
`, testAccAuthCertTPMRoleMountOnlyConfig(backend), acctest.RandomWithPrefix("entity"), acctest.RandomWithPrefix("group"), roleName)
}

func testAccAuthCertTPMRoleWithTokenFieldsConfig(backend, roleName string) string {
	return fmt.Sprintf(`
%s

resource "vault_cert_auth_backend_tpm_role" "test" {
  backend = vault_auth_backend.cert.path
  name    = %q

  token_ttl      = 3600
  token_max_ttl  = 7200
  token_policies = ["policy-a", "policy-b"]
  token_type     = "service"
}
`, testAccAuthCertTPMRoleMountOnlyConfig(backend), roleName)
}

func testAccAuthCertTPMRoleNamespaceConfig(ns, backend, roleName string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = %q
}

resource "vault_auth_backend" "cert" {
  type      = "cert"
  path      = %q
  namespace = vault_namespace.test.path
}

resource "vault_cert_auth_backend_tpm_role" "test" {
  namespace = vault_namespace.test.path
  backend   = vault_auth_backend.cert.path
  name      = %q
}
`, ns, backend, roleName)
}
