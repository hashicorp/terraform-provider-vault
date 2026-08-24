// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package tpm_test

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

// TestAccTPMAuthRole tests the full CRUD lifecycle, token-field round-trip,
// and import for the vault_tpm_auth_backend_role resource.
func TestAccTPMAuthRole(t *testing.T) {
	mount := acctest.RandomWithPrefix("tpm-mount")
	roleName := acctest.RandomWithPrefix("tpm-role")
	tpmName := acctest.RandomWithPrefix("tpm")
	resourceName := "vault_tpm_auth_backend_role.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create a role bound to a TPM ID and TPM group ID.
			{
				Config: testAccTPMAuthRoleWithTPMIDAndTPMGroupIDConfig(mount, roleName, tpmName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mount", mount),
					resource.TestCheckResourceAttr(resourceName, "name", roleName),
					resource.TestCheckResourceAttr(resourceName, "cert_ttl", "24h"),
					resource.TestCheckResourceAttr(resourceName, "tpm_ids.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "tpmgroup_ids.#", "1"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 2: Set token fields.
			{
				Config: testAccTPMAuthRoleWithTokenFieldsConfig(mount, roleName, tpmName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mount", mount),
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
			// Step 3: Clear token fields, revert to minimal.
			{
				Config: testAccTPMAuthRoleWithTPMIDAndTPMGroupIDConfig(mount, roleName, tpmName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mount", mount),
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
			// Step 4: Import state.
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccTPMAuthRoleImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "mount",
				ImportStateVerifyIgnore:              []string{"cert_ttl"},
			},
			// Step 5: Destroy the role (keep the mount).
			{
				Config: testAccTPMAuthRoleMountOnlyConfig(mount),
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

// TestAccTPMAuthRoleNamespace verifies that the role resource works correctly
// when deployed inside a Vault namespace.
func TestAccTPMAuthRoleNamespace(t *testing.T) {
	mount := acctest.RandomWithPrefix("tpm-mount")
	ns := acctest.RandomWithPrefix("ns")
	roleName := acctest.RandomWithPrefix("tpm-role")
	tpmName := acctest.RandomWithPrefix("tpm")
	resourceName := "vault_tpm_auth_backend_role.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the role inside a namespace.
			{
				Config: testAccTPMAuthRoleNamespaceConfig(ns, mount, roleName, tpmName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "namespace", ns),
					resource.TestCheckResourceAttr(resourceName, "mount", mount),
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

func testAccTPMAuthRoleImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		return fmt.Sprintf("auth/%s/role/%s", rs.Primary.Attributes["mount"], rs.Primary.Attributes["name"]), nil
	}
}

func testAccTPMAuthRoleMountOnlyConfig(mount string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "tpm" {
  type = "tpm"
  path = %q
}
`, mount)
}

func testAccTPMAuthRoleWithTPMIDConfig(mount, roleName, tpmName string) string {
	return fmt.Sprintf(`
%s

resource "vault_identity_tpm" "test" {
  name = %q
  tpm_ek_public_key = <<EOT
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAu5YIWbS0JtKO6mgJrmMa24RHTACn2BF3OOd9N7BxtIA=
-----END PUBLIC KEY-----
EOT
}

resource "vault_tpm_auth_backend_role" "test" {
  mount   = vault_auth_backend.tpm.path
  name    = %q
  tpm_ids = [vault_identity_tpm.test.tpm_id]
}
`, testAccTPMAuthRoleMountOnlyConfig(mount), tpmName, roleName)
}

func testAccTPMAuthRoleWithTPMIDAndTPMGroupIDConfig(mount, roleName, tpmName string) string {
	return fmt.Sprintf(`
%s

resource "vault_identity_tpm" "test" {
  name = %q
  tpm_ek_public_key = <<EOT
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAu5YIWbS0JtKO6mgJrmMa24RHTACn2BF3OOd9N7BxtIA=
-----END PUBLIC KEY-----
EOT
}

resource "vault_identity_tpm_group" "test" {
  name = %q
}

resource "vault_tpm_auth_backend_role" "test" {
  mount        = vault_auth_backend.tpm.path
  name         = %q
  cert_ttl     = "24h"
  tpm_ids      = [vault_identity_tpm.test.tpm_id]
  tpmgroup_ids = [vault_identity_tpm_group.test.tpm_group_id]
}
`, testAccTPMAuthRoleMountOnlyConfig(mount), tpmName, roleName, roleName)
}

func testAccTPMAuthRoleWithTokenFieldsConfig(mount, roleName, tpmName string) string {
	return fmt.Sprintf(`
%s

resource "vault_identity_tpm" "test" {
  name = %q
  tpm_ek_public_key = <<EOT
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAu5YIWbS0JtKO6mgJrmMa24RHTACn2BF3OOd9N7BxtIA=
-----END PUBLIC KEY-----
EOT
}

resource "vault_tpm_auth_backend_role" "test" {
  mount   = vault_auth_backend.tpm.path
  name    = %q
  tpm_ids = [vault_identity_tpm.test.tpm_id]

  token_ttl      = 3600
  token_max_ttl  = 7200
  token_policies = ["policy-a", "policy-b"]
  token_type     = "service"
}
`, testAccTPMAuthRoleMountOnlyConfig(mount), tpmName, roleName)
}

func testAccTPMAuthRoleNamespaceConfig(ns, mount, roleName, tpmName string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = %q
}

resource "vault_auth_backend" "tpm" {
  type      = "tpm"
  path      = %q
  namespace = vault_namespace.test.path
}

resource "vault_identity_tpm" "test" {
  namespace = vault_namespace.test.path
  name      = %q
  tpm_ek_public_key = <<EOT
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAu5YIWbS0JtKO6mgJrmMa24RHTACn2BF3OOd9N7BxtIA=
-----END PUBLIC KEY-----
EOT
}

resource "vault_tpm_auth_backend_role" "test" {
  namespace = vault_namespace.test.path
  mount     = vault_auth_backend.tpm.path
  name      = %q
  tpm_ids   = [vault_identity_tpm.test.tpm_id]
}
`, ns, mount, tpmName, roleName)
}
