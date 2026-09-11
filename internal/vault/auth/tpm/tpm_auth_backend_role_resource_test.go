// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package tpm_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

// TestAccTPMAuthRole validates the complete lifecycle of vault_tpm_auth_backend_role:
//   - Step 1: Create with only required fields to verify Vault-computed defaults
//     (display_name defaults to role name, cert_ttl=0, token_type="default")
//   - Step 2: Set cert_ttl explicitly and add tpmgroup_ids
//   - Step 3: Set cert_ttl back to 0 to "unset" it (Vault always returns a value)
//   - Step 4: Set all token fields to verify token field round-trip
//   - Step 5: Clear token fields and revert to minimal config, confirming defaults are restored
//   - Step 6: Import to verify zero drift
//   - Step 7: Destroy the role (keep the mount)
func TestAccTPMAuthRole(t *testing.T) {
	mount := acctest.RandomWithPrefix("tpm-mount")
	roleName := acctest.RandomWithPrefix("tpm-role")
	tpmName := acctest.RandomWithPrefix("tpm")
	resourceName := "vault_tpm_auth_backend_role.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create with only required fields.
			// Verifies that Vault-computed defaults are read back correctly:
			//   - display_name defaults to the role name
			//   - cert_ttl is 0 (Vault always returns a value; 0 means "use backend default")
			//   - token_type defaults to "default"
			{
				Config: testAccTPMAuthRoleConfig(tpmRoleFields{
					mount:    mount,
					roleName: roleName,
					tpmName:  tpmName,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mount", mount),
					resource.TestCheckResourceAttr(resourceName, "name", roleName),
					resource.TestCheckResourceAttr(resourceName, "display_name", roleName),
					resource.TestCheckResourceAttr(resourceName, "cert_ttl", "0"),
					resource.TestCheckResourceAttr(resourceName, "tpm_ids.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "tpmgroup_ids.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "token_type", "default"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 2: Set cert_ttl explicitly and add a tpmgroup_ids binding.
			// Verifies an in-place update (no replace) and that both ID sets are reflected.
			{
				Config: testAccTPMAuthRoleConfig(tpmRoleFields{
					mount:          mount,
					roleName:       roleName,
					tpmName:        tpmName,
					certTTL:        86400,
					specifyCertTTL: true,
					withTPMGroupID: true,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mount", mount),
					resource.TestCheckResourceAttr(resourceName, "name", roleName),
					resource.TestCheckResourceAttr(resourceName, "cert_ttl", "86400"),
					resource.TestCheckResourceAttr(resourceName, "tpm_ids.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "tpmgroup_ids.#", "1"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 3: Set cert_ttl back to 0 to "unset" it explicitly.
			// Vault always returns a value; 0 means "use backend default".
			{
				Config: testAccTPMAuthRoleConfig(tpmRoleFields{
					mount:          mount,
					roleName:       roleName,
					tpmName:        tpmName,
					certTTL:        0,
					specifyCertTTL: true,
					withTPMGroupID: true,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mount", mount),
					resource.TestCheckResourceAttr(resourceName, "name", roleName),
					resource.TestCheckResourceAttr(resourceName, "cert_ttl", "0"),
					resource.TestCheckResourceAttr(resourceName, "tpm_ids.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "tpmgroup_ids.#", "1"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 4: Set token fields.
			// Verifies that all standard token fields are written and read back with no drift.
			{
				Config: testAccTPMAuthRoleConfig(tpmRoleFields{
					mount:          mount,
					roleName:       roleName,
					tpmName:        tpmName,
					certTTL:        86400,
					specifyCertTTL: true,
					withTPMGroupID: true,
					tokenTTL:       3600,
					tokenMaxTTL:    7200,
					tokenPolicies:  []string{"policy-a", "policy-b"},
					tokenType:      "service",
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "token_ttl", "3600"),
					resource.TestCheckResourceAttr(resourceName, "token_max_ttl", "7200"),
					resource.TestCheckResourceAttr(resourceName, "token_policies.#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, "token_policies.*", "policy-a"),
					resource.TestCheckTypeSetElemAttr(resourceName, "token_policies.*", "policy-b"),
					resource.TestCheckResourceAttr(resourceName, "token_type", "service"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 5: Revert to minimal config (required fields only).
			// Verifies that clearing optional fields restores Vault defaults with no drift.
			// cert_ttl reverts to 0 (Vault always returns a value).
			{
				Config: testAccTPMAuthRoleConfig(tpmRoleFields{
					mount:    mount,
					roleName: roleName,
					tpmName:  tpmName,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mount", mount),
					resource.TestCheckResourceAttr(resourceName, "name", roleName),
					resource.TestCheckResourceAttr(resourceName, "cert_ttl", "0"),
					resource.TestCheckNoResourceAttr(resourceName, "token_ttl"),
					resource.TestCheckNoResourceAttr(resourceName, "token_max_ttl"),
					resource.TestCheckNoResourceAttr(resourceName, "token_policies"),
					resource.TestCheckResourceAttr(resourceName, "token_type", "default"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 6: Import state to verify zero drift.
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccTPMAuthRoleImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "mount",
			},
			// Step 7: Destroy the role (keep the mount).
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

	resource.ParallelTest(t, resource.TestCase{
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

// tpmRoleFields holds all configurable parameters for testAccTPMAuthRoleConfig.
// Zero-value fields are omitted from the rendered HCL.
type tpmRoleFields struct {
	mount          string
	roleName       string
	tpmName        string
	certTTL        int64
	specifyCertTTL bool
	withTPMGroupID bool
	tokenTTL       int64
	tokenMaxTTL    int64
	tokenPolicies  []string
	tokenType      string
}

// testAccTPMAuthRoleConfig renders the full HCL for a vault_tpm_auth_backend_role
// and its dependencies (mount, vault_identity_tpm, optionally vault_identity_tpm_group).
// Only fields explicitly set via the fields struct are emitted.
func testAccTPMAuthRoleConfig(f tpmRoleFields) string {
	body := testAccTPMAuthRoleMountOnlyConfig(f.mount)

	body += fmt.Sprintf(`
resource "vault_identity_tpm" "test" {
  name = %q
  tpm_ek_public_key = <<EOT
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAu5YIWbS0JtKO6mgJrmMa24RHTACn2BF3OOd9N7BxtIA=
-----END PUBLIC KEY-----
EOT
}
`, f.tpmName)

	if f.withTPMGroupID {
		body += fmt.Sprintf(`
resource "vault_identity_tpm_group" "test" {
  name = %q
}
`, f.roleName)
	}

	body += fmt.Sprintf(`
resource "vault_tpm_auth_backend_role" "test" {
  mount   = vault_auth_backend.tpm.path
  name    = %q
  tpm_ids = [vault_identity_tpm.test.tpm_id]
`, f.roleName)

	if f.withTPMGroupID {
		body += "  tpmgroup_ids = [vault_identity_tpm_group.test.tpm_group_id]\n"
	}
	if f.specifyCertTTL {
		body += fmt.Sprintf("  cert_ttl = %d\n", f.certTTL)
	}
	if f.tokenTTL != 0 {
		body += fmt.Sprintf("  token_ttl = %d\n", f.tokenTTL)
	}
	if f.tokenMaxTTL != 0 {
		body += fmt.Sprintf("  token_max_ttl = %d\n", f.tokenMaxTTL)
	}
	if len(f.tokenPolicies) > 0 {
		body += fmt.Sprintf("  token_policies = %s\n", renderStringSlice(f.tokenPolicies))
	}
	if f.tokenType != "" {
		body += fmt.Sprintf("  token_type = %q\n", f.tokenType)
	}

	body += "}\n"
	return body
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

// renderStringSlice renders a Go string slice as an HCL list literal,
// e.g. []string{"a", "b"} → `["a", "b"]`.
func renderStringSlice(ss []string) string {
	quoted := make([]string, len(ss))
	for i, s := range ss {
		quoted[i] = fmt.Sprintf("%q", s)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}
