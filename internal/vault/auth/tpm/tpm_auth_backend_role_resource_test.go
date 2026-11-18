// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package tpm_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccTPMAuthRole validates the complete lifecycle of vault_tpm_auth_backend_role with IDs:
//   - Step 1: Validator rejects config with neither tpm_ids/tpm_names nor tpmgroup_ids/tpmgroup_names
//   - Step 2: Create with only required fields to verify Vault-computed defaults
//     (display_name defaults to role name, cert_ttl=0, token_type="default")
//   - Step 3: Set cert_ttl explicitly and add tpmgroup_ids
//   - Step 4: Set cert_ttl back to 0 to "unset" it (Vault always returns a value)
//   - Step 5: Set all token fields to verify token field round-trip
//   - Step 6: Clear token fields and revert to minimal config, confirming defaults are restored
//   - Step 7: Import to verify zero drift
//   - Step 8: Destroy the role (keep the mount)
func TestAccTPMAuthRole(t *testing.T) {
	mount := acctest.RandomWithPrefix("tpm-mount")
	roleName := acctest.RandomWithPrefix("tpm-role")
	tpmName := acctest.RandomWithPrefix("tpm")
	groupName := acctest.RandomWithPrefix("tpm-grp")
	publicKey := testutil.GenerateRSAPublicKeyPEM(t, 2048)
	resourceName := "vault_tpm_auth_backend_role.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Validator rejects when no TPM IDs or names are set.
			{
				Config: testAccTPMAuthRoleConfig(tpmRoleFields{
					mount:     mount,
					roleName:  roleName,
					tpmName:   tpmName,
					publicKey: publicKey,
				}),
				ExpectError: regexp.MustCompile(`(?s)At least one attribute out of \[tpm_ids,tpm_names,tpmgroup_ids,tpmgroup_names\].*must be specified`),
			},
			// Step 2: Create with only required fields. Either tpm_ids or tpmgroup_ids must be set.
			// Verifies that Vault-computed defaults are read back correctly:
			//   - display_name defaults to the role name
			//   - cert_ttl is 0 (Vault always returns a value; 0 means "use backend default")
			//   - token_type defaults to "default"
			{
				Config: testAccTPMAuthRoleConfig(tpmRoleFields{
					mount:     mount,
					roleName:  roleName,
					tpmName:   tpmName,
					publicKey: publicKey,
					useTPMIDs: true,
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
			// Step 3: Set cert_ttl explicitly and add tpmgroup_ids.
			// Verifies an in-place update (no replace) and that both ID sets are reflected.
			{
				Config: testAccTPMAuthRoleConfig(tpmRoleFields{
					mount:          mount,
					roleName:       roleName,
					tpmName:        tpmName,
					publicKey:      publicKey,
					groupName:      groupName,
					useTPMIDs:      true,
					useTPMGroupIDs: true,
					certTTL:        ptr(int64(86400)),
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
			// Step 4: Set cert_ttl back to 0 explicitly (Vault always returns a value; 0 means
			// "use backend default") and clear tpm_ids by configuring only tpmgroup_ids.
			// Verifies that omitting tpm_ids unsets it in Vault.
			{
				Config: testAccTPMAuthRoleConfig(tpmRoleFields{
					mount:          mount,
					roleName:       roleName,
					tpmName:        tpmName,
					publicKey:      publicKey,
					groupName:      groupName,
					useTPMGroupIDs: true,
					certTTL:        ptr(int64(0)),
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mount", mount),
					resource.TestCheckResourceAttr(resourceName, "name", roleName),
					resource.TestCheckResourceAttr(resourceName, "cert_ttl", "0"),
					resource.TestCheckResourceAttr(resourceName, "tpm_ids.#", "0"),
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
			// Step 5: Set token fields.
			// Verifies that all standard token fields are written and read back with no drift.
			{
				Config: testAccTPMAuthRoleConfig(tpmRoleFields{
					mount:          mount,
					roleName:       roleName,
					tpmName:        tpmName,
					publicKey:      publicKey,
					groupName:      groupName,
					useTPMGroupIDs: true,
					certTTL:        ptr(int64(86400)),
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
			// Step 6: Revert to minimal config (required fields only).
			// Verifies that clearing optional fields restores Vault defaults with no drift.
			// cert_ttl reverts to 0 (Vault always returns a value).
			{
				Config: testAccTPMAuthRoleConfig(tpmRoleFields{
					mount:     mount,
					roleName:  roleName,
					tpmName:   tpmName,
					publicKey: publicKey,
					useTPMIDs: true,
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
			// Step 7: Import state to verify zero drift.
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccTPMAuthRoleImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "mount",
			},
			// Step 8: Destroy the role (keep the mount).
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
	publicKey := testutil.GenerateRSAPublicKeyPEM(t, 2048)
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
				Config: testAccTPMAuthRoleNamespaceConfig(ns, mount, roleName, tpmName, publicKey),
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

// TestAccTPMAuthRole_names validates vault_tpm_auth_backend_role configured using names:
//   - Step 1: Create role with tpm_names
//   - Step 2: Add tpmgroup_names
//   - Step 3: Switch from names to IDs (in-place update)
//   - Step 4: Import state (verified against the IDs configuration)
//   - Step 5: Switch back from IDs to names (in-place update)
func TestAccTPMAuthRole_names(t *testing.T) {
	mount := acctest.RandomWithPrefix("tpm-mount")
	roleName := acctest.RandomWithPrefix("tpm-role")
	tpmName := acctest.RandomWithPrefix("tpm")
	groupName := acctest.RandomWithPrefix("tpm-grp")
	publicKey := testutil.GenerateRSAPublicKeyPEM(t, 2048)
	resourceName := "vault_tpm_auth_backend_role.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion230)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create with tpm_names.
			{
				Config: testAccTPMAuthRoleConfig(tpmRoleFields{
					mount:       mount,
					roleName:    roleName,
					tpmName:     tpmName,
					publicKey:   publicKey,
					groupName:   groupName,
					useTPMNames: true,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mount", mount),
					resource.TestCheckResourceAttr(resourceName, "name", roleName),
					resource.TestCheckResourceAttr(resourceName, "display_name", roleName),
					resource.TestCheckResourceAttr(resourceName, "tpm_names.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "tpm_names.*", tpmName),
					resource.TestCheckNoResourceAttr(resourceName, "tpm_ids"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 2: Add tpmgroup_names.
			{
				Config: testAccTPMAuthRoleConfig(tpmRoleFields{
					mount:            mount,
					roleName:         roleName,
					tpmName:          tpmName,
					publicKey:        publicKey,
					groupName:        groupName,
					useTPMNames:      true,
					useTPMGroupNames: true,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mount", mount),
					resource.TestCheckResourceAttr(resourceName, "name", roleName),
					resource.TestCheckResourceAttr(resourceName, "tpm_names.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "tpm_names.*", tpmName),
					resource.TestCheckResourceAttr(resourceName, "tpmgroup_names.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "tpmgroup_names.*", groupName),
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
			// Step 3: Switch to tpm_ids and tpmgroup_ids (in-place update).
			{
				Config: testAccTPMAuthRoleConfig(tpmRoleFields{
					mount:          mount,
					roleName:       roleName,
					tpmName:        tpmName,
					publicKey:      publicKey,
					groupName:      groupName,
					useTPMIDs:      true,
					useTPMGroupIDs: true,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mount", mount),
					resource.TestCheckResourceAttr(resourceName, "name", roleName),
					resource.TestCheckResourceAttr(resourceName, "tpm_ids.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "tpmgroup_ids.#", "1"),
					resource.TestCheckNoResourceAttr(resourceName, "tpm_names"),
					resource.TestCheckNoResourceAttr(resourceName, "tpmgroup_names"),
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
			// Step 4: Import state while configured with IDs. On import there is no prior state,
			// so Read always populates the ID attributes (Vault stores only IDs). Importing is
			// therefore verified against the IDs configuration, with no ignored attributes.
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccTPMAuthRoleImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "mount",
			},
			// Step 5: Switch back to tpm_names and tpmgroup_names.
			{
				Config: testAccTPMAuthRoleConfig(tpmRoleFields{
					mount:            mount,
					roleName:         roleName,
					tpmName:          tpmName,
					publicKey:        publicKey,
					groupName:        groupName,
					useTPMNames:      true,
					useTPMGroupNames: true,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mount", mount),
					resource.TestCheckResourceAttr(resourceName, "name", roleName),
					resource.TestCheckResourceAttr(resourceName, "tpm_names.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "tpm_names.*", tpmName),
					resource.TestCheckResourceAttr(resourceName, "tpmgroup_names.#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "tpmgroup_names.*", groupName),
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
		},
	})
}

// TestAccTPMAuthRole_conflicts verifies plan-time validation errors for mutually exclusive
// attributes. No Vault calls are made, so no version or edition gating is needed.
func TestAccTPMAuthRole_conflicts(t *testing.T) {
	mount := acctest.RandomWithPrefix("tpm-mount")
	roleName := acctest.RandomWithPrefix("tpm-role")
	tpmName := acctest.RandomWithPrefix("tpm")
	groupName := acctest.RandomWithPrefix("tpm-grp")
	publicKey := testutil.GenerateRSAPublicKeyPEM(t, 2048)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Reject both tpm_ids and tpm_names.
			{
				Config: testAccTPMAuthRoleConfig(tpmRoleFields{
					mount:       mount,
					roleName:    roleName,
					tpmName:     tpmName,
					publicKey:   publicKey,
					groupName:   groupName,
					useTPMIDs:   true,
					useTPMNames: true,
				}),
				ExpectError: regexp.MustCompile(`(?s)Attribute "(tpm_ids|tpm_names)" cannot be specified when "(tpm_ids|tpm_names)" is.*specified`),
			},
			// Step 2: Reject both tpmgroup_ids and tpmgroup_names.
			{
				Config: testAccTPMAuthRoleConfig(tpmRoleFields{
					mount:            mount,
					roleName:         roleName,
					tpmName:          tpmName,
					publicKey:        publicKey,
					groupName:        groupName,
					useTPMGroupIDs:   true,
					useTPMGroupNames: true,
				}),
				ExpectError: regexp.MustCompile(`(?s)Attribute "(tpmgroup_ids|tpmgroup_names)" cannot be specified when "(tpmgroup_ids|tpmgroup_names)" is.*specified`),
			},
		},
	})
}

func ptr[T any](v T) *T { return &v }

// tpmRoleFields holds all configurable parameters for testAccTPMAuthRoleConfig.
// Only attributes explicitly set to true or non-zero are emitted into the HCL.
type tpmRoleFields struct {
	mount            string
	roleName         string
	tpmName          string
	certTTL          *int64 // nil omits cert_ttl from the HCL; a pointer to 0 emits an explicit 0
	publicKey        string
	groupName        string
	useTPMIDs        bool
	useTPMNames      bool
	useTPMGroupIDs   bool
	useTPMGroupNames bool
	tokenTTL         int64
	tokenMaxTTL      int64
	tokenPolicies    []string
	tokenType        string
}

// testAccTPMAuthRoleConfig renders the full HCL for a vault_tpm_auth_backend_role
// and its dependencies (mount, vault_identity_tpm, optionally vault_identity_tpm_group).
func testAccTPMAuthRoleConfig(f tpmRoleFields) string {
	// Start with the auth backend mount.
	config := testAccTPMAuthRoleMountOnlyConfig(f.mount)

	if f.groupName == "" {
		f.groupName = f.roleName
	}

	// TPM identity resource
	if f.tpmName != "" && f.publicKey != "" {
		config += fmt.Sprintf(`
resource "vault_identity_tpm" "test" {
  name              = %q
  tpm_ek_public_key = %q
}
`, f.tpmName, f.publicKey)
	}

	// TPM group resource (created when groupName is provided and groups are referenced)
	if f.groupName != "" && (f.useTPMGroupIDs || f.useTPMGroupNames) {
		config += fmt.Sprintf(`
resource "vault_identity_tpm_group" "test" {
  name = %q
}
`, f.groupName)
	}

	// Role resource and parameters
	role := fmt.Sprintf(`
resource "vault_tpm_auth_backend_role" "test" {
  mount = vault_auth_backend.tpm.path
  name  = %q
`, f.roleName)

	if f.useTPMIDs {
		role += "  tpm_ids = [vault_identity_tpm.test.tpm_id]\n"
	}
	if f.useTPMNames {
		role += "  tpm_names = [vault_identity_tpm.test.name]\n"
	}
	if f.useTPMGroupIDs {
		role += "  tpmgroup_ids = [vault_identity_tpm_group.test.tpm_group_id]\n"
	}
	if f.useTPMGroupNames {
		role += "  tpmgroup_names = [vault_identity_tpm_group.test.name]\n"
	}
	if f.certTTL != nil {
		role += fmt.Sprintf("  cert_ttl = %d\n", *f.certTTL)
	}
	if f.tokenTTL != 0 {
		role += fmt.Sprintf("  token_ttl = %d\n", f.tokenTTL)
	}
	if f.tokenMaxTTL != 0 {
		role += fmt.Sprintf("  token_max_ttl = %d\n", f.tokenMaxTTL)
	}
	if len(f.tokenPolicies) > 0 {
		role += fmt.Sprintf("  token_policies = %s\n", renderStringSlice(f.tokenPolicies))
	}
	if f.tokenType != "" {
		role += fmt.Sprintf("  token_type = %q\n", f.tokenType)
	}
	role += "}\n"

	return config + role
}

func testAccTPMAuthRoleNamespaceConfig(ns, mount, roleName, tpmName, publicKey string) string {
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
  tpm_ek_public_key = %q
}

resource "vault_tpm_auth_backend_role" "test" {
  namespace = vault_namespace.test.path
  mount     = vault_auth_backend.tpm.path
  name      = %q
  tpm_ids   = [vault_identity_tpm.test.tpm_id]
}
`, ns, mount, tpmName, publicKey, roleName)
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
