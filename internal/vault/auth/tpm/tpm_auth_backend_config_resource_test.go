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

// TestAccTPMAuthBackendConfig validates the complete lifecycle of the TPM auth
// backend config resource:
//   - Step 1: Create with only mount set to verify Vault-computed defaults
//   - Step 2: Set all three duration fields explicitly
//   - Step 3: Set default_cert_ttl to 0 which should unset the field
//   - Step 4: Import to verify zero drift
func TestAccTPMAuthBackendConfig(t *testing.T) {
	mount := acctest.RandomWithPrefix("tpm-mount")
	resourceName := "vault_tpm_auth_backend_config.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create with only mount path to confirm default behavior.
			{
				Config: testAccTPMAuthBackendConfigConfig(tpmAuthConfigFields{mount: mount}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mount", mount),
					resource.TestCheckResourceAttr(resourceName, "ca_lifetime", "31536000"),   // 1 year in seconds
					resource.TestCheckResourceAttr(resourceName, "ca_soft_expiry", "2592000"), // 30 days in seconds
					resource.TestCheckResourceAttr(resourceName, "default_cert_ttl", "0"),     // not set by user; Vault returns 0
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 2: Set all three duration fields explicitly
			{
				Config: testAccTPMAuthBackendConfigConfig(tpmAuthConfigFields{
					mount:                 mount,
					caLifetime:            7200000,
					caSoftExpiry:          3600,
					defaultCertTTL:        1800,
					specifyDefaultCertTTL: true,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mount", mount),
					resource.TestCheckResourceAttr(resourceName, "ca_lifetime", "7200000"),
					resource.TestCheckResourceAttr(resourceName, "ca_soft_expiry", "3600"),
					resource.TestCheckResourceAttr(resourceName, "default_cert_ttl", "1800"),
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
			// Step 3: Set default_cert_ttl back to 0 to "unset" it
			{
				Config: testAccTPMAuthBackendConfigConfig(tpmAuthConfigFields{
					mount:                 mount,
					caLifetime:            10800000,
					caSoftExpiry:          7200,
					defaultCertTTL:        0,
					specifyDefaultCertTTL: true,
				}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mount", mount),
					resource.TestCheckResourceAttr(resourceName, "ca_lifetime", "10800000"),
					resource.TestCheckResourceAttr(resourceName, "ca_soft_expiry", "7200"),
					resource.TestCheckResourceAttr(resourceName, "default_cert_ttl", "0"),
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
			// Step 4: Import state should result in zero drift
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccTPMAuthBackendConfigImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "mount",
			},
		},
	})
}

func testAccTPMAuthBackendConfigImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		return fmt.Sprintf("auth/%s/config", rs.Primary.Attributes["mount"]), nil
	}
}

type tpmAuthConfigFields struct {
	mount                 string
	caLifetime            int64
	caSoftExpiry          int64
	defaultCertTTL        int64
	specifyDefaultCertTTL bool
}

func testAccTPMAuthBackendConfigConfig(c tpmAuthConfigFields) string {
	body := fmt.Sprintf(`
resource "vault_auth_backend" "tpm" {
  type = "tpm"
  path = %q
}

resource "vault_tpm_auth_backend_config" "test" {
  mount = vault_auth_backend.tpm.path
`, c.mount)

	if c.caLifetime != 0 {
		body += fmt.Sprintf("  ca_lifetime      = %d\n", c.caLifetime)
	}
	if c.caSoftExpiry != 0 {
		body += fmt.Sprintf("  ca_soft_expiry   = %d\n", c.caSoftExpiry)
	}
	if c.specifyDefaultCertTTL {
		body += fmt.Sprintf("  default_cert_ttl = %d\n", c.defaultCertTTL)
	}

	body += "}\n"
	return body
}
