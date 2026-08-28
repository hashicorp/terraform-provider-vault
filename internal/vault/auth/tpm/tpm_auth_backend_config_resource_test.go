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
			{
				Config: testAccTPMAuthBackendConfigConfig(mount, "2000h", "1h", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mount", mount),
					resource.TestCheckResourceAttr(resourceName, "ca_lifetime", "2000h"),
					resource.TestCheckResourceAttr(resourceName, "ca_soft_expiry", "1h"),
					resource.TestCheckNoResourceAttr(resourceName, "default_cert_ttl"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				Config: testAccTPMAuthBackendConfigConfig(mount, "3000h", "2h", "30m"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mount", mount),
					resource.TestCheckResourceAttr(resourceName, "ca_lifetime", "3000h"),
					resource.TestCheckResourceAttr(resourceName, "ca_soft_expiry", "2h"),
					resource.TestCheckResourceAttr(resourceName, "default_cert_ttl", "30m"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 3: Import state.
			// ca_lifetime, ca_soft_expiry, and default_cert_ttl are ignored because
			// Vault normalizes duration strings on read (e.g. "3000h" → "10800000s").
			// resolveDurationFieldState preserves the user-supplied format when prior
			// state exists, but import starts with null state so the raw API value is
			// stored instead. The values are functionally equivalent.
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccTPMAuthBackendConfigImportStateIdFunc(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "mount",
				ImportStateVerifyIgnore:              []string{"ca_lifetime", "ca_soft_expiry", "default_cert_ttl"},
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

func testAccTPMAuthBackendConfigConfig(mount, caLifetime, caSoftExpiry, defaultCertTTL string) string {
	defaultCertTTLAttr := ""
	if defaultCertTTL != "" {
		defaultCertTTLAttr = fmt.Sprintf("\n  default_cert_ttl = %q", defaultCertTTL)
	}

	return fmt.Sprintf(`
resource "vault_auth_backend" "tpm" {
  type = "tpm"
  path = %q
}

resource "vault_tpm_auth_backend_config" "test" {
  mount          = vault_auth_backend.tpm.path
  ca_lifetime    = %q
  ca_soft_expiry = %q%s
}
`, mount, caLifetime, caSoftExpiry, defaultCertTTLAttr)
}
