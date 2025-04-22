// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func randomQuotaRateString() string {
	whole := float64(acctest.RandIntRange(1000, 2000))
	decimal := float64(acctest.RandIntRange(0, 100)) / 100

	rateLimit := fmt.Sprintf("%.1f", whole+decimal)
	// Vault returns floats with trailing zeros trimmed
	return strings.TrimRight(strings.TrimRight(rateLimit, "0"), ".")
}

func TestQuotaRateLimit(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test")
	rateLimit := randomQuotaRateString()
	newRateLimit := randomQuotaRateString()
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testQuotaRateLimitCheckDestroy([]string{rateLimit, newRateLimit}),
		Steps: []resource.TestStep{
			{
				Config: testQuotaRateLimitConfig(name, "", rateLimit, 1, 0),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "name", name),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "path", ""),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "rate", rateLimit),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "interval", "1"),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "block_interval", "0"),
				),
			},
			{
				Config: testQuotaRateLimitConfig(name, "", newRateLimit, 60, 120),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "name", name),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "path", ""),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "rate", newRateLimit),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "interval", "60"),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "block_interval", "120"),
				),
			},
			{
				Config: testQuotaRateLimitConfig(name, "sys/", newRateLimit, 60, 120),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "name", name),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "path", "sys/"),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "rate", newRateLimit),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "interval", "60"),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "block_interval", "120"),
				),
			},
		},
	})
}

func TestQuotaRateLimitWithRole(t *testing.T) {
	name := acctest.RandomWithPrefix("rate-limit")
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")
	rateLimit := randomQuotaRateString()
	newRateLimit := randomQuotaRateString()
	resourceName := "vault_quota_rate_limit.foobar"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		},
		CheckDestroy: resource.ComposeTestCheckFunc(
			testQuotaRateLimitCheckDestroy([]string{rateLimit}),
			testAccCheckAppRoleAuthBackendRoleDestroy,
		),
		Steps: []resource.TestStep{
			{
				Config: testQuotaRateLimitWithRoleConfig(backend, role, name, rateLimit, 1, 0),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("auth/%s/", backend)),
					resource.TestCheckResourceAttr(resourceName, "rate", rateLimit),
					resource.TestCheckResourceAttr(resourceName, "interval", "1"),
					resource.TestCheckResourceAttr(resourceName, "block_interval", "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRole, role),
				),
			},
			{
				Config: testQuotaRateLimitWithRoleConfig(backend, role, name, newRateLimit, 1, 0),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("auth/%s/", backend)),
					resource.TestCheckResourceAttr(resourceName, "rate", newRateLimit),
					resource.TestCheckResourceAttr(resourceName, "interval", "1"),
					resource.TestCheckResourceAttr(resourceName, "block_interval", "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRole, role),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

func TestQuotaRateLimitInheritable(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test")
	rateLimit := randomQuotaRateString()
	newRateLimit := randomQuotaRateString()
	inheritable := true
	resourceName := "vault_quota_rate_limit.foobar"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		},
		CheckDestroy: testQuotaRateLimitCheckDestroy([]string{rateLimit, newRateLimit}),
		Steps: []resource.TestStep{
			{
				Config: testQuotaRateLimitConfigInheritable(name, "", rateLimit, 1, 0, inheritable),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "path", ""),
					resource.TestCheckResourceAttr(resourceName, "rate", rateLimit),
					resource.TestCheckResourceAttr(resourceName, "interval", "1"),
					resource.TestCheckResourceAttr(resourceName, "block_interval", "0"),
					resource.TestCheckResourceAttr(resourceName, "inheritable", fmt.Sprintf("%t", inheritable)),
				),
			},
			{
				Config: testQuotaRateLimitConfigInheritable(name, "", newRateLimit, 60, 120, inheritable),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "path", ""),
					resource.TestCheckResourceAttr(resourceName, "rate", newRateLimit),
					resource.TestCheckResourceAttr(resourceName, "interval", "60"),
					resource.TestCheckResourceAttr(resourceName, "block_interval", "120"),
					resource.TestCheckResourceAttr(resourceName, "inheritable", fmt.Sprintf("%t", inheritable)),
				),
			},
			{
				Config: testQuotaRateLimitConfigInheritable(name, "", newRateLimit, 60, 120, inheritable),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "path", ""),
					resource.TestCheckResourceAttr(resourceName, "rate", newRateLimit),
					resource.TestCheckResourceAttr(resourceName, "interval", "60"),
					resource.TestCheckResourceAttr(resourceName, "block_interval", "120"),
					resource.TestCheckResourceAttr(resourceName, "inheritable", fmt.Sprintf("%t", inheritable)),
				),
			},
		},
	})
}

func TestQuotaRateLimitWithNamespaceInheritable(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test")
	ns := "ns-" + name
	rateLimit := randomQuotaRateString()
	newRateLimit := randomQuotaRateString()
	inheritable := true
	resourceName := "vault_quota_rate_limit.foobar"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		},
		CheckDestroy: testQuotaRateLimitCheckDestroy([]string{rateLimit, newRateLimit}),
		Steps: []resource.TestStep{
			{
				Config: testQuotaRateLimitWithNamespaceConfigInheritable(ns, name, "", rateLimit, 1, 0, inheritable),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "path", ns+"/"),
					resource.TestCheckResourceAttr(resourceName, "rate", rateLimit),
					resource.TestCheckResourceAttr(resourceName, "interval", "1"),
					resource.TestCheckResourceAttr(resourceName, "block_interval", "0"),
					resource.TestCheckResourceAttr(resourceName, "inheritable", fmt.Sprintf("%t", inheritable)),
				),
			},
			{
				Config: testQuotaRateLimitWithNamespaceConfigInheritable(ns, name, "", newRateLimit, 60, 120, inheritable),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "path", ns+"/"),
					resource.TestCheckResourceAttr(resourceName, "rate", newRateLimit),
					resource.TestCheckResourceAttr(resourceName, "interval", "60"),
					resource.TestCheckResourceAttr(resourceName, "block_interval", "120"),
					resource.TestCheckResourceAttr(resourceName, "inheritable", fmt.Sprintf("%t", inheritable)),
				),
			},
			{
				Config: testQuotaRateLimitWithNamespaceConfigInheritable(ns, name, "", newRateLimit, 60, 120, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "path", ns+"/"),
					resource.TestCheckResourceAttr(resourceName, "rate", newRateLimit),
					resource.TestCheckResourceAttr(resourceName, "interval", "60"),
					resource.TestCheckResourceAttr(resourceName, "block_interval", "120"),
					resource.TestCheckResourceAttr(resourceName, "inheritable", "false"),
				),
			},
		},
	})
}

func testQuotaRateLimitCheckDestroy(rateLimits []string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

		for _, name := range rateLimits {
			resp, err := client.Logical().Read(quotaRateLimitPath(name))
			if err != nil {
				return err
			}

			if resp != nil {
				return fmt.Errorf("Resource Quota Rate Limit %s still exists", name)
			}
		}

		return nil
	}
}

// Caution: Don't set test rate values too low or other tests running concurrently might fail
func testQuotaRateLimitConfig(name, path, rate string, interval, blockInterval int) string {
	return fmt.Sprintf(`
resource "vault_quota_rate_limit" "foobar" {
  name = "%s"
  path = "%s"
  rate = %s
  interval = %d
  block_interval = %d
}
`, name, path, rate, interval, blockInterval)
}

func testQuotaRateLimitWithRoleConfig(backend, role, name, rate string, interval, blockInterval int) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "%s"
}

resource "vault_approle_auth_backend_role" "role" {
  backend = vault_auth_backend.approle.path
  role_name = "%s"
  token_policies = ["default", "dev", "prod"]
}

resource "vault_quota_rate_limit" "foobar" {
  name = "%s"
  path = "auth/${vault_auth_backend.approle.path}/"
  role = vault_approle_auth_backend_role.role.role_name
  rate = %s
  interval = %d
  block_interval = %d
}
`, backend, role, name, rate, interval, blockInterval)
}

func testQuotaRateLimitConfigInheritable(name, path, rate string, interval, blockInterval int, inheritable bool) string {
	return fmt.Sprintf(`
resource "vault_quota_rate_limit" "foobar" {
  name = "%s"
  path = "%s"
  rate = %s
  interval = %d
  block_interval = %d
  inheritable  = %t
}
`, name, path, rate, interval, blockInterval, inheritable)
}

func testQuotaRateLimitWithNamespaceConfigInheritable(ns, name, path, rate string, interval, blockInterval int, inheritable bool) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
	path = "%s"
	}

resource "vault_quota_rate_limit" "foobar" {
  name = "%s"
  path = "${vault_namespace.test.path}/%s"
  rate = %s
  interval = %d
  block_interval = %d
  inheritable  = %t
}
`, ns, name, path, rate, interval, blockInterval, inheritable)
}
