// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testQuotaRateLimitCheckDestroy([]string{rateLimit, newRateLimit}),
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			testutil.SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			testutil.SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
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
			// TODO: fix the inheritable field to work with tf import
			// testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

func TestQuotaRateLimitGroupBy(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test")
	ns := "ns-" + name
	rateLimit := randomQuotaRateString()
	newRateLimit := randomQuotaRateString()
	resourceName := "vault_quota_rate_limit.foobar"

	getConfig := func(resourceAddon string) string {
		return fmt.Sprintf(`
resource "vault_namespace" "test" {
	path = "%s"
	}

resource "vault_quota_rate_limit" "foobar" {
  name = "%s"
  path = "${vault_namespace.test.path}/"
  rate = 10
  %s
}
`, ns, name, resourceAddon)
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			testutil.SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion120)
		},
		CheckDestroy: testQuotaRateLimitCheckDestroy([]string{rateLimit, newRateLimit}),
		Steps: []resource.TestStep{
			{
				// RLQ default to group_by = "ip". secondary_rate for unsupported group_by values is 0
				Config: getConfig(""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "group_by", "ip"),
					resource.TestCheckResourceAttr(resourceName, "secondary_rate", "0"),
				),
			},
			{
				// secondary_rate is only allowed for entity-based group_by values
				Config:      getConfig("secondary_rate = 5"),
				ExpectError: regexp.MustCompile(`secondary_rate can only be set if group_by is set to 'entity_then_ip' or 'entity_then_none'`),
			},
			{
				// group_by cannot be explicitly set to an empty string, the API allows it but the provider does not
				Config:      getConfig("group_by = \"\""),
				ExpectError: regexp.MustCompile(`Error: expected group_by to be one of`),
			},
			{
				// group_by can be explicitly set to "ip", secondary_rate remains 0
				Config: getConfig("group_by = \"ip\""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "group_by", "ip"),
					resource.TestCheckResourceAttr(resourceName, "secondary_rate", "0"),
				),
			},
			{
				// group_by can be explicitly set to "entity_then_ip", secondary_rate can then be set
				Config: getConfig("group_by = \"entity_then_ip\"\nsecondary_rate = 5"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "group_by", "entity_then_ip"),
					resource.TestCheckResourceAttr(resourceName, "secondary_rate", "5"),
				),
			},
			{
				Config: getConfig("group_by = \"entity_then_none\""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "group_by", "entity_then_none"),
					// this is actually an issue with the TF SDKv2, it does not distinguish between unset and zero values
					// so even tho ideally we'd like to have secondary_rate unset, defaulting back to rate which is 10,
					// it will actually remain 5 because that value is still in the state. If we instead used the same
					// approach as the inheritable field then TF import wouldn't work with hese new fields.
					resource.TestCheckResourceAttr(resourceName, "secondary_rate", "5"),
				),
			},
			{
				// we actually need to explicitly set secondary_rate to 0, otherwise the old value of 5 will remain in
				// the state which causes the validation to fail because secondary_rate is not allowed for group_by = "none"
				Config: getConfig("group_by = \"none\"\nsecondary_rate = 0"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "group_by", "none"),
					resource.TestCheckResourceAttr(resourceName, "secondary_rate", "0"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
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
