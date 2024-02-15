// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestQuotaLeaseCount(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test")
	ns := "ns-" + name
	leaseCount := "1001"
	newLeaseCount := "2001"
	resourceName := "vault_quota_lease_count.foobar"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestEntPreCheck(t) },
		CheckDestroy:      testQuotaLeaseCountCheckDestroy([]string{leaseCount, newLeaseCount}),
		Steps: []resource.TestStep{
			{
				Config: testQuotaLeaseCountConfig(ns, name, "", leaseCount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, ns+"/"),
					resource.TestCheckResourceAttr(resourceName, "max_leases", leaseCount),
				),
			},
			{
				Config: testQuotaLeaseCountConfig(ns, name, "", newLeaseCount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, ns+"/"),
					resource.TestCheckResourceAttr(resourceName, "max_leases", newLeaseCount),
				),
			},
			{
				Config: testQuotaLeaseCountConfig(ns, name, "sys/", newLeaseCount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, ns+"/sys/"),
					resource.TestCheckResourceAttr(resourceName, "max_leases", newLeaseCount),
				),
			},
		},
	})
}

func TestQuotaLeaseCountWithRole(t *testing.T) {
	name := acctest.RandomWithPrefix("lease-count")
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")
	leaseCount := "1001"
	newLeaseCount := "2001"
	resourceName := "vault_quota_lease_count.foobar"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		},
		CheckDestroy: resource.ComposeTestCheckFunc(
			testQuotaLeaseCountCheckDestroy([]string{leaseCount, newLeaseCount}),
			testAccCheckAppRoleAuthBackendRoleDestroy,
		),
		Steps: []resource.TestStep{
			{
				Config: testQuotaLeaseCountWithRoleConfig(backend, role, name, leaseCount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("auth/%s/", backend)),
					resource.TestCheckResourceAttr(resourceName, "max_leases", leaseCount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRole, role),
				),
			},
			{
				Config: testQuotaLeaseCountWithRoleConfig(backend, role, name, newLeaseCount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("auth/%s/", backend)),
					resource.TestCheckResourceAttr(resourceName, "max_leases", newLeaseCount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRole, role),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

func testQuotaLeaseCountCheckDestroy(leaseCounts []string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

		for _, name := range leaseCounts {
			resp, err := client.Logical().Read(quotaLeaseCountPath(name))
			if err != nil {
				return err
			}

			if resp != nil {
				return fmt.Errorf("Resource Quota Lease Count %s still exists", name)
			}
		}

		return nil
	}
}

// Caution: Don't set test max_leases values too low or other tests running concurrently might fail
func testQuotaLeaseCountConfig(ns, name, path, maxLeases string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = "%s"
}

resource "vault_quota_lease_count" "foobar" {
  name       = "%s"
  path       = "${vault_namespace.test.path}/%s"
  max_leases = %s
}
`, ns, name, path, maxLeases)
}

func testQuotaLeaseCountWithRoleConfig(backend, role, name, maxLeases string) string {
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

resource "vault_quota_lease_count" "foobar" {
  name = "%s"
  path = "auth/${vault_auth_backend.approle.path}/"
  role = vault_approle_auth_backend_role.role.role_name
  max_leases = %s
}
`, backend, role, name, maxLeases)
}
