// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		CheckDestroy:             testQuotaLeaseCountCheckDestroy([]string{leaseCount, newLeaseCount}),
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

func TestQuotaLeaseCountRoot(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test")
	leaseCount := "1001"
	newLeaseCount := "2001"
	resourceName := "vault_quota_lease_count.foobar"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			testutil.SkipIfAPIVersionGTE(t, testProvider.Meta(), provider.VaultVersion116)
		},
		CheckDestroy: testQuotaLeaseCountCheckDestroy([]string{leaseCount, newLeaseCount}),
		Steps: []resource.TestStep{
			{
				Config: testQuotaLeaseCountConfigRootPath(name, "", newLeaseCount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "path", ""),
					resource.TestCheckResourceAttr(resourceName, "max_leases", newLeaseCount),
				),
			},
		},
	})
}

func TestQuotaLeaseCountWithRole(t *testing.T) {
	name := acctest.RandomWithPrefix("lease-count")
	ns := "ns-" + name
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")
	leaseCount := "1001"
	newLeaseCount := "2001"
	resourceName := "vault_quota_lease_count.foobar"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			testutil.SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		},
		CheckDestroy: resource.ComposeTestCheckFunc(
			testQuotaLeaseCountCheckDestroy([]string{leaseCount, newLeaseCount}),
			testAccCheckAppRoleAuthBackendRoleDestroy,
		),
		Steps: []resource.TestStep{
			{
				Config: testQuotaLeaseCountWithRoleConfig(ns, backend, role, name, leaseCount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/auth/%s/", ns, backend)),
					resource.TestCheckResourceAttr(resourceName, "max_leases", leaseCount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRole, role),
				),
			},
			{
				Config: testQuotaLeaseCountWithRoleConfig(ns, backend, role, name, newLeaseCount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/auth/%s/", ns, backend)),
					resource.TestCheckResourceAttr(resourceName, "max_leases", newLeaseCount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRole, role),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

func TestQuotaLeaseCountInheritable(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test")
	ns := "ns-" + name
	leaseCount := "1001"
	newLeaseCount := "2001"
	inheritable := false
	resourceName := "vault_quota_lease_count.foobar"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			testutil.SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		},
		CheckDestroy: testQuotaLeaseCountCheckDestroy([]string{leaseCount, newLeaseCount}),
		Steps: []resource.TestStep{
			{
				Config: testQuotaLeaseCountConfigInheritable(ns, name, "", leaseCount, inheritable),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, ns+"/"),
					resource.TestCheckResourceAttr(resourceName, "max_leases", leaseCount),
					resource.TestCheckResourceAttr(resourceName, "inheritable", fmt.Sprintf("%t", inheritable)),
				),
			},
			{
				Config: testQuotaLeaseCountConfigInheritable(ns, name, "", newLeaseCount, inheritable),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, ns+"/"),
					resource.TestCheckResourceAttr(resourceName, "max_leases", newLeaseCount),
					resource.TestCheckResourceAttr(resourceName, "inheritable", fmt.Sprintf("%t", inheritable)),
				),
			},
			{
				Config: testQuotaLeaseCountConfigInheritable(ns, name, "sys/", newLeaseCount, inheritable),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, ns+"/sys/"),
					resource.TestCheckResourceAttr(resourceName, "max_leases", newLeaseCount),
					resource.TestCheckResourceAttr(resourceName, "inheritable", fmt.Sprintf("%t", inheritable)),
				),
			},
			{
				Config: testQuotaLeaseCountConfigInheritable(ns, name, "", newLeaseCount, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, ns+"/"),
					resource.TestCheckResourceAttr(resourceName, "max_leases", newLeaseCount),
					resource.TestCheckResourceAttr(resourceName, "inheritable", "true"),
				),
			},
		},
	})
}

func TestQuotaLeaseCountWithRoleInheritable(t *testing.T) {
	name := acctest.RandomWithPrefix("lease-count")
	ns := "ns-" + name
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")
	leaseCount := "1001"
	newLeaseCount := "2001"
	inheritable := false
	resourceName := "vault_quota_lease_count.foobar"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			testutil.SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		},
		CheckDestroy: resource.ComposeTestCheckFunc(
			testQuotaLeaseCountCheckDestroy([]string{leaseCount, newLeaseCount}),
			testAccCheckAppRoleAuthBackendRoleDestroy,
		),
		Steps: []resource.TestStep{
			{
				Config: testQuotaLeaseCountWithRoleConfigInheritable(ns, backend, role, name, leaseCount, inheritable),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/auth/%s/", ns, backend)),
					resource.TestCheckResourceAttr(resourceName, "max_leases", leaseCount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRole, role),
					resource.TestCheckResourceAttr(resourceName, "inheritable", fmt.Sprintf("%t", inheritable)),
				),
			},
			{
				Config: testQuotaLeaseCountWithRoleConfigInheritable(ns, backend, role, name, newLeaseCount, inheritable),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/auth/%s/", ns, backend)),
					resource.TestCheckResourceAttr(resourceName, "max_leases", newLeaseCount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRole, role),
					resource.TestCheckResourceAttr(resourceName, "inheritable", fmt.Sprintf("%t", inheritable)),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"inheritable"},
			},
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

func testQuotaLeaseCountConfigRootPath(name, path, maxLeases string) string {
	return fmt.Sprintf(`
resource "vault_quota_lease_count" "foobar" {
  name       = "%s"
  path       = "%s"
  max_leases = %s
}
`, name, path, maxLeases)
}

func testQuotaLeaseCountWithRoleConfig(ns, backend, role, name, maxLeases string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
	path = "%s"
	}

resource "vault_auth_backend" "approle" {
  namespace      = vault_namespace.test.path
  type = "approle"
  path = "%s"
}

resource "vault_approle_auth_backend_role" "role" {
  namespace      = vault_namespace.test.path
  backend = vault_auth_backend.approle.path
  role_name = "%s"
  token_policies = ["default", "dev", "prod"]
}

resource "vault_quota_lease_count" "foobar" {
  name = "%s"
  path = "${vault_namespace.test.path}/auth/${vault_auth_backend.approle.path}/"
  role = vault_approle_auth_backend_role.role.role_name
  max_leases = %s
}
`, ns, backend, role, name, maxLeases)
}

// Caution: Don't set test max_leases values too low or other tests running concurrently might fail
func testQuotaLeaseCountConfigInheritable(ns, name, path, maxLeases string, inheritable bool) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = "%s"
}

resource "vault_quota_lease_count" "foobar" {
  name        = "%s"
  path        = "${vault_namespace.test.path}/%s"
  max_leases  = %s
  inheritable  = %t
}
`, ns, name, path, maxLeases, inheritable)
}

func testQuotaLeaseCountWithRoleConfigInheritable(ns, backend, role, name, maxLeases string, inheritable bool) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = "%s"
}

resource "vault_auth_backend" "approle" {
  namespace      = vault_namespace.test.path
  type = "approle"
  path = "%s"
}

resource "vault_approle_auth_backend_role" "role" {
  namespace      = vault_namespace.test.path
  backend = vault_auth_backend.approle.path
  role_name = "%s"
  token_policies = ["default", "dev", "prod"]
}

resource "vault_quota_lease_count" "foobar" {
  name = "%s"
  path = "${vault_namespace.test.path}/auth/${vault_auth_backend.approle.path}/"
  role = vault_approle_auth_backend_role.role.role_name
  max_leases = %s
  inheritable  = %t
}
`, ns, backend, role, name, maxLeases, inheritable)
}
