// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos_test

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

func TestAccKerberosAuthBackendGroup_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("kerberos")
	groupName := acctest.RandomWithPrefix("test-group")
	resourceType := "vault_kerberos_auth_backend_group"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendGroupConfig_basic(backend, groupName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, groupName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPolicies+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldPolicies+".*", "default"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldPolicies+".*", "dev"),
				),
			},
			{
				Config: testAccKerberosAuthBackendGroupConfig_updated(backend, groupName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, groupName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPolicies+".#", "3"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldPolicies+".*", "default"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldPolicies+".*", "dev"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldPolicies+".*", "prod"),
				),
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateId:                        fmt.Sprintf("auth/%s/groups/%s", backend, groupName),
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
			},
		},
	})
}

// TestAccKerberosAuthBackendGroup_defaultCheck tests to check default values
func TestAccKerberosAuthBackendGroup_defaultCheck(t *testing.T) {
	groupName := acctest.RandomWithPrefix("test-group")
	resourceType := "vault_kerberos_auth_backend_group"
	resourceName := resourceType + ".group"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendGroupConfig_defaultValues(groupName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, "kerberos"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, groupName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPolicies+".#", "1"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldPolicies+".*", "default"),
				),
			},
		},
	})
}

// TestAccKerberosAuthBackendGroup_pathChange tests that changing path requires replacement
func TestAccKerberosAuthBackendGroup_pathChange(t *testing.T) {
	path1 := acctest.RandomWithPrefix("kerberos")
	path2 := acctest.RandomWithPrefix("kerberos")
	groupName := acctest.RandomWithPrefix("test-group")
	resourceName := "vault_kerberos_auth_backend_group.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendGroupConfig_basic(path1, groupName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path1),
				),
			},
			{
				PreConfig: func() {
					// Verify the group exists in the old path before the change
					client, err := api.NewClient(api.DefaultConfig())
					if err != nil {
						t.Fatalf("failed to create client: %v", err)
					}

					oldGroupPath := fmt.Sprintf("auth/%s/groups/%s", path1, groupName)
					resp, err := client.Logical().Read(oldGroupPath)
					if err != nil || resp == nil {
						t.Fatalf("group %s should exist in path %s before path change", groupName, path1)
					}
				},
				Config: testAccKerberosAuthBackendGroupConfig_basic(path2, groupName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, path2),
				),
			},
			{
				// Additional step to verify the group was deleted from old path and created in new path
				PreConfig: func() {
					client, err := api.NewClient(api.DefaultConfig())
					if err != nil {
						t.Fatalf("failed to create client: %v", err)
					}

					// Verify group no longer exists in old path
					oldGroupPath := fmt.Sprintf("auth/%s/groups/%s", path1, groupName)
					resp, err := client.Logical().Read(oldGroupPath)
					if err == nil && resp != nil {
						t.Fatalf("group %s still exists in old path %s after path change, should have been deleted", groupName, path1)
					}

					// Verify group exists in new path
					newGroupPath := fmt.Sprintf("auth/%s/groups/%s", path2, groupName)
					resp, err = client.Logical().Read(newGroupPath)
					if err != nil || resp == nil {
						t.Fatalf("group %s should exist in new path %s after path change", groupName, path2)
					}
				},
				Config:   testAccKerberosAuthBackendGroupConfig_basic(path2, groupName),
				PlanOnly: true,
			},
		},
	})
}

// TestAccKerberosAuthBackendGroup_nameChange tests that changing name requires replacement
func TestAccKerberosAuthBackendGroup_nameChange(t *testing.T) {
	path := acctest.RandomWithPrefix("kerberos")
	groupName1 := acctest.RandomWithPrefix("test-group")
	groupName2 := acctest.RandomWithPrefix("test-group")
	resourceName := "vault_kerberos_auth_backend_group.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendGroupConfig_basic(path, groupName1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, groupName1),
				),
			},
			{
				PreConfig: func() {
					// Verify the old group exists before the change
					client, err := api.NewClient(api.DefaultConfig())
					if err != nil {
						t.Fatalf("failed to create client: %v", err)
					}

					oldGroupPath := fmt.Sprintf("auth/%s/groups/%s", path, groupName1)
					resp, err := client.Logical().Read(oldGroupPath)
					if err != nil || resp == nil {
						t.Fatalf("old group %s should exist before name change", groupName1)
					}
				},
				Config: testAccKerberosAuthBackendGroupConfig_basic(path, groupName2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, groupName2),
				),
			},
			{
				// Additional step to verify the old group was deleted after replacement
				PreConfig: func() {
					client, err := api.NewClient(api.DefaultConfig())
					if err != nil {
						t.Fatalf("failed to create client: %v", err)
					}

					// Verify old group no longer exists
					oldGroupPath := fmt.Sprintf("auth/%s/groups/%s", path, groupName1)
					resp, err := client.Logical().Read(oldGroupPath)
					if err == nil && resp != nil {
						t.Fatalf("old group %s still exists after name change, should have been deleted", groupName1)
					}

					// Verify new group exists
					newGroupPath := fmt.Sprintf("auth/%s/groups/%s", path, groupName2)
					resp, err = client.Logical().Read(newGroupPath)
					if err != nil || resp == nil {
						t.Fatalf("new group %s should exist after name change", groupName2)
					}
				},
				Config:   testAccKerberosAuthBackendGroupConfig_basic(path, groupName2),
				PlanOnly: true,
			},
		},
	})
}

func TestAccKerberosAuthBackendGroup_noPolicies(t *testing.T) {
	backend := acctest.RandomWithPrefix("kerberos")
	groupName := acctest.RandomWithPrefix("test-group")
	resourceName := "vault_kerberos_auth_backend_group.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendGroupConfig_noPolicies(backend, groupName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, groupName),
					resource.TestCheckNoResourceAttr(resourceName, consts.FieldPolicies+".#"),
				),
			},
		},
	})
}

func TestAccKerberosAuthBackendGroup_namespace(t *testing.T) {
	backend := acctest.RandomWithPrefix("kerberos")
	groupName := acctest.RandomWithPrefix("test-group")
	namespace := acctest.RandomWithPrefix("ns")
	resourceName := "vault_kerberos_auth_backend_group.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendGroupConfig_namespace(namespace, backend, groupName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, namespace),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, groupName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPolicies+".#", "2"),
				),
			},
			{
				PreConfig: func() {
					t.Setenv(consts.EnvVarVaultNamespaceImport, namespace)
				},
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateId:                        fmt.Sprintf("auth/%s/groups/%s", backend, groupName),
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				Config:                               testAccKerberosAuthBackendGroupConfig_namespace(namespace, backend, groupName),
			},
			{
				Config: testAccKerberosAuthBackendGroupConfig_namespace(namespace, backend, groupName),
				PreConfig: func() {
					os.Unsetenv(consts.EnvVarVaultNamespaceImport)
				},
				PlanOnly: true,
			},
		},
	})
}

func TestAccKerberosAuthBackendGroup_invalid(t *testing.T) {
	backend := acctest.RandomWithPrefix("kerberos")
	groupName := acctest.RandomWithPrefix("test-group")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Test invalid mount
			{
				Config:      testAccKerberosAuthBackendGroupConfig_invalidMount(groupName),
				ExpectError: regexp.MustCompile("no handler for route|unsupported path|route entry not found"),
			},
			// Test missing group name
			{
				Config:      testAccKerberosAuthBackendGroupConfig_missingName(backend),
				ExpectError: regexp.MustCompile(`Missing required argument|The argument "name" is required`),
			},
		},
	})
}

func TestAccKerberosAuthBackendGroup_invalidNamespace(t *testing.T) {
	backend := acctest.RandomWithPrefix("kerberos")
	groupName := acctest.RandomWithPrefix("test-group")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccKerberosAuthBackendGroupConfig_invalidNamespace(backend, groupName),
				ExpectError: regexp.MustCompile("no handler for route|namespace not found|route entry not found"),
			},
		},
	})
}

func testAccKerberosAuthBackendGroupConfig_basic(backend, groupName string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
  type = "kerberos"
  path = "%s"
}

resource "vault_kerberos_auth_backend_group" "test" {
  mount    = vault_auth_backend.test.path
  name     = "%s"
  policies = ["default", "dev"]
}
`, backend, groupName)
}

func testAccKerberosAuthBackendGroupConfig_updated(backend, groupName string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
  type = "kerberos"
  path = "%s"
}

resource "vault_kerberos_auth_backend_group" "test" {
  mount    = vault_auth_backend.test.path
  name     = "%s"
  policies = ["default", "dev", "prod"]
}
`, backend, groupName)
}

func testAccKerberosAuthBackendGroupConfig_defaultValues(groupName string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
}

resource "vault_kerberos_auth_backend_group" "group" {
  name       = %q
  policies   = ["default"]
  depends_on = [vault_auth_backend.kerberos]
}
`, groupName)
}

func testAccKerberosAuthBackendGroupConfig_noPolicies(backend, groupName string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
  type = "kerberos"
  path = "%s"
}

resource "vault_kerberos_auth_backend_group" "test" {
  mount = vault_auth_backend.test.path
  name  = "%s"
}
`, backend, groupName)
}

func testAccKerberosAuthBackendGroupConfig_invalidMount(groupName string) string {
	return fmt.Sprintf(`
resource "vault_kerberos_auth_backend_group" "test" {
  mount    = "nonexistent-mount"
  name     = "%s"
  policies = ["default"]
}
`, groupName)
}

func testAccKerberosAuthBackendGroupConfig_missingName(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
  type = "kerberos"
  path = "%s"
}

resource "vault_kerberos_auth_backend_group" "test" {
  mount    = vault_auth_backend.test.path
  policies = ["default"]
}
`, backend)
}

func testAccKerberosAuthBackendGroupConfig_invalidNamespace(backend, groupName string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
  type = "kerberos"
  path = "%s"
}

resource "vault_kerberos_auth_backend_group" "test" {
  namespace = "nonexistent-namespace"
  mount     = vault_auth_backend.test.path
  name      = "%s"
  policies  = ["default"]
}
`, backend, groupName)
}

func testAccKerberosAuthBackendGroupConfig_namespace(namespace, backend, groupName string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = "%s"
}

resource "vault_auth_backend" "test" {
  namespace = vault_namespace.test.path
  type      = "kerberos"
  path      = "%s"
}

resource "vault_kerberos_auth_backend_group" "test" {
  namespace = vault_namespace.test.path
  mount     = vault_auth_backend.test.path
  name      = "%s"
  policies  = ["default", "dev"]
}
`, namespace, backend, groupName)
}

// Made with Bob
