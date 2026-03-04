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
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/vault/api"
)

// TestAccKerberosAuthBackendGroup_basic tests basic resource creation
func TestAccKerberosAuthBackendGroup_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("kerberos")
	groupName := acctest.RandomWithPrefix("test-group")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendGroupConfig_basic(path, groupName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldMount, path),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldName, groupName),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldPolicies+".#", "2"),
					resource.TestCheckTypeSetElemAttr("vault_kerberos_auth_backend_group.group", consts.FieldPolicies+".*", "default"),
					resource.TestCheckTypeSetElemAttr("vault_kerberos_auth_backend_group.group", consts.FieldPolicies+".*", "dev"),
				),
			},
		},
	})
}

// TestAccKerberosAuthBackendGroup_update tests updating the group policies (adding and removing)
func TestAccKerberosAuthBackendGroup_update(t *testing.T) {
	path := acctest.RandomWithPrefix("kerberos")
	groupName := acctest.RandomWithPrefix("test-group")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendGroupConfig_basic(path, groupName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldMount, path),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldName, groupName),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldPolicies+".#", "2"),
					resource.TestCheckTypeSetElemAttr("vault_kerberos_auth_backend_group.group", consts.FieldPolicies+".*", "default"),
					resource.TestCheckTypeSetElemAttr("vault_kerberos_auth_backend_group.group", consts.FieldPolicies+".*", "dev"),
				),
			},
			{
				Config: testAccKerberosAuthBackendGroupConfig_updated(path, groupName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldMount, path),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldName, groupName),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldPolicies+".#", "3"),
					resource.TestCheckTypeSetElemAttr("vault_kerberos_auth_backend_group.group", consts.FieldPolicies+".*", "default"),
					resource.TestCheckTypeSetElemAttr("vault_kerberos_auth_backend_group.group", consts.FieldPolicies+".*", "dev"),
					resource.TestCheckTypeSetElemAttr("vault_kerberos_auth_backend_group.group", consts.FieldPolicies+".*", "prod"),
				),
			},
			{
				Config: testAccKerberosAuthBackendGroupConfig_basic(path, groupName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldPolicies+".#", "2"),
					resource.TestCheckTypeSetElemAttr("vault_kerberos_auth_backend_group.group", consts.FieldPolicies+".*", "default"),
					resource.TestCheckTypeSetElemAttr("vault_kerberos_auth_backend_group.group", consts.FieldPolicies+".*", "dev"),
				),
			},
		},
	})
}

// TestAccKerberosAuthBackendGroup_noPolicies tests creating a group without policies
func TestAccKerberosAuthBackendGroup_noPolicies(t *testing.T) {
	path := acctest.RandomWithPrefix("kerberos")
	groupName := acctest.RandomWithPrefix("test-group")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendGroupConfig_noPolicies(path, groupName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldMount, path),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldName, groupName),
					resource.TestCheckNoResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldPolicies),
				),
			},
		},
	})
}

// TestAccKerberosAuthBackendGroup_import tests importing the resource
func TestAccKerberosAuthBackendGroup_import(t *testing.T) {
	path := acctest.RandomWithPrefix("kerberos")
	groupName := acctest.RandomWithPrefix("test-group")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendGroupConfig_basic(path, groupName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldMount, path),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldName, groupName),
				),
			},
			{
				ResourceName:                         "vault_kerberos_auth_backend_group.group",
				ImportState:                          true,
				ImportStateId:                        fmt.Sprintf("auth/%s/groups/%s", path, groupName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore:              []string{consts.FieldPolicies},
			},
		},
	})
}

// TestAccKerberosAuthBackendGroup_defaultCheck tests to check default values
func TestAccKerberosAuthBackendGroup_defaultCheck(t *testing.T) {
	groupName := acctest.RandomWithPrefix("test-group")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendGroupConfig_defaultValues(groupName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldMount, "kerberos"),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldName, groupName),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldPolicies+".#", "1"),
					resource.TestCheckTypeSetElemAttr("vault_kerberos_auth_backend_group.group", consts.FieldPolicies+".*", "default"),
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

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendGroupConfig_basic(path1, groupName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldMount, path1),
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
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldMount, path2),
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

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendGroupConfig_basic(path, groupName1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldName, groupName1),
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
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldName, groupName2),
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

// TestAccKerberosAuthBackendGroup_runtimeErrors tests runtime errors
func TestAccKerberosAuthBackendGroup_runtimeErrors(t *testing.T) {
	groupName := acctest.RandomWithPrefix("test-group")
	nonExistentPath := "non-existent-kerberos-backend"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Test non-existent backend
			{
				Config:      testAccKerberosAuthBackendGroupConfig_nonExistentBackend(nonExistentPath, groupName),
				ExpectError: regexp.MustCompile(`error writing|no handler for route|unsupported path`),
			},
		},
	})
}

// TestAccKerberosAuthBackendGroup_groupNotFound tests the group not found scenario
func TestAccKerberosAuthBackendGroup_groupNotFound(t *testing.T) {
	path := acctest.RandomWithPrefix("kerberos")
	groupName := acctest.RandomWithPrefix("test-group")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create a valid group
			{
				Config: testAccKerberosAuthBackendGroupConfig_basic(path, groupName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldMount, path),
				),
			},
			// Step 2: Test group not found
			// Delete the group manually, then try to refresh
			{
				PreConfig: func() {
					// Get a Vault client and delete the group
					client, err := api.NewClient(api.DefaultConfig())
					if err != nil {
						t.Fatalf("failed to create client: %v", err)
					}
					// Delete the group
					groupPath := fmt.Sprintf("auth/%s/groups/%s", path, groupName)
					if _, err := client.Logical().Delete(groupPath); err != nil {
						t.Logf("Warning: failed to delete group: %v", err)
					}
				},
				Config:      testAccKerberosAuthBackendGroupConfig_basic(path, groupName),
				ExpectError: regexp.MustCompile(`Kerberos group not found`),
			},
		},
	})
}

// TestAccKerberosAuthBackendGroup_importErrors tests import validation errors
func TestAccKerberosAuthBackendGroup_importErrors(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Test completely invalid import ID
			{
				Config:            testAccKerberosAuthBackendGroupConfig_basic("test", "test-group"),
				ResourceName:      "vault_kerberos_auth_backend_group.group",
				ImportState:       true,
				ImportStateId:     "invalid-import-id",
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile(`Error parsing import identifier`),
			},
			// Test import ID missing /groups/{name} suffix
			{
				Config:            testAccKerberosAuthBackendGroupConfig_basic("test", "test-group"),
				ResourceName:      "vault_kerberos_auth_backend_group.group",
				ImportState:       true,
				ImportStateId:     "auth/kerberos",
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile(`Error parsing import identifier`),
			},
			// Test import ID missing auth/ prefix
			{
				Config:            testAccKerberosAuthBackendGroupConfig_basic("test", "test-group"),
				ResourceName:      "vault_kerberos_auth_backend_group.group",
				ImportState:       true,
				ImportStateId:     "kerberos/groups/test-group",
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile(`Error parsing import identifier`),
			},
			// Test import ID with empty path between prefix and suffix
			{
				Config:            testAccKerberosAuthBackendGroupConfig_basic("test", "test-group"),
				ResourceName:      "vault_kerberos_auth_backend_group.group",
				ImportState:       true,
				ImportStateId:     "auth//groups/test-group",
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile(`Error parsing import identifier`),
			},
			// Test import ID with empty group name
			{
				Config:            testAccKerberosAuthBackendGroupConfig_basic("test", "test-group"),
				ResourceName:      "vault_kerberos_auth_backend_group.group",
				ImportState:       true,
				ImportStateId:     "auth/kerberos/groups/",
				ImportStateVerify: false,
				ExpectError:       regexp.MustCompile(`Error parsing import identifier`),
			},
		},
	})
}

// TestAccKerberosAuthBackendGroup_namespace tests configuration and import with namespace (Enterprise only)
func TestAccKerberosAuthBackendGroup_namespace(t *testing.T) {
	namespace := acctest.RandomWithPrefix("tf-ns")
	path := acctest.RandomWithPrefix("kerberos")
	groupName := acctest.RandomWithPrefix("test-group")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKerberosAuthBackendGroupConfig_namespace(namespace, path, groupName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldNamespace, namespace),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldMount, path),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldName, groupName),
					resource.TestCheckResourceAttr("vault_kerberos_auth_backend_group.group", consts.FieldPolicies+".#", "2"),
				),
			},
			{
				PreConfig: func() {
					// Set the namespace environment variable for import
					t.Setenv(consts.EnvVarVaultNamespaceImport, namespace)
				},
				ResourceName:                         "vault_kerberos_auth_backend_group.group",
				ImportState:                          true,
				ImportStateId:                        fmt.Sprintf("auth/%s/groups/%s", path, groupName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateVerifyIgnore:              []string{consts.FieldPolicies},
			},
			{
				// Cleanup step needed for the import step above
				Config: testAccKerberosAuthBackendGroupConfig_namespace(namespace, path, groupName),
				PreConfig: func() {
					os.Unsetenv(consts.EnvVarVaultNamespaceImport)
				},
				PlanOnly: true,
			},
		},
	})
}

// Configuration templates for negative tests

func testAccKerberosAuthBackendGroupConfig_nonExistentBackend(path, groupName string) string {
	return fmt.Sprintf(`
resource "vault_kerberos_auth_backend_group" "group" {
  mount    = %q
  name     = %q
  policies = ["default"]
}
`, path, groupName)
}

// Configuration templates for positive tests

func testAccKerberosAuthBackendGroupConfig_basic(path, groupName string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_group" "group" {
  mount    = vault_auth_backend.kerberos.path
  name     = %q
  policies = ["default", "dev"]
}
`, path, groupName)
}

func testAccKerberosAuthBackendGroupConfig_updated(path, groupName string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_group" "group" {
  mount    = vault_auth_backend.kerberos.path
  name     = %q
  policies = ["default", "dev", "prod"]
}
`, path, groupName)
}

func testAccKerberosAuthBackendGroupConfig_noPolicies(path, groupName string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "kerberos" {
  type = "kerberos"
  path = %q
}

resource "vault_kerberos_auth_backend_group" "group" {
  mount = vault_auth_backend.kerberos.path
  name  = %q
}
`, path, groupName)
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

func testAccKerberosAuthBackendGroupConfig_namespace(namespace, path, groupName string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = %q
}

resource "vault_auth_backend" "kerberos" {
  namespace = vault_namespace.test.path
  type      = "kerberos"
  path      = %q
}

resource "vault_kerberos_auth_backend_group" "group" {
  namespace = vault_namespace.test.path
  mount     = vault_auth_backend.kerberos.path
  name      = %q
  policies  = ["default", "dev"]
}
`, namespace, path, groupName)
}

// Made with Bob
