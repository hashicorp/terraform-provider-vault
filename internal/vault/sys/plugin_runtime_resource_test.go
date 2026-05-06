// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccPluginRuntime(t *testing.T) {
	runtimeName := acctest.RandomWithPrefix("test-runtime")
	resourceName := "vault_plugin_runtime.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion115)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPluginRuntimeConfig(runtimeName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "container"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, runtimeName),
					resource.TestCheckResourceAttr(resourceName, "oci_runtime", "runc"),
					resource.TestCheckResourceAttr(resourceName, "rootless", "false"),
				),
			},
			{
				Config: testAccPluginRuntimeConfigUpdated(runtimeName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "container"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, runtimeName),
					resource.TestCheckResourceAttr(resourceName, "oci_runtime", "runsc"),
					resource.TestCheckResourceAttr(resourceName, "cpu_nanos", "1000000000"),
					resource.TestCheckResourceAttr(resourceName, "memory_bytes", "536870912"),
					resource.TestCheckResourceAttr(resourceName, "rootless", "true"),
				),
			},
			// Import test - type and name are part of the ID, so they're ignored
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldType,
				consts.FieldName,
			),
		},
	})
}

func TestAccPluginRuntimeNS(t *testing.T) {
	ns := acctest.RandomWithPrefix("ns")
	runtimeName := acctest.RandomWithPrefix("test-runtime")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion115)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccPluginRuntimeConfigNS(ns, runtimeName),
				ExpectError: regexp.MustCompile(`(?i)(unsupported path|404|namespace)`),
			},
		},
	})
}

func TestAccPluginRuntime_MinimalConfig(t *testing.T) {
	runtimeName := acctest.RandomWithPrefix("test-runtime")
	resourceName := "vault_plugin_runtime.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion115)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPluginRuntimeConfigMinimal(runtimeName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "container"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, runtimeName),
					resource.TestCheckResourceAttr(resourceName, "rootless", "false"),
				),
			},
			// Import test - type and name are part of the ID, so they're ignored
			testutil.GetImportTestStep(resourceName, false, nil,
				consts.FieldType,
				consts.FieldName,
				"cpu_nanos",
				"memory_bytes",
			),
		},
	})
}

func TestAccPluginRuntime_ImportWithAllFields(t *testing.T) {
	runtimeName := acctest.RandomWithPrefix("test-runtime")
	resourceName := "vault_plugin_runtime.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion115)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: Create runtime with all fields
				Config: testAccPluginRuntimeConfigFull(runtimeName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "container"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, runtimeName),
					resource.TestCheckResourceAttr(resourceName, "oci_runtime", "runc"),
					resource.TestCheckResourceAttr(resourceName, "cgroup_parent", "/vault/plugins"),
					resource.TestCheckResourceAttr(resourceName, "cpu_nanos", "1000000000"),
					resource.TestCheckResourceAttr(resourceName, "memory_bytes", "536870912"),
					resource.TestCheckResourceAttr(resourceName, "rootless", "true"),
				),
			},
			{
				// Step 2: Import - all fields should be read from API
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					consts.FieldType,
					consts.FieldName,
				},
			},
		},
	})
}

func TestAccPluginRuntime_ImportApplyPlanNoDrift(t *testing.T) {
	runtimeName := acctest.RandomWithPrefix("test-runtime")
	resourceName := "vault_plugin_runtime.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion115)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: Create runtime with all write-only fields
				Config: testAccPluginRuntimeConfigFull(runtimeName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "container"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, runtimeName),
					resource.TestCheckResourceAttr(resourceName, "oci_runtime", "runc"),
					resource.TestCheckResourceAttr(resourceName, "cgroup_parent", "/vault/plugins"),
					resource.TestCheckResourceAttr(resourceName, "cpu_nanos", "1000000000"),
					resource.TestCheckResourceAttr(resourceName, "memory_bytes", "536870912"),
					resource.TestCheckResourceAttr(resourceName, "rootless", "true"),
				),
			},
			{
				// Step 2: Import the resource - all fields should be read from API
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     fmt.Sprintf("container/%s", runtimeName),
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					consts.FieldType,
					consts.FieldName,
				},
			},
			{
				// Step 3: Plan-only step to verify no drift after import
				// Since API returns all fields, there should be no drift
				Config:             testAccPluginRuntimeConfigFull(runtimeName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false, // Should be no changes
			},
		},
	})
}

func TestAccPluginRuntime_MinimalImportPlanNoDrift(t *testing.T) {
	runtimeName := acctest.RandomWithPrefix("test-runtime")
	resourceName := "vault_plugin_runtime.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion115)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPluginRuntimeConfigMinimal(runtimeName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "container"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, runtimeName),
					resource.TestCheckResourceAttr(resourceName, "rootless", "false"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     fmt.Sprintf("container/%s", runtimeName),
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					consts.FieldType,
					consts.FieldName,
					"cpu_nanos",
					"memory_bytes",
				},
			},
			{
				Config:             testAccPluginRuntimeConfigMinimal(runtimeName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func TestAccPluginRuntime_UpdateFromFullToMinimalNoDrift(t *testing.T) {
	runtimeName := acctest.RandomWithPrefix("test-runtime")
	resourceName := "vault_plugin_runtime.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion115)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPluginRuntimeConfigFull(runtimeName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "oci_runtime", "runc"),
					resource.TestCheckResourceAttr(resourceName, "cgroup_parent", "/vault/plugins"),
					resource.TestCheckResourceAttr(resourceName, "cpu_nanos", "1000000000"),
					resource.TestCheckResourceAttr(resourceName, "memory_bytes", "536870912"),
					resource.TestCheckResourceAttr(resourceName, "rootless", "true"),
				),
			},
			{
				Config: testAccPluginRuntimeConfigMinimal(runtimeName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldType, "container"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, runtimeName),
					resource.TestCheckResourceAttr(resourceName, "rootless", "false"),
				),
			},
			{
				Config:             testAccPluginRuntimeConfigMinimal(runtimeName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func TestAccPluginRuntime_InvalidType(t *testing.T) {
	runtimeName := acctest.RandomWithPrefix("test-runtime")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion115)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccPluginRuntimeConfigInvalidType(runtimeName),
				ExpectError: regexp.MustCompile(`(?i)(invalid|unsupported|plugin runtime|Error Writing Plugin Runtime)`),
			},
		},
	})
}

func TestAccPluginRuntime_ImportInvalidID(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion115)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPluginRuntimeConfigMinimal(acctest.RandomWithPrefix("test-runtime")),
			},
			{
				ResourceName:  resourceNameForPluginRuntimeTest(),
				ImportState:   true,
				ImportStateId: "invalid-import-id",
				ExpectError:   regexp.MustCompile(`(?i)(invalid id|format <type>/<name>)`),
			},
		},
	})
}

func testAccPluginRuntimeConfig(name string) string {
	return fmt.Sprintf(`
resource "vault_plugin_runtime" "test" {
  type        = "container"
  name        = %q
  oci_runtime = "runc"
  rootless    = false
}
`, name)
}

func testAccPluginRuntimeConfigUpdated(name string) string {
	return fmt.Sprintf(`
resource "vault_plugin_runtime" "test" {
  type         = "container"
  name         = %q
  oci_runtime  = "runsc"
  cpu_nanos    = 1000000000
  memory_bytes = 536870912
  rootless     = true
}
`, name)
}

func testAccPluginRuntimeConfigNS(ns, name string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = %q
}

resource "vault_plugin_runtime" "test" {
  namespace   = vault_namespace.test.path
  type        = "container"
  name        = %q
  oci_runtime = "runc"
}
`, ns, name)
}

func testAccPluginRuntimeConfigUpdatedNS(ns, name string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = %q
}

resource "vault_plugin_runtime" "test" {
  namespace    = vault_namespace.test.path
  type         = "container"
  name         = %q
  oci_runtime  = "runsc"
  cpu_nanos    = 1000000000
}
`, ns, name)
}

func testAccPluginRuntimeConfigMinimal(name string) string {
	return fmt.Sprintf(`
resource "vault_plugin_runtime" "test" {
  type = "container"
  name = %q
}
`, name)
}

func testAccPluginRuntimeConfigFull(name string) string {
	return fmt.Sprintf(`
resource "vault_plugin_runtime" "test" {
  type           = "container"
  name           = %q
  oci_runtime    = "runc"
  cgroup_parent  = "/vault/plugins"
  cpu_nanos      = 1000000000
  memory_bytes   = 536870912
  rootless       = true
}
`, name)
}

func testAccPluginRuntimeConfigInvalidType(name string) string {
	return fmt.Sprintf(`
resource "vault_plugin_runtime" "test" {
  type = "invalid"
  name = %q
}
`, name)
}

func resourceNameForPluginRuntimeTest() string {
	return "vault_plugin_runtime.test"
}
