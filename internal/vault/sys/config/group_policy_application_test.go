// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

// TestAccConfigGroupPolicyApplication tests basic resource creation and import
func TestAccConfigGroupPolicyApplication(t *testing.T) {
	resourceName := "vault_config_group_policy_application.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion1138)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfigGroupPolicyApplicationConfig_basic("within_namespace_hierarchy"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldID, "config"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGroupPolicyApplicationMode, "within_namespace_hierarchy"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, ""),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateId:     "config",
			},
		},
	})
}

// TestAccConfigGroupPolicyApplication_update tests update operations
func TestAccConfigGroupPolicyApplication_update(t *testing.T) {
	resourceName := "vault_config_group_policy_application.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion1138)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfigGroupPolicyApplicationConfig_basic("within_namespace_hierarchy"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldGroupPolicyApplicationMode, "within_namespace_hierarchy"),
				),
			},
			// Verify import works
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateId:     "config",
			},
			// Update to "any" mode
			{
				Config: testAccConfigGroupPolicyApplicationConfig_basic("any"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldGroupPolicyApplicationMode, "any"),
				),
			},
			// Verify import still works after update
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateId:     "config",
			},
			// Update back to default
			{
				Config: testAccConfigGroupPolicyApplicationConfig_basic("within_namespace_hierarchy"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldGroupPolicyApplicationMode, "within_namespace_hierarchy"),
				),
			},
		},
	})
}

// TestAccConfigGroupPolicyApplication_invalidMode tests that invalid modes are rejected
func TestAccConfigGroupPolicyApplication_invalidMode(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion1138)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccConfigGroupPolicyApplicationConfig_basic("invalid_mode"),
				ExpectError: regexp.MustCompile(`Attribute group_policy_application_mode value must be one of`),
			},
		},
	})
}

// TestAccConfigGroupPolicyApplication_invalidNamespace tests that non-root/admin namespaces are rejected
func TestAccConfigGroupPolicyApplication_invalidNamespace(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion1138)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccConfigGroupPolicyApplicationConfig_withNamespace("any", "invalid-namespace"),
				ExpectError: regexp.MustCompile(`Invalid Namespace`),
			},
		},
	})
}

// TestAccConfigGroupPolicyApplication_importInvalidID tests that import with invalid ID fails
func TestAccConfigGroupPolicyApplication_importInvalidID(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion1138)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfigGroupPolicyApplicationConfig_basic("any"),
			},
			{
				ResourceName:  "vault_config_group_policy_application.test",
				ImportState:   true,
				ImportStateId: "invalid-id",
				ExpectError:   regexp.MustCompile(`Import ID must be "config"`),
			},
		},
	})
}

// TestAccConfigGroupPolicyApplication_modeAny tests the "any" mode specifically
func TestAccConfigGroupPolicyApplication_modeAny(t *testing.T) {
	resourceName := "vault_config_group_policy_application.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion1138)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfigGroupPolicyApplicationConfig_basic("any"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldID, "config"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGroupPolicyApplicationMode, "any"),
				),
			},
		},
	})
}

// TestAccConfigGroupPolicyApplication_delete tests that delete resets to default
func TestAccConfigGroupPolicyApplication_delete(t *testing.T) {
	resourceName := "vault_config_group_policy_application.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion1138)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create with "any" mode
				Config: testAccConfigGroupPolicyApplicationConfig_basic("any"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldGroupPolicyApplicationMode, "any"),
				),
			},
			{
				// Delete the resource - this should reset to default
				Config: testAccConfigGroupPolicyApplicationConfig_empty(),
			},
			{
				// Re-import to verify it was reset to default
				Config: testAccConfigGroupPolicyApplicationConfig_basic("within_namespace_hierarchy"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldGroupPolicyApplicationMode, "within_namespace_hierarchy"),
				),
			},
		},
	})
}

// TestAccConfigGroupPolicyApplication_explicitRootNamespace tests explicit root namespace
func TestAccConfigGroupPolicyApplication_explicitRootNamespace(t *testing.T) {
	resourceName := "vault_config_group_policy_application.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion1138)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfigGroupPolicyApplicationConfig_withNamespace("any", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGroupPolicyApplicationMode, "any"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateId:     "config",
			},
		},
	})
}

// TestAccConfigGroupPolicyApplication_importVerifyNamespace tests import with namespace verification
func TestAccConfigGroupPolicyApplication_importVerifyNamespace(t *testing.T) {
	resourceName := "vault_config_group_policy_application.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion1138)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfigGroupPolicyApplicationConfig_withNamespace("any", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGroupPolicyApplicationMode, "any"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateId:     "config",
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, ""),
				),
			},
		},
	})
}

// Helper function to generate test configuration
func testAccConfigGroupPolicyApplicationConfig_basic(mode string) string {
	return fmt.Sprintf(`
resource "vault_config_group_policy_application" "test" {
  group_policy_application_mode = %q
}`, mode)
}

// Helper function to generate test configuration with namespace
func testAccConfigGroupPolicyApplicationConfig_withNamespace(mode, namespace string) string {
	return fmt.Sprintf(`
resource "vault_config_group_policy_application" "test" {
  group_policy_application_mode = %q
  namespace                     = %q
}`, mode, namespace)
}

// Helper function to generate empty configuration (for delete testing)
func testAccConfigGroupPolicyApplicationConfig_empty() string {
	return `
# Resource removed - should reset to default
`
}
