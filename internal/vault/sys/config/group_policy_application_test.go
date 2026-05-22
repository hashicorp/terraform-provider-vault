// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config_test

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/internal/vault/sys/config"
)

// TestAccConfigGroupPolicyApplication tests basic resource creation and import
func TestAccConfigGroupPolicyApplication(t *testing.T) {
	resourceName := "vault_config_group_policy_application.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfigGroupPolicyApplicationConfig_basic("within_namespace_hierarchy"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldID, config.ConfigGroupPolicyApplicationPath),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGroupPolicyApplicationMode, "within_namespace_hierarchy"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateId:     config.ConfigGroupPolicyApplicationPath,
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
				ImportStateId:     config.ConfigGroupPolicyApplicationPath,
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
				ImportStateId:     config.ConfigGroupPolicyApplicationPath,
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
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccConfigGroupPolicyApplicationConfig_basic("invalid_mode"),
				ExpectError: regexp.MustCompile(`group_policy_application_mode must be either`),
			},
		},
	})
}

// TestAccConfigGroupPolicyApplication_invalidNamespace tests that non-root/admin namespaces are rejected
func TestAccConfigGroupPolicyApplication_invalidNamespace(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccConfigGroupPolicyApplicationConfig_withNamespace("any", "invalid-namespace"),
				ExpectError: regexp.MustCompile(`no handler for route`),
			},
		},
	})
}

// TestAccConfigGroupPolicyApplication_providerNamespaceUnset tests that provider-level child namespaces
// are rejected even when the resource namespace attribute is unset.
func TestAccConfigGroupPolicyApplication_providerNamespaceUnset(t *testing.T) {
	const providerNamespace = "child-namespace"

	originalNamespace, hadOriginalNamespace := os.LookupEnv("VAULT_NAMESPACE")
	t.Setenv("VAULT_NAMESPACE", providerNamespace)
	if hadOriginalNamespace {
		t.Cleanup(func() {
			_ = os.Setenv("VAULT_NAMESPACE", originalNamespace)
		})
	} else {
		t.Cleanup(func() {
			_ = os.Unsetenv("VAULT_NAMESPACE")
		})
	}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccConfigGroupPolicyApplicationConfig_basic("any"),
				ExpectError: regexp.MustCompile(`no handler for route`),
			},
		},
	})
}

// TestAccConfigGroupPolicyApplication_importInvalidID tests that import with invalid ID fails
func TestAccConfigGroupPolicyApplication_importInvalidID(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
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
				ExpectError:   regexp.MustCompile(fmt.Sprintf(`Import ID must be "%s"`, config.ConfigGroupPolicyApplicationPath)),
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
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfigGroupPolicyApplicationConfig_basic("any"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldID, config.ConfigGroupPolicyApplicationPath),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGroupPolicyApplicationMode, "any"),
				),
			},
		},
	})
}

// TestAccConfigGroupPolicyApplication_explicitRootNamespace tests root namespace (omitted)
func TestAccConfigGroupPolicyApplication_explicitRootNamespace(t *testing.T) {
	resourceName := "vault_config_group_policy_application.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfigGroupPolicyApplicationConfig_basic("any"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldGroupPolicyApplicationMode, "any"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateId:     config.ConfigGroupPolicyApplicationPath,
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
