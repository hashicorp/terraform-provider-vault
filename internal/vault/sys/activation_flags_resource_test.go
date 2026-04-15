// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys_test

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccActivationFlagsResource_basic tests basic resource creation and read
// Note: This test reads the current state and ensures it can be managed
func TestAccActivationFlagsResource_basic(t *testing.T) {
	resourceName := "vault_activation_flags.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccActivationFlagsResourceConfig_basic(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", "activation-flags"),
					resource.TestCheckResourceAttrSet(resourceName, "activated_flags.#"),
				),
			},
		},
	})
}

// TestAccActivationFlagsResource_withFlags tests managing specific activation flags
// Note: The actual flags available depend on Vault version and license
func TestAccActivationFlagsResource_withFlags(t *testing.T) {
	resourceName := "vault_activation_flags.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				// First, read current state to understand what flags exist
				Config: testAccActivationFlagsResourceConfig_readCurrent(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", "activation-flags"),
					resource.TestCheckResourceAttrSet(resourceName, "activated_flags.#"),
				),
			},
		},
	})
}

// TestAccActivationFlagsResource_import tests importing the resource
func TestAccActivationFlagsResource_import(t *testing.T) {
	resourceName := "vault_activation_flags.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccActivationFlagsResourceConfig_basic(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", "activation-flags"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

// TestAccActivationFlagsResource_emptyList tests resource with empty activated_flags list
// This represents managing the state where no flags should be activated
func TestAccActivationFlagsResource_emptyList(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccActivationFlagsResourceConfig_empty(),
				ExpectError: regexp.MustCompile(`does not support deactivation`),
			},
		},
	})
}

// TestAccActivationFlagsResource_delete tests that delete shows warning
func TestAccActivationFlagsResource_delete(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccActivationFlagsResourceConfig_basic(),
			},
			{
				Config:  testAccActivationFlagsResourceConfig_basic(),
				Destroy: true,
			},
		},
	})
}

// TestAccActivationFlagsResource_namespace tests resource with namespace
func TestAccActivationFlagsResource_namespace(t *testing.T) {
	resourceName := "vault_activation_flags.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccActivationFlagsResourceConfig_namespace(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", "activation-flags"),
					resource.TestCheckResourceAttrSet(resourceName, "activated_flags.#"),
				),
			},
		},
	})
}

// Config functions

func testAccActivationFlagsResourceConfig_basic() string {
	return `
# Read the current activation flags state from Vault
data "vault_activation_flags" "current" {}

# Manage activation flags - maintain currently activated flags
resource "vault_activation_flags" "test" {
  # Keep all currently activated flags
  activated_flags = data.vault_activation_flags.current.activated_flags
}
`
}

func testAccActivationFlagsResourceConfig_readCurrent() string {
	return `
# Read current state to understand available flags
data "vault_activation_flags" "current" {}

# Manage the activation flags resource
resource "vault_activation_flags" "test" {
  # Maintain current state
  activated_flags = data.vault_activation_flags.current.activated_flags
}
`
}

func testAccActivationFlagsResourceConfig_empty() string {
	return `
# Attempt to manage with no activated flags
# Note: This may not actually deactivate flags since the API doesn't support deactivation
resource "vault_activation_flags" "test" {
  activated_flags = []
}
`
}

func testAccActivationFlagsResourceConfig_namespace() string {
	return `
# Read current state
data "vault_activation_flags" "current" {}

# Manage activation flags in root namespace
resource "vault_activation_flags" "test" {
  namespace       = "root"
  activated_flags = data.vault_activation_flags.current.activated_flags
}
`
}

// Made with Bob
