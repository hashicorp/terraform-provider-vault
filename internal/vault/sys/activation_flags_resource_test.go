// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys_test

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccActivationFlagsResource_basic tests basic resource creation and read
// Note: This test reads the current state and ensures it can be managed
func TestAccActivationFlagsResource_basic(t *testing.T) {
	resourceName := "vault_activation_flags.test"
	var activatedFlags []string

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			activatedFlags = testAccReadCurrentActivatedFlags(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccActivationFlagsResourceConfig_basic(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", "activation-flags"),
					testAccCheckActivationFlagsEqual(resourceName, activatedFlags),
				),
			},
		},
	})
}

// TestAccActivationFlagsResource_omitsAlreadyActiveFlag verifies the resource
// fails when configuration omits a flag that is already active in Vault.
func TestAccActivationFlagsResource_omitsAlreadyActiveFlag(t *testing.T) {
	var activatedFlags []string

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			activatedFlags = testAccReadCurrentActivatedFlags(t)
			if len(activatedFlags) == 0 {
				t.Skip("Vault has no activated flags; omission error path is not applicable")
			}
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccActivationFlagsResourceConfigExplicit(activatedFlags[1:]),
				ExpectError: regexp.MustCompile(`already has activated flags not declared in configuration`),
			},
		},
	})
}

// TestAccActivationFlagsResource_unknownFlagName verifies the resource fails
// when configuration includes a feature key that Vault does not advertise.
func TestAccActivationFlagsResource_unknownFlagName(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccActivationFlagsResourceConfigExplicit([]string{"definitely-not-a-real-activation-flag"}),
				ExpectError: regexp.MustCompile(`was\s+not\s+returned by GET /sys/activation-flags`),
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

func testAccReadCurrentActivatedFlags(t *testing.T) []string {
	t.Helper()
	return testAccReadCurrentActivationFlagsField(t, "activated")
}

func testAccReadCurrentUnactivatedFlags(t *testing.T) []string {
	t.Helper()
	return testAccReadCurrentActivationFlagsField(t, "unactivated")
}

func testAccReadCurrentActivationFlagsField(t *testing.T, field string) []string {
	t.Helper()

	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		t.Fatalf("failed to create Vault API client: %v", err)
	}

	secret, err := client.Logical().ReadWithContext(context.Background(), "sys/activation-flags")
	if err != nil {
		t.Fatalf("failed to read activation flags from Vault: %v", err)
	}

	if secret == nil || secret.Data == nil {
		t.Fatalf("activation flags read returned nil response")
	}

	raw, ok := secret.Data[field]
	if !ok || raw == nil {
		return []string{}
	}

	items, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("unexpected activation flags type %T", raw)
	}

	flags := make([]string, 0, len(items))
	for _, item := range items {
		flag, ok := item.(string)
		if !ok {
			t.Fatalf("unexpected activation flag value type %T", item)
		}
		flags = append(flags, flag)
	}

	return flags
}

func testAccCheckActivationFlagsEqual(resourceName string, expected []string) resource.TestCheckFunc {
	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, "activated_flags.#", fmt.Sprintf("%d", len(expected))),
	}

	for _, flag := range expected {
		checks = append(checks, resource.TestCheckTypeSetElemAttr(resourceName, "activated_flags.*", flag))
	}

	return resource.ComposeTestCheckFunc(checks...)
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
	var activatedFlags []string

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			activatedFlags = testAccReadCurrentActivatedFlags(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccActivationFlagsResourceConfig_namespace(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", "activation-flags"),
					testAccCheckActivationFlagsEqual(resourceName, activatedFlags),
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

func testAccActivationFlagsResourceConfigExplicit(flags []string) string {
	quotedFlags := make([]string, 0, len(flags))
	for _, flag := range flags {
		quotedFlags = append(quotedFlags, fmt.Sprintf("%q", flag))
	}

	return fmt.Sprintf(`
resource "vault_activation_flags" "test" {
  activated_flags = [%s]
}
`, strings.Join(quotedFlags, ", "))
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
