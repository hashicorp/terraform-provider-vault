// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys_test

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccActivationFlagsResource_basic tests resource creation and read.
func TestAccActivationFlagsResource_basic(t *testing.T) {
	resourceName := "vault_activation_flags.test"
	testAccActivationFlagsEntPreCheck(t)
	feature := testAccActivatedFlagForResource(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccActivationFlagsResourceConfig(feature),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", feature),
					resource.TestCheckResourceAttr(resourceName, "feature", feature),
					resource.TestCheckTypeSetElemAttr("data.vault_activation_flags.current", "activated_flags.*", feature),
				),
			},
		},
	})
}

// TestAccActivationFlagsResource_activateFeature verifies the resource
// activates a single unactivated feature.
func TestAccActivationFlagsResource_activateFeature(t *testing.T) {
	testAccActivationFlagsEntPreCheck(t)

	unactivatedFlags := testAccReadCurrentUnactivatedFlags(t)
	if len(unactivatedFlags) == 0 {
		t.Skip("Vault has no unactivated flags; single-feature activation path is not applicable")
	}

	feature := unactivatedFlags[0]

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccActivationFlagsResourceConfigWithAfter(feature),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_activation_flags.test", "id", feature),
					resource.TestCheckResourceAttr("vault_activation_flags.test", "feature", feature),
					resource.TestCheckTypeSetElemAttr("data.vault_activation_flags.after", "activated_flags.*", feature),
				),
			},
		},
	})
}

// TestAccActivationFlagsResource_import tests importing the resource
func TestAccActivationFlagsResource_import(t *testing.T) {
	resourceName := "vault_activation_flags.test"
	testAccActivationFlagsEntPreCheck(t)
	feature := testAccActivationFlagForResource(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccActivationFlagsResourceConfig(feature),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", feature),
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

func testAccActivationFlagsEntPreCheck(t *testing.T) {
	t.Helper()
	acctestutil.TestEntPreCheck(t)
	acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion116)
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

// TestAccActivationFlagsResource_delete tests that delete shows warning
func TestAccActivationFlagsResource_delete(t *testing.T) {
	testAccActivationFlagsEntPreCheck(t)
	feature := testAccActivationFlagForResource(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccActivationFlagsResourceConfig(feature),
			},
			{
				Config:  testAccActivationFlagsResourceConfig(feature),
				Destroy: true,
			},
		},
	})
}

// Config functions

func testAccActivationFlagForResource(t *testing.T) string {
	t.Helper()

	unactivatedFlags := testAccReadCurrentUnactivatedFlags(t)
	if len(unactivatedFlags) > 0 {
		sort.Strings(unactivatedFlags)
		return unactivatedFlags[0]
	}

	activatedFlags := testAccReadCurrentActivatedFlags(t)
	if len(activatedFlags) > 0 {
		sort.Strings(activatedFlags)
		return activatedFlags[0]
	}

	t.Skip("Vault reported no activation flags")
	return ""
}

func testAccActivatedFlagForResource(t *testing.T) string {
	t.Helper()

	activatedFlags := testAccReadCurrentActivatedFlags(t)
	if len(activatedFlags) > 0 {
		sort.Strings(activatedFlags)
		return activatedFlags[0]
	}

	t.Skip("Vault reported no activated flags")
	return ""
}

func testAccActivationFlagsResourceConfig(feature string) string {
	return fmt.Sprintf(`
data "vault_activation_flags" "current" {}

resource "vault_activation_flags" "test" {
  feature = %q
}
`, feature)
}

func testAccActivationFlagsResourceConfigWithAfter(feature string) string {
	return fmt.Sprintf(`
resource "vault_activation_flags" "test" {
	feature = %q
}

data "vault_activation_flags" "after" {
	depends_on = [vault_activation_flags.test]
}
`, feature)
}
