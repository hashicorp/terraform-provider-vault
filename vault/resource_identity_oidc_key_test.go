// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccIdentityOidcKey(t *testing.T) {
	key := acctest.RandomWithPrefix("test-key")

	resourceName := "vault_identity_oidc_key.key"
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckIdentityOidcKeyDestroy,
		Steps: []resource.TestStep{
			{
				// Test a create failure
				Config:      testAccIdentityOidcKeyConfig_bad(key),
				ExpectError: regexp.MustCompile(`unknown signing algorithm "RS123"`),
			},
			{
				Config: testAccIdentityOidcKeyConfig(key),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", key),
					resource.TestCheckResourceAttr(resourceName, "rotation_period", "86400"),
					resource.TestCheckResourceAttr(resourceName, "verification_ttl", "86400"),
					resource.TestCheckResourceAttr(resourceName, "algorithm", "RS256"),
					resource.TestCheckResourceAttr(resourceName, "allowed_client_ids.#", "0"),
					testAccIdentityOidcKeyCheckAttrs(resourceName),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccIdentityOidcKeyUpdate(t *testing.T) {
	key := acctest.RandomWithPrefix("test-key")

	resourceName := "vault_identity_oidc_key.key"
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckIdentityOidcKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityOidcKeyConfig(key),
				Check:  testAccIdentityOidcKeyCheckAttrs(resourceName),
			},
			{
				Config: testAccIdentityOidcKeyConfigUpdate(key),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", key),
					resource.TestCheckResourceAttr(resourceName, "rotation_period", "3600"),
					resource.TestCheckResourceAttr(resourceName, "verification_ttl", "3600"),
					resource.TestCheckResourceAttr(resourceName, "algorithm", "ES256"),
					resource.TestCheckResourceAttr(resourceName, "allowed_client_ids.#", "1"),
					testAccIdentityOidcKeyCheckAttrs(resourceName),
				),
			},
			{
				Config: testAccIdentityOidcKeyConfig(key),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", key),
					resource.TestCheckResourceAttr(resourceName, "rotation_period", "86400"),
					resource.TestCheckResourceAttr(resourceName, "verification_ttl", "86400"),
					resource.TestCheckResourceAttr(resourceName, "algorithm", "RS256"),
					resource.TestCheckResourceAttr(resourceName, "allowed_client_ids.#", "0"),
					testAccIdentityOidcKeyCheckAttrs(resourceName),
				),
			},
			{
				// Test an update failure
				Config:      testAccIdentityOidcKeyConfig_bad(key),
				ExpectError: regexp.MustCompile(`unknown signing algorithm "RS123"`),
			},
		},
	})
}

func testAccCheckIdentityOidcKeyDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_identity_oidc_key" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		resp, err := identityOidcKeyApiRead(rs.Primary.Attributes["name"], client)
		if err != nil {
			return fmt.Errorf("error checking for identity oidc key %q: %s", rs.Primary.ID, err)
		}
		if resp != nil {
			return fmt.Errorf("identity oidc key %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccIdentityOidcKeyCheckAttrs(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		client, err := provider.GetClient(rs.Primary, testProvider.Meta())
		if err != nil {
			return err
		}

		path := identityOidcKeyPath(rs.Primary.ID)

		attrs := map[string]string{
			"rotation_period":    "rotation_period",
			"verification_ttl":   "verification_ttl",
			"algorithm":          "algorithm",
			"allowed_client_ids": "allowed_client_ids",
		}

		tAttrs := []*testutil.VaultStateTest{}
		for k, v := range attrs {
			ta := &testutil.VaultStateTest{
				ResourceName: resourceName,
				StateAttr:    k,
				VaultAttr:    v,
			}

			tAttrs = append(tAttrs, ta)
		}

		return testutil.AssertVaultState(client, s, path, tAttrs...)
	}
}

func testAccIdentityOidcKeyConfig(entityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "key" {
  name = "%s"
	algorithm = "RS256"

	allowed_client_ids = []
}`, entityName)
}

func testAccIdentityOidcKeyConfig_bad(entityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "key" {
  name = "%s"
	algorithm = "RS123"

	allowed_client_ids = []
}`, entityName)
}

func testAccIdentityOidcKeyConfigUpdate(entityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "key" {
  name = "%s"
	algorithm = "ES256"
	rotation_period = 3600
	verification_ttl = 3600

	allowed_client_ids = ["*"]
}`, entityName)
}
