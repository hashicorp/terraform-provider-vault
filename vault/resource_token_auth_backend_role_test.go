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

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccTokenAuthBackendRole(t *testing.T) {
	role := acctest.RandomWithPrefix("test-role")

	resourceName := "vault_token_auth_backend_role.role"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckTokenAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccTokenAuthBackendRoleConfig(role),
				Check:  testAccTokenAuthBackendRoleCheck_attrs(resourceName, role),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccTokenAuthBackendRoleUpdate(t *testing.T) {
	role := acctest.RandomWithPrefix("test-role")
	roleUpdated := acctest.RandomWithPrefix("test-role-updated")

	resourceName := "vault_token_auth_backend_role.role"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckTokenAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccTokenAuthBackendRoleConfig(role),
				Check:  testAccTokenAuthBackendRoleCheck_attrs(resourceName, role),
			},
			{
				Config: testAccTokenAuthBackendRoleConfigUpdate(role),
				Check: resource.ComposeTestCheckFunc(
					testAccTokenAuthBackendRoleCheck_attrs(resourceName, role),
					resource.TestCheckResourceAttr(resourceName, "role_name", role),
					resource.TestCheckResourceAttr(resourceName, "allowed_policies.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_policies.0", "dev"),
					resource.TestCheckResourceAttr(resourceName, "allowed_policies.1", "test"),
					resource.TestCheckResourceAttr(resourceName, "allowed_policies_glob.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_policies_glob.0", "dev/*"),
					resource.TestCheckResourceAttr(resourceName, "allowed_policies_glob.1", "test/*"),
					resource.TestCheckResourceAttr(resourceName, "disallowed_policies.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "disallowed_policies.0", "default"),
					resource.TestCheckResourceAttr(resourceName, "disallowed_policies_glob.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "disallowed_policies_glob.0", "def*"),
					resource.TestCheckResourceAttr(resourceName, "orphan", "true"),
					resource.TestCheckResourceAttr(resourceName, "allowed_entity_aliases.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "allowed_entity_aliases.0", "test"),
					resource.TestCheckResourceAttr(resourceName, "token_period", "86400"),
					resource.TestCheckResourceAttr(resourceName, "renewable", "false"),
					resource.TestCheckResourceAttr(resourceName, "token_explicit_max_ttl", "115200"),
					resource.TestCheckResourceAttr(resourceName, "path_suffix", "parth-suffix"),
					resource.TestCheckResourceAttr(resourceName, "token_bound_cidrs.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "token_bound_cidrs.0", "0.0.0.0/0"),
					resource.TestCheckResourceAttr(resourceName, "token_type", "default-batch"),
				),
			},
			{
				Config: testAccTokenAuthBackendRoleConfigUpdate(roleUpdated),
				Check: resource.ComposeTestCheckFunc(
					testAccTokenAuthBackendRoleCheck_attrs(resourceName, roleUpdated),
					testAccTokenAuthBackendRoleCheck_deleted(role),
					resource.TestCheckResourceAttr(resourceName, "role_name", roleUpdated),
					resource.TestCheckResourceAttr(resourceName, "allowed_policies.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_policies.0", "dev"),
					resource.TestCheckResourceAttr(resourceName, "allowed_policies.1", "test"),
					resource.TestCheckResourceAttr(resourceName, "allowed_policies_glob.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_policies_glob.0", "dev/*"),
					resource.TestCheckResourceAttr(resourceName, "allowed_policies_glob.1", "test/*"),
					resource.TestCheckResourceAttr(resourceName, "disallowed_policies.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "disallowed_policies.0", "default"),
					resource.TestCheckResourceAttr(resourceName, "disallowed_policies_glob.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "disallowed_policies_glob.0", "def*"),
					resource.TestCheckResourceAttr(resourceName, "orphan", "true"),
					resource.TestCheckResourceAttr(resourceName, "allowed_entity_aliases.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "allowed_entity_aliases.0", "test"),
					resource.TestCheckResourceAttr(resourceName, "token_period", "86400"),
					resource.TestCheckResourceAttr(resourceName, "renewable", "false"),
					resource.TestCheckResourceAttr(resourceName, "token_explicit_max_ttl", "115200"),
					resource.TestCheckResourceAttr(resourceName, "path_suffix", "parth-suffix"),
					resource.TestCheckResourceAttr(resourceName, "token_bound_cidrs.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "token_bound_cidrs.0", "0.0.0.0/0"),
					resource.TestCheckResourceAttr(resourceName, "token_type", "default-batch"),
				),
			},
			{
				Config: testAccTokenAuthBackendRoleConfig(roleUpdated),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccTokenAuthBackendRoleCheck_attrs(resourceName, roleUpdated),
					resource.TestCheckResourceAttr(resourceName, "role_name", roleUpdated),
					resource.TestCheckResourceAttr(resourceName, "allowed_policies.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "disallowed_policies.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "orphan", "false"),
					resource.TestCheckResourceAttr(resourceName, "allowed_entity_aliases.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "token_period", "0"),
					resource.TestCheckResourceAttr(resourceName, "renewable", "true"),
					resource.TestCheckResourceAttr(resourceName, "token_explicit_max_ttl", "0"),
					resource.TestCheckResourceAttr(resourceName, "path_suffix", ""),
					resource.TestCheckResourceAttr(resourceName, "token_bound_cidrs.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "token_type", "default-service"),
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

func testAccCheckTokenAuthBackendRoleDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_token_auth_backend_role" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for Token auth backend role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("token auth backend role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccTokenAuthBackendRoleCheck_deleted(role string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		endpoint := "auth/token/roles"
		client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

		resp, err := client.Logical().List(endpoint)
		if err != nil {
			return fmt.Errorf("%q returned unexpectedly", endpoint)
		}

		apiData := resp.Data["keys"].([]interface{})
		for _, r := range apiData {
			if r == role {
				return fmt.Errorf("%q still exists, extected to be deleted", role)
			}
		}
		return nil
	}
}

func testAccTokenAuthBackendRoleCheck_attrs(resourceName string, role string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		path := rs.Primary.ID

		if path != "auth/token/roles/"+role {
			return fmt.Errorf("expected ID to be %q, got %q instead", "auth/token/roles/"+role, path)
		}

		client, err := provider.GetClient(rs.Primary, testProvider.Meta())
		if err != nil {
			return err
		}

		attrs := map[string]string{
			"role_name":                "name",
			"allowed_policies":         "allowed_policies",
			"allowed_policies_glob":    "allowed_policies_glob",
			"disallowed_policies":      "disallowed_policies",
			"disallowed_policies_glob": "disallowed_policies_glob",
			"allowed_entity_aliases":   "allowed_entity_aliases",
			"orphan":                   "orphan",
			"token_period":             "token_period",
			"token_explicit_max_ttl":   "token_explicit_max_ttl",
			"path_suffix":              "path_suffix",
			"renewable":                "renewable",
			// TODO investigate why we do not get this field back from vault
			//"token_bound_cidrs":        "token_bound_cidrs",
			"token_type": "token_type",
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

func testAccTokenAuthBackendRoleConfig(roleName string) string {
	return fmt.Sprintf(`
resource "vault_token_auth_backend_role" "role" {
  role_name = "%s"
}
`, roleName)
}

func testAccTokenAuthBackendRoleConfigUpdate(role string) string {
	return fmt.Sprintf(`
resource "vault_token_auth_backend_role" "role" {
  role_name                = "%s"
  allowed_policies         = ["dev", "test"]
  allowed_policies_glob    = ["dev/*", "test/*"]
  disallowed_policies      = ["default"]
  disallowed_policies_glob = ["def*"]
  orphan                   = true
  allowed_entity_aliases   = ["test"]
  token_period             = "86400"
  renewable                = false
  token_explicit_max_ttl   = "115200"
  path_suffix              = "parth-suffix"
  token_bound_cidrs        = ["0.0.0.0/0"]
  token_type               = "default-batch"
}
`, role)
}
