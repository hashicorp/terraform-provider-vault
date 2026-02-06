// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccAppRoleAuthBackendRole_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")
	roleID := acctest.RandomWithPrefix("test-role-id")
	resourcePath := "vault_approle_auth_backend_role.role"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAppRoleAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAppRoleAuthBackendRoleConfig_full(backend, role, roleID),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourcePath, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldRoleName, role),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldTokenPolicies+".#", "3"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldRoleID, roleID),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldTokenTTL, "3600"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldTokenMaxTTL, "7200"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldTokenNumUses, "12"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldSecretIDTTL, "600"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldSecretIDNumUses, "5"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldTokenPeriod, "0"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldBindSecretID, "false"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldLocalSecretIDs, "true"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldSecretIDBoundCIDRs+".#", "2"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldSecretIDBoundCIDRs+".0", "10.148.0.0/20"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldSecretIDBoundCIDRs+".1", "10.150.0.0/20"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldTokenBoundCIDRs+".#", "4"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldTokenBoundCIDRs+".0", "10.148.1.1/32"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldTokenBoundCIDRs+".1", "10.150.0.0/20"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldTokenBoundCIDRs+".2", "10.150.2.1"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldTokenBoundCIDRs+".3", "::1/128"),
				),
			},
			{
				ResourceName:      "vault_approle_auth_backend_role.role",
				ImportState:       true,
				ImportStateVerify: true,
				// TODO: once we fully enforce that the values are in CIDR notation then we can drop this ignore.
				ImportStateVerifyIgnore: []string{TokenFieldBoundCIDRs},
			},
		},
	})
}

func TestAccAppRoleAuthBackendRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAppRoleAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAppRoleAuthBackendRoleConfig_basic(backend, role, ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldBackend, backend),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldRoleName, role),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenPolicies+".#", "3"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_role.role",
						consts.FieldRoleID),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenTTL, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenMaxTTL, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenNumUses, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldSecretIDTTL, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldSecretIDNumUses, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenPeriod, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldBindSecretID, "true"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldLocalSecretIDs, "false"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldSecretIDBoundCIDRs+".#", "0"),
				),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					if !meta.IsAPISupported(provider.VaultVersion121) {
						return true, nil
					}

					return !meta.IsEnterpriseSupported(), nil
				},
				Config: testAccAppRoleAuthBackendRoleConfig_basic(backend, role, aliasMetadataConfig),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldBackend, backend),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldRoleName, role),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenPolicies+".#", "3"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_role.role",
						consts.FieldRoleID),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenTTL, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenMaxTTL, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenNumUses, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldSecretIDTTL, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldSecretIDNumUses, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenPeriod, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldBindSecretID, "true"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldSecretIDBoundCIDRs+".#", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"alias_metadata.%", "1"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"alias_metadata.foo", "bar"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldLocalSecretIDs, "false"),
				),
			},
		},
	})
}

func TestAccAppRoleAuthBackendRole_update(t *testing.T) {
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAppRoleAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAppRoleAuthBackendRoleConfig_basic(backend, role, ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldBackend, backend),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldRoleName, role),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenPolicies+".#", "3"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_role.role",
						consts.FieldRoleID),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenTTL, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenMaxTTL, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenNumUses, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldSecretIDTTL, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldSecretIDNumUses, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenPeriod, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldBindSecretID, "true"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldSecretIDBoundCIDRs+".#", "0"),
				),
			},
			{
				Config: testAccAppRoleAuthBackendRoleConfig_update(backend, role),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldBackend, backend),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldRoleName, role),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenPolicies+".#", "2"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_role.role",
						consts.FieldRoleID),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenTTL, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenMaxTTL, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenNumUses, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldSecretIDTTL, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldSecretIDNumUses, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenPeriod, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldBindSecretID, "true"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldSecretIDBoundCIDRs+".#", "0"),
				),
			},
		},
	})
}

func TestAccAppRoleAuthBackendRole_full(t *testing.T) {
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")
	roleID := acctest.RandomWithPrefix("test-role-id")
	resourcePath := "vault_approle_auth_backend_role.role"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAppRoleAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAppRoleAuthBackendRoleConfig_full(backend, role, roleID),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourcePath, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldRoleName, role),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldTokenPolicies+".#", "3"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldRoleID, roleID),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldTokenTTL, "3600"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldTokenMaxTTL, "7200"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldTokenNumUses, "12"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldTokenBoundCIDRs+".#", "4"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldTokenBoundCIDRs+".0", "10.148.1.1/32"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldTokenBoundCIDRs+".1", "10.150.0.0/20"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldTokenBoundCIDRs+".2", "10.150.2.1"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldTokenBoundCIDRs+".3", "::1/128"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldSecretIDTTL, "600"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldSecretIDNumUses, "5"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldTokenPeriod, "0"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldBindSecretID, "false"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldSecretIDBoundCIDRs+".#", "2"),
					resource.TestCheckResourceAttr(resourcePath, consts.FieldLocalSecretIDs, "true"),
				),
			},
		},
	})
}

func TestAccAppRoleAuthBackendRole_fullUpdate(t *testing.T) {
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")
	roleID := acctest.RandomWithPrefix("test-role-id")
	newRoleID := acctest.RandomWithPrefix("test-role-id")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAppRoleAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAppRoleAuthBackendRoleConfig_full(backend, role, roleID),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldBackend, backend),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldRoleName, role),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenPolicies+".#", "3"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldRoleID, roleID),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenTTL, "3600"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenMaxTTL, "7200"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenNumUses, "12"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldSecretIDTTL, "600"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldSecretIDNumUses, "5"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenPeriod, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldBindSecretID, "false"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldSecretIDBoundCIDRs+".#", "2"),
				),
			},
			{
				Config: testAccAppRoleAuthBackendRoleConfig_fullUpdate(backend, role, newRoleID),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldBackend, backend),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldRoleName, role),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenPolicies+".#", "2"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldRoleID, newRoleID),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenTTL, "7200"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenMaxTTL, "10800"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenNumUses, "24"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldSecretIDTTL, "1200"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldSecretIDNumUses, "10"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenPeriod, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldBindSecretID, "true"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldSecretIDBoundCIDRs+".#", "2"),
				),
			},
			{
				Config: testAccAppRoleAuthBackendRoleConfig_basic(backend, role, `local_secret_ids = true`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldBackend, backend),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldRoleName, role),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenPolicies+".#", "3"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_role.role",
						consts.FieldRoleID),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenTTL, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenMaxTTL, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenNumUses, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldSecretIDTTL, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldSecretIDNumUses, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldTokenPeriod, "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldBindSecretID, "true"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldSecretIDBoundCIDRs+".#", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						consts.FieldLocalSecretIDs, "true"),
				),
			},
		},
	})
}

func testAccCheckAppRoleAuthBackendRoleDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_approle_auth_backend_role" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for AppRole auth backend role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("AppRole auth backend role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccAppRoleAuthBackendRoleConfig_basic(backend, role, extraConfig string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "%s"
}

resource "vault_approle_auth_backend_role" "role" {
  backend = vault_auth_backend.approle.path
  role_name = "%s"
  token_policies = ["default", "dev", "prod"]
 
  %s
}`, backend, role, extraConfig)
}

func testAccAppRoleAuthBackendRoleConfig_update(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "%s"
}

resource "vault_approle_auth_backend_role" "role" {
  backend = vault_auth_backend.approle.path
  role_name = "%s"
  token_policies = ["default", "dev"]

}`, backend, role)
}

func testAccAppRoleAuthBackendRoleConfig_full(backend, role, roleID string) string {
	config := fmt.Sprintf(`
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "%s"
}

resource "vault_approle_auth_backend_role" "role" {
  backend = vault_auth_backend.approle.path
  role_name = "%s"
  role_id = "%s"
  bind_secret_id = false
  secret_id_bound_cidrs = ["10.148.0.0/20", "10.150.0.0/20"]
  token_policies = ["default", "dev", "prod"]
  secret_id_num_uses = 5
  secret_id_ttl = 600
  token_num_uses = 12
  token_ttl = 3600
  token_max_ttl = 7200
  token_bound_cidrs = ["10.148.1.1/32", "10.150.0.0/20", "10.150.2.1", "::1/128"]
  local_secret_ids = true
}
`, backend, role, roleID)

	return config
}

func testAccAppRoleAuthBackendRoleConfig_fullUpdate(backend, role, roleID string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "%s"
}

resource "vault_approle_auth_backend_role" "role" {
  backend = vault_auth_backend.approle.path
  role_name = "%s"
  role_id = "%s"
  bind_secret_id = true
  secret_id_bound_cidrs = ["10.150.0.0/20", "10.152.0.0/20"]
  token_policies = ["default", "dev"]
  secret_id_num_uses = 10
  secret_id_ttl = 1200
  token_num_uses = 24
  token_ttl = 7200
  local_secret_ids = true
  token_max_ttl = 10800
}`, backend, role, roleID)
}

func TestAccAppRoleAuthBackendRole_localSecretIDs_cannotUpdate(t *testing.T) {
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckAppRoleAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				// create with local_secret_ids = true
				Config: testAccAppRoleAuthBackendRoleConfig_basic(backend, role, `local_secret_ids = true`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role", "local_secret_ids", "true"),
				),
			},
			{
				// attempt to update local_secret_ids to false — Vault returns an immutability error.
				Config:      testAccAppRoleAuthBackendRoleConfig_basic(backend, role, `local_secret_ids = false`),
				ExpectError: regexp.MustCompile(`local_secret_ids can only be modified during role creation`),
			},
		},
	})
}
