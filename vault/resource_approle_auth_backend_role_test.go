// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccAppRoleAuthBackendRole_import(t *testing.T) {
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")
	roleID := acctest.RandomWithPrefix("test-role-id")
	resourcePath := "vault_approle_auth_backend_role.role"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		CheckDestroy:             testAccCheckAppRoleAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAppRoleAuthBackendRoleConfig_full(backend, role, roleID),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourcePath, "backend", backend),
					resource.TestCheckResourceAttr(resourcePath, "role_name", role),
					resource.TestCheckResourceAttr(resourcePath, "token_policies.#", "3"),
					resource.TestCheckResourceAttr(resourcePath, "role_id", roleID),
					resource.TestCheckResourceAttr(resourcePath, "token_ttl", "3600"),
					resource.TestCheckResourceAttr(resourcePath, "token_max_ttl", "7200"),
					resource.TestCheckResourceAttr(resourcePath, "token_num_uses", "12"),
					resource.TestCheckResourceAttr(resourcePath, "secret_id_ttl", "600"),
					resource.TestCheckResourceAttr(resourcePath, "secret_id_num_uses", "5"),
					resource.TestCheckResourceAttr(resourcePath, "token_period", "0"),
					resource.TestCheckResourceAttr(resourcePath, "bind_secret_id", "false"),
					resource.TestCheckResourceAttr(resourcePath, "secret_id_bound_cidrs.#", "2"),
					resource.TestCheckResourceAttr(resourcePath, "secret_id_bound_cidrs.0", "10.148.0.0/20"),
					resource.TestCheckResourceAttr(resourcePath, "secret_id_bound_cidrs.1", "10.150.0.0/20"),
					resource.TestCheckResourceAttr(resourcePath, "token_bound_cidrs.#", "4"),
					resource.TestCheckResourceAttr(resourcePath, "token_bound_cidrs.0", "10.148.1.1/32"),
					resource.TestCheckResourceAttr(resourcePath, "token_bound_cidrs.1", "10.150.0.0/20"),
					resource.TestCheckResourceAttr(resourcePath, "token_bound_cidrs.2", "10.150.2.1"),
					resource.TestCheckResourceAttr(resourcePath, "token_bound_cidrs.3", "::1/128"),
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
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		CheckDestroy:             testAccCheckAppRoleAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAppRoleAuthBackendRoleConfig_basic(backend, role),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"role_name", role),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_policies.#", "3"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_role.role",
						"role_id"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_ttl", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_max_ttl", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_num_uses", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"secret_id_ttl", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"secret_id_num_uses", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_period", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"bind_secret_id", "true"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"secret_id_bound_cidrs.#", "0"),
				),
			},
		},
	})
}

func TestAccAppRoleAuthBackendRole_update(t *testing.T) {
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		CheckDestroy:             testAccCheckAppRoleAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAppRoleAuthBackendRoleConfig_basic(backend, role),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"role_name", role),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_policies.#", "3"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_role.role",
						"role_id"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_ttl", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_max_ttl", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_num_uses", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"secret_id_ttl", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"secret_id_num_uses", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_period", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"bind_secret_id", "true"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"secret_id_bound_cidrs.#", "0"),
				),
			},
			{
				Config: testAccAppRoleAuthBackendRoleConfig_update(backend, role),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"role_name", role),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_policies.#", "2"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_role.role",
						"role_id"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_ttl", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_max_ttl", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_num_uses", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"secret_id_ttl", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"secret_id_num_uses", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_period", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"bind_secret_id", "true"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"secret_id_bound_cidrs.#", "0"),
				),
			},
		},
	})
}

func TestAccAppRoleAuthBackendRole_full(t *testing.T) {
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")
	roleID := acctest.RandomWithPrefix("test-role-id")
	resourcePath := "vault_approle_auth_backend_role.role"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		CheckDestroy:             testAccCheckAppRoleAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAppRoleAuthBackendRoleConfig_full(backend, role, roleID),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourcePath, "backend", backend),
					resource.TestCheckResourceAttr(resourcePath, "role_name", role),
					resource.TestCheckResourceAttr(resourcePath, "token_policies.#", "3"),
					resource.TestCheckResourceAttr(resourcePath, "role_id", roleID),
					resource.TestCheckResourceAttr(resourcePath, "token_ttl", "3600"),
					resource.TestCheckResourceAttr(resourcePath, "token_max_ttl", "7200"),
					resource.TestCheckResourceAttr(resourcePath, "token_num_uses", "12"),
					resource.TestCheckResourceAttr(resourcePath, "token_bound_cidrs.#", "4"),
					resource.TestCheckResourceAttr(resourcePath, "token_bound_cidrs.0", "10.148.1.1/32"),
					resource.TestCheckResourceAttr(resourcePath, "token_bound_cidrs.1", "10.150.0.0/20"),
					resource.TestCheckResourceAttr(resourcePath, "token_bound_cidrs.2", "10.150.2.1"),
					resource.TestCheckResourceAttr(resourcePath, "token_bound_cidrs.3", "::1/128"),
					resource.TestCheckResourceAttr(resourcePath, "secret_id_ttl", "600"),
					resource.TestCheckResourceAttr(resourcePath, "secret_id_num_uses", "5"),
					resource.TestCheckResourceAttr(resourcePath, "token_period", "0"),
					resource.TestCheckResourceAttr(resourcePath, "bind_secret_id", "false"),
					resource.TestCheckResourceAttr(resourcePath, "secret_id_bound_cidrs.#", "2"),
				),
			},
		},
	})
}

func TestAccAppRoleAuthBackendRole_fullUpdate(t *testing.T) {
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")
	roleID := acctest.RandomWithPrefix("test-role-id")
	newRoleID := acctest.RandomWithPrefix("test-role-id")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		CheckDestroy:             testAccCheckAppRoleAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAppRoleAuthBackendRoleConfig_full(backend, role, roleID),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"role_name", role),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_policies.#", "3"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"role_id", roleID),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_ttl", "3600"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_max_ttl", "7200"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_num_uses", "12"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"secret_id_ttl", "600"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"secret_id_num_uses", "5"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_period", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"bind_secret_id", "false"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"secret_id_bound_cidrs.#", "2"),
				),
			},
			{
				Config: testAccAppRoleAuthBackendRoleConfig_fullUpdate(backend, role, newRoleID),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"role_name", role),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_policies.#", "2"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"role_id", newRoleID),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_ttl", "7200"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_max_ttl", "10800"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_num_uses", "24"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"secret_id_ttl", "1200"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"secret_id_num_uses", "10"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_period", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"bind_secret_id", "true"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"secret_id_bound_cidrs.#", "2"),
				),
			},
			{
				Config: testAccAppRoleAuthBackendRoleConfig_basic(backend, role),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"role_name", role),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_policies.#", "3"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_role.role",
						"role_id"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_ttl", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_max_ttl", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_num_uses", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"secret_id_ttl", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"secret_id_num_uses", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"token_period", "0"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"bind_secret_id", "true"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role.role",
						"secret_id_bound_cidrs.#", "0"),
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

func testAccAppRoleAuthBackendRoleConfig_basic(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "%s"
}

resource "vault_approle_auth_backend_role" "role" {
  backend = vault_auth_backend.approle.path
  role_name = "%s"
  token_policies = ["default", "dev", "prod"]
}`, backend, role)
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
  token_max_ttl = 10800
}`, backend, role, roleID)
}
