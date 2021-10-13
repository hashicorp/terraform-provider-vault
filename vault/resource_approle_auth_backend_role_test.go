package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccAppRoleAuthBackendRole_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")
	roleID := acctest.RandomWithPrefix("test-role-id")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAppRoleAuthBackendRoleDestroy,
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
				ResourceName:      "vault_approle_auth_backend_role.role",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAppRoleAuthBackendRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAppRoleAuthBackendRoleDestroy,
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
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAppRoleAuthBackendRoleDestroy,
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
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")
	roleID := acctest.RandomWithPrefix("test-role-id")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAppRoleAuthBackendRoleDestroy,
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
		},
	})
}

func TestAccAppRoleAuthBackendRole_fullUpdate(t *testing.T) {
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")
	roleID := acctest.RandomWithPrefix("test-role-id")
	newRoleID := acctest.RandomWithPrefix("test-role-id")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAppRoleAuthBackendRoleDestroy,
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
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_approle_auth_backend_role" {
			continue
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
	return fmt.Sprintf(`
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
}`, backend, role, roleID)
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
