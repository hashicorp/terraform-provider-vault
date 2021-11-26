package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccAppRoleAuthBackendRoleID_basic(t *testing.T) {
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
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_role.role",
						"role_id"),
				),
			},
			{
				Config: testAccAppRoleAuthBackendRoleIDConfig_basic(backend, role),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_approle_auth_backend_role_id.role",
						"backend", backend),
					resource.TestCheckResourceAttr("data.vault_approle_auth_backend_role_id.role",
						"role_name", role),
					resource.TestCheckResourceAttrSet("data.vault_approle_auth_backend_role_id.role",
						"role_id"),
				),
			},
		},
	})
}

func TestAccAppRoleAuthBackendRoleID_customID(t *testing.T) {
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
						"role_id", roleID),
				),
			},
			{
				Config: testAccAppRoleAuthBackendRoleIDConfig_customID(backend, role, roleID),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_approle_auth_backend_role_id.role",
						"backend", backend),
					resource.TestCheckResourceAttr("data.vault_approle_auth_backend_role_id.role",
						"role_name", role),
					resource.TestCheckResourceAttr("data.vault_approle_auth_backend_role_id.role",
						"role_id", roleID),
				),
			},
		},
	})
}

func testAccAppRoleAuthBackendRoleIDConfig_basic(backend, role string) string {
	return fmt.Sprintf(`
%s

data "vault_approle_auth_backend_role_id" "role" {
  backend = "%s"
  role_name = "%s"
}`, testAccAppRoleAuthBackendRoleConfig_basic(backend, role), backend, role)
}

func testAccAppRoleAuthBackendRoleIDConfig_customID(backend, role, roleID string) string {
	return fmt.Sprintf(`
%s

data "vault_approle_auth_backend_role_id" "role" {
  backend = "%s"
  role_name = "%s"
}`, testAccAppRoleAuthBackendRoleConfig_full(backend, role, roleID), backend, role)
}
