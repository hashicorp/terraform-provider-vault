package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccAppRoleAuthBackendLogin_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccAppRoleAuthBackendLoginConfig_basic(backend, role),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_approle_auth_backend_login.test",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_login.test",
						"policies.#", "3"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_login.test",
						"policies.0", "default"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_login.test",
						"policies.1", "dev"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_login.test",
						"policies.2", "prod"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_login.test",
						"role_id"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_login.test",
						"secret_id"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_login.test",
						"renewable"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_login.test",
						"lease_duration"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_login.test",
						"lease_started"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_login.test",
						"accessor"),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_login.test",
						"client_token"),
				),
			},
		},
	})
}

func testAccAppRoleAuthBackendLoginConfig_basic(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "%s"
}

resource "vault_approle_auth_backend_role" "role" {
  backend = vault_auth_backend.approle.path
  role_name = "%s"
  token_policies = ["default", "dev", "prod"]
}

resource "vault_approle_auth_backend_role_secret_id" "secret" {
  backend = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.role.role_name
}

resource "vault_approle_auth_backend_login" "test" {
  backend = vault_auth_backend.approle.path
  role_id = vault_approle_auth_backend_role.role.role_id
  secret_id = vault_approle_auth_backend_role_secret_id.secret.secret_id
}
`, backend, role)
}
