package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccAppRoleAuthBackendRoleSecretID_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAppRoleAuthBackendRoleSecretIDDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAppRoleAuthBackendRoleSecretIDConfig_basic(backend, role),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role_secret_id.secret_id",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role_secret_id.secret_id",
						"role_name", role),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_role_secret_id.secret_id",
						"accessor"),
				),
			},
		},
	})
}

func TestAccAppRoleAuthBackendRoleSecretID_full(t *testing.T) {
	backend := acctest.RandomWithPrefix("approle")
	role := acctest.RandomWithPrefix("test-role")
	secretID := acctest.RandomWithPrefix("test-role-id")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAppRoleAuthBackendRoleSecretIDDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAppRoleAuthBackendRoleSecretIDConfig_full(backend, role, secretID),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role_secret_id.secret_id",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role_secret_id.secret_id",
						"role_name", role),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role_secret_id.secret_id",
						"secret_id", secretID),
					resource.TestCheckResourceAttrSet("vault_approle_auth_backend_role_secret_id.secret_id",
						"accessor"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role_secret_id.secret_id",
						"cidr_list.#", "2"),
					resource.TestCheckResourceAttr("vault_approle_auth_backend_role_secret_id.secret_id",
						"metadata", `{"hello":"world"}`),
				),
			},
		},
	})
}

func testAccCheckAppRoleAuthBackendRoleSecretIDDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_approle_auth_backend_role_secret_id" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for AppRole auth backend role SecretID %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("AppRole auth backend role SecretID %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccAppRoleAuthBackendRoleSecretIDConfig_basic(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "%s"
}

resource "vault_approle_auth_backend_role" "role" {
  backend = "${vault_auth_backend.approle.path}"
  role_name = "%s"
  policies = ["default", "dev", "prod"]
}

resource "vault_approle_auth_backend_role_secret_id" "secret_id" {
  role_name = "${vault_approle_auth_backend_role.role.role_name}"
  backend = "${vault_auth_backend.approle.path}"
}`, backend, role)
}

func testAccAppRoleAuthBackendRoleSecretIDConfig_full(backend, role, secretID string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "%s"
}

resource "vault_approle_auth_backend_role" "role" {
  backend = "${vault_auth_backend.approle.path}"
  role_name = "%s"
  policies = ["default", "dev", "prod"]
}

resource "vault_approle_auth_backend_role_secret_id" "secret_id" {
  role_name = "${vault_approle_auth_backend_role.role.role_name}"
  backend = "${vault_auth_backend.approle.path}"
  cidr_list = ["10.148.0.0/20", "10.150.0.0/20"]
  metadata = <<EOF
{
  "hello": "world"
}
EOF

  secret_id = "%s"
}`, backend, role, secretID)
}
