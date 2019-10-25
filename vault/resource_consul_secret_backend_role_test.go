package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func TestConsulSecretBackendRole(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-backend")
	name := acctest.RandomWithPrefix("tf-test-name")
	token := "026a0c16-87cd-4c2d-b3f3-fb539f592b7e"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccConsulSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testConsulSecretBackendRole_initialConfig(backend, name, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_consul_secret_backend_role.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_consul_secret_backend_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_consul_secret_backend_role.test", "ttl", "0"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend_role.test", "policies.0", "foo"),
				),
			},
			{
				Config: testConsulSecretBackendRole_updateConfig(backend, name, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_consul_secret_backend_role.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_consul_secret_backend_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_consul_secret_backend_role.test", "ttl", "120"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend_role.test", "max_ttl", "240"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend_role.test", "local", "true"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend_role.test", "token_type", "client"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend_role.test", "policies.0", "foo"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend_role.test", "policies.1", "bar"),
				),
			},
		},
	})
}

func testAccConsulSecretBackendRoleCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_consul_secret_backend_role" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return err
		}
		if secret != nil {
			return fmt.Errorf("role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testConsulSecretBackendRole_initialConfig(backend, name, token string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  address = "127.0.0.1:8500"
  token = "%s"
}

resource "vault_consul_secret_backend_role" "test" {
  backend = vault_consul_secret_backend.test.path
  name = "%s"

  policies = [
    "foo"
  ]
}`, backend, token, name)
}

func testConsulSecretBackendRole_updateConfig(backend, name, token string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  address = "127.0.0.1:8500"
  token = "%s"
}

resource "vault_consul_secret_backend_role" "test" {
  backend = vault_consul_secret_backend.test.path
  name = "%s"

  policies = [
    "foo",
    "bar",
  ]
  ttl = 120
  max_ttl = 240
  local = true
  token_type = "client"

}`, backend, token, name)
}
