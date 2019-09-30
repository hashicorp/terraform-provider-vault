package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
)

func TestConsulSecretBackendRole(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-path")
	name := acctest.RandomWithPrefix("tf-test-name")
	token := "026a0c16-87cd-4c2d-b3f3-fb539f592b7e"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccConsulSecretBackendRoleCheckDestroy(path, name),
		Steps: []resource.TestStep{
			{
				Config: testConsulSecretBackendRole_initialConfig(path, name, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "name", name),
					resource.TestCheckResourceAttrSet("vault_consul_secret_backend.test", "policies"),
				),
			},
			{
				Config: testConsulSecretBackendRole_updateConfig(path, name, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "name", name),
					resource.TestCheckResourceAttrSet("vault_consul_secret_backend.test", "policies"),
				),
			},
		},
	})
}

func testAccConsulSecretBackendRoleCheckDestroy(path, name string) func(*terraform.State) error {
	return func(s *terraform.State) error {
		client := testProvider.Meta().(*api.Client)

		for _, rs := range s.RootModule().Resources {
			if rs.Type != "vault_consul_secret_backend_role" {
				continue
			}

			reqPath := consulSecretBackendRolePath(path, name)

			secret, err := client.Logical().Read(reqPath)
			if err != nil {
				return err
			}

			if secret != nil {
				return fmt.Errorf("Role %q still exists", reqPath)
			}
		}

		return nil
	}
}

func testConsulSecretBackendRole_initialConfig(path, name, token string) string {
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
  path = "%s"
  name = "%s"

  policies = [
    "foo"
  ]
}`, path, token, path, name)
}

func testConsulSecretBackendRole_updateConfig(path, name, token string) string {
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
  path = "%s"
  name = "%s"

  policies = [
    "foo",
    "bar",
  ]
}`, path, token, path, name)
}
