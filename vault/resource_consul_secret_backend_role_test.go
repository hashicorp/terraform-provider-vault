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
					resource.TestCheckResourceAttr("vault_consul_secret_backend_role.test_path", "path", backend),
					resource.TestCheckResourceAttr("vault_consul_secret_backend_role.test_path", "policies.0", "foo"),
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
					resource.TestCheckResourceAttr("vault_consul_secret_backend_role.test_path", "path", backend),
					resource.TestCheckResourceAttr("vault_consul_secret_backend_role.test_path", "ttl", "120"),
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
}
resource "vault_consul_secret_backend_role" "test_path" {
  path = vault_consul_secret_backend.test.path
  name = "%[2]s_path"

  policies = [
    "foo"
  ]
}
`, backend, token, name)
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
}
resource "vault_consul_secret_backend_role" "test_path" {
  path = vault_consul_secret_backend.test.path
  name = "%[2]s_path"

  policies = [
    "foo"
  ]
  ttl = 120
}
`, backend, token, name)
}

func TestConsulSecretBackendRoleNameFromPath(t *testing.T) {
	{
		name, err := consulSecretBackendRoleNameFromPath("foo/roles/bar")
		if err != nil {
			t.Fatalf("error getting name: %v", err)
		}
		if name != "bar" {
			t.Fatalf("expected name 'bar', but got %s", name)
		}
	}

	{
		name, err := consulSecretBackendRoleNameFromPath("no match")
		if err == nil {
			t.Fatal("Expected error getting name but got nil")
		}
		if name != "" {
			t.Fatalf("expected empty name, but got %s", name)
		}
	}
}

func TestConsulSecretBackendRoleBackendFromPath(t *testing.T) {
	{
		backend, err := consulSecretBackendRoleBackendFromPath("foo/roles/bar")
		if err != nil {
			t.Fatalf("error getting backend: %v", err)
		}
		if backend != "foo" {
			t.Fatalf("expected backend 'foo', but got %s", backend)
		}
	}

	{
		backend, err := consulSecretBackendRoleBackendFromPath("no match")
		if err == nil {
			t.Fatal("Expected error getting backend but got nil")
		}
		if backend != "" {
			t.Fatalf("expected empty backend, but got %s", backend)
		}
	}
}
