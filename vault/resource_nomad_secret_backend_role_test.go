package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/terraform"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/vault/api"
)

const testAccNomadSecretBackendRoleTags_basic = `management`
const testAccNomadSecretBackendRoleTags_updated = `management,policymaker`

func TestAccNomadSecretBackendRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-nomad")
	name := acctest.RandomWithPrefix("tf-test-nomad")
	address, token := getTestNomadCreds(t)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccNomadSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccNomadSecretBackendRoleConfig_basic(name, backend, address, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_nomad_secret_backend_role.test", "name", fmt.Sprintf("%s", name)),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend_role.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend_role.test", "policies", "readonly"),
				),
			},
			{
				Config: testAccNomadSecretBackendRoleConfig_updated(name, backend, address, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_nomad_secret_backend_role.test", "name", fmt.Sprintf("%s", name)),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend_role.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend_role.test", "policies", "readonly"),
				),
			},
		},
	})
}

func TestAccNomadSecretBackendRole_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-nomad")
	name := acctest.RandomWithPrefix("tf-test-nomad")
	address, token := getTestNomadCreds(t)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccNomadSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccNomadSecretBackendRoleConfig_basic(name, backend, address, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_nomad_secret_backend_role.test", "name", fmt.Sprintf("%s", name)),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend_role.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend_role.test", "policies", "readonly"),
				),
			},
			{
				ResourceName:      "vault_nomad_secret_backend_role.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccNomadSecretBackendRole_nested(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-nomad")
	name := acctest.RandomWithPrefix("tf-test-nomad")
	address, token, password := getTestNomadCreds(t)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccNomadSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccNomadSecretBackendRoleConfig_basic(name, backend, address, token, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_nomad_secret_backend_role.test", "name", fmt.Sprintf("%s", name)),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend_role.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend_role.test", "policies", "readonly"),
				),
			},
			{
				Config: testAccNomadSecretBackendRoleConfig_updated(name, backend, address, token, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_nomad_secret_backend_role.test", "name", fmt.Sprintf("%s", name)),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend_role.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend_role.test", "policies", "readonly"),
				),
			},
		},
	})
}

func testAccNomadSecretBackendRoleCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_nomad_secret_backend_role" {
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

func testAccNomadSecretBackendRoleConfig_basic(name, path, address, token string) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  address = "%s"
  token = "%s"
}

resource "vault_nomad_secret_backend_role" "test" {
  backend = "${vault_nomad_secret_backend.test.path}"
  name = "%s"
  tags = %q
  policies = "readonly"
}
`, path, address, token, name, testAccNomadSecretBackendRoleTags_basic)
}

func testAccNomadSecretBackendRoleConfig_updated(name, path, address, token string) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 1800
  max_lease_ttl_seconds = 43200
  address = "%s"
  token = "%s"
  policies = "readonly"
}

resource "vault_nomad_secret_backend_role" "test" {
  backend = "${vault_nomad_secret_backend.test.path}"
  name = "%s"
  policies = "readonly"
}
`, path, address, token, name, testAccNomadSecretBackendRoleTags_updated)
}
