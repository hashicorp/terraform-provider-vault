package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

func TestAccNomadSecretBackendRoleClientBasic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-nomad")
	address, token := util.GetTestNomadCreds(t)

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { util.TestAccPreCheck(t) },
		CheckDestroy: testAccNomadSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testNomadSecretBackendRoleClientConfig(backend, address, token, "bob", "readonly", true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_nomad_secret_role.test", "role", "bob"),
					resource.TestCheckResourceAttr("vault_nomad_secret_role.test", "policies.#", "1"),
					resource.TestCheckResourceAttr("vault_nomad_secret_role.test", "policies.0", "readonly"),
					resource.TestCheckResourceAttr("vault_nomad_secret_role.test", "global", "true"),
					resource.TestCheckResourceAttr("vault_nomad_secret_role.test", "type", "client"),
				),
			},
		},
	})
}

func TestAccNomadSecretBackendRoleManagementBasic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-nomad")
	address, token := util.GetTestNomadCreds(t)

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { util.TestAccPreCheck(t) },
		CheckDestroy: testAccNomadSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testNomadSecretBackendRoleManagementConfig(backend, address, token, "bob", false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_nomad_secret_role.test", "role", "bob"),
					resource.TestCheckResourceAttr("vault_nomad_secret_role.test", "policies.#", "0"),
					resource.TestCheckResourceAttr("vault_nomad_secret_role.test", "global", "false"),
					resource.TestCheckResourceAttr("vault_nomad_secret_role.test", "type", "management"),
				),
			},
		},
	})
}

func TestAccNomadSecretBackendRoleImport(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-nomad")
	address, token := util.GetTestNomadCreds(t)

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { util.TestAccPreCheck(t) },
		CheckDestroy: testAccADSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testNomadSecretBackendRoleClientConfig(backend, address, token, "bob", "readonly", true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_nomad_secret_role.test", "role", "bob"),
					resource.TestCheckResourceAttr("vault_nomad_secret_role.test", "policies.#", "1"),
					resource.TestCheckResourceAttr("vault_nomad_secret_role.test", "policies.0", "readonly"),
					resource.TestCheckResourceAttr("vault_nomad_secret_role.test", "global", "true"),
					resource.TestCheckResourceAttr("vault_nomad_secret_role.test", "type", "client"),
				),
			},
			{
				ResourceName:      "vault_nomad_secret_role.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccNomadSecretBackendRoleCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_nomad_secret_role" {
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

func testNomadSecretBackendRoleClientConfig(backend, address, token, role, policies string, global bool) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "config" {
	backend = "%s"
	description = "test description"
	default_lease_ttl_seconds = "3600"
	max_lease_ttl_seconds = "7200"
	address = "%s"
	token = "%s"
}

resource "vault_nomad_secret_role" "test" {
    backend = vault_nomad_secret_backend.config.backend
	role = "%s"
	type = "client"
	policies = ["%s"]
	global = "%t"
}
`, backend, address, token, role, policies, global)
}

func testNomadSecretBackendRoleManagementConfig(backend, address, token, role string, global bool) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "config" {
	backend = "%s"
	description = "test description"
	default_lease_ttl_seconds = "3600"
	max_lease_ttl_seconds = "7200"
	address = "%s"
	token = "%s"
}

resource "vault_nomad_secret_role" "test" {
    backend = vault_nomad_secret_backend.config.backend
	role = "%s"
	type = "management"
	global = "%t"
}
`, backend, address, token, role, global)
}
