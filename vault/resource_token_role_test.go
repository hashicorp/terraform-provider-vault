package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
)

func testResourceTokenRoleCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_token_role" {
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

func TestResourceTokenRole_basic(t *testing.T) {
	name := acctest.RandomWithPrefix("role")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testResourceTokenRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenRoleConfig_basic(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_token_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_token_role.test", "allowed_policies.#", "2"),
					resource.TestCheckResourceAttr("vault_token_role.test", "allowed_policies.0", "dev"),
					resource.TestCheckResourceAttr("vault_token_role.test", "allowed_policies.1", "prod"),
					resource.TestCheckResourceAttr("vault_token_role.test", "disallowed_policies.#", "1"),
					resource.TestCheckResourceAttr("vault_token_role.test", "disallowed_policies.0", "test"),
				),
			},
		},
	})
}

func testResourceTokenRoleConfig_basic(name string) string {
	return fmt.Sprintf(`
resource "vault_token_role" "test" {
  name = "%s"
  allowed_policies = [ "dev", "prod" ]
  disallowed_policies = [ "test" ]
}`, name)
}

func TestResourceTokenRole_update(t *testing.T) {
	name := acctest.RandomWithPrefix("role")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testResourceTokenRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenRoleConfig_basic(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_token_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_token_role.test", "allowed_policies.#", "2"),
					resource.TestCheckResourceAttr("vault_token_role.test", "allowed_policies.0", "dev"),
					resource.TestCheckResourceAttr("vault_token_role.test", "allowed_policies.1", "prod"),
					resource.TestCheckResourceAttr("vault_token_role.test", "disallowed_policies.#", "1"),
					resource.TestCheckResourceAttr("vault_token_role.test", "disallowed_policies.0", "test"),
				),
			},
			{
				Config: testResourceTokenRoleConfig_update(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_token_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_token_role.test", "allowed_policies.#", "1"),
					resource.TestCheckResourceAttr("vault_token_role.test", "allowed_policies.0", "test"),
					resource.TestCheckResourceAttr("vault_token_role.test", "disallowed_policies.#", "2"),
					resource.TestCheckResourceAttr("vault_token_role.test", "disallowed_policies.0", "dev"),
					resource.TestCheckResourceAttr("vault_token_role.test", "disallowed_policies.1", "prod"),
				),
			},
		},
	})
}

func testResourceTokenRoleConfig_update(name string) string {
	return fmt.Sprintf(`
resource "vault_token_role" "test" {
  name = "%s"
  allowed_policies = [ "test" ]
  disallowed_policies = [ "dev", "prod" ]
}`, name)
}
