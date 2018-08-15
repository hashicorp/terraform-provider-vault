package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
)

func testResourceTokenCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_token" {
			continue
		}
		_, err := client.Auth().Token().LookupAccessor(rs.Primary.ID)
		if err == nil {
			return fmt.Errorf("token with accessor %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func TestResourceToken_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testResourceTokenCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenConfig_basic(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_token.test", "policies.#", "1"),
				),
			},
		},
	})
}

func testResourceTokenConfig_basic() string {
	return `
resource "vault_policy" "test" {
	name = "test"
	policy = <<EOT
path "secret/*" { capabilities = [ "list" ] }
EOT
}

resource "vault_token" "test" {
	policies = [ "${vault_policy.test.name}" ]
	ttl = "60s"
}`
}

func TestResourceToken_role(t *testing.T) {
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testResourceTokenCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenConfig_role(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_token.test", "role_name", "test"),
					resource.TestCheckResourceAttr("vault_token.test", "policies.#", "1"),
				),
			},
		},
	})
}

func testResourceTokenConfig_role() string {
	return `
resource "vault_policy" "test" {
	name = "test"
	policy = <<EOT
path "secret/*" { capabilities = [ "list" ] }
EOT
}

resource "vault_token_role" "test" {
	name = "test"
}

resource "vault_token" "test" {
	role_name = "${vault_token_role.test.name}"
	policies = [ "${vault_policy.test.name}" ]
	ttl = "60s"
}`
}
