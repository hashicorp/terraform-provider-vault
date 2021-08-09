package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

func TestAccIdentityOidcKeyAllowedClientId(t *testing.T) {
	name := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckIdentityOidcKeyAllowedClientIdDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityOidcKeyAllowedClientIdConfig(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "rotation_period", "86400"),
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "verification_ttl", "86400"),
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "algorithm", "RS256"),
					testAccIdentityOidcKeyAllowedClientIdCheckAttrs("vault_identity_oidc_key_allowed_client_id.role_one", 3),
					testAccIdentityOidcKeyAllowedClientIdCheckAttrs("vault_identity_oidc_key_allowed_client_id.role_two", 3),
					testAccIdentityOidcKeyAllowedClientIdCheckAttrs("vault_identity_oidc_key_allowed_client_id.role_three", 3),
				),
			},
			{
				Config: testAccIdentityOidcKeyAllowedClientIdRemove(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "rotation_period", "86401"),
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "verification_ttl", "86401"),
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "algorithm", "RS256"),
					testAccIdentityOidcKeyAllowedClientIdCheckAttrs("vault_identity_oidc_key_allowed_client_id.role_one", 1),
				),
			},
			{
				Config: testAccIdentityOidcKeyAllowedClientIdRecreate(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "rotation_period", "86400"),
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "verification_ttl", "86400"),
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "algorithm", "RS256"),
					testAccIdentityOidcKeyAllowedClientIdCheckAttrs("vault_identity_oidc_key_allowed_client_id.role", 1),
				),
			},
		},
	})
}

func testAccCheckIdentityOidcKeyAllowedClientIdDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_identity_oidc_key_allowed_client_id" {
			continue
		}
		resp, err := identityOidcKeyApiRead(rs.Primary.ID, client)
		if err != nil {
			return err
		}
		if resp != nil {
			clientIDs := resp["allowed_client_ids"].([]interface{})
			clientID := rs.Primary.Attributes["allowed_client_id"]

			if found, _ := util.SliceHasElement(clientIDs, clientID); found {
				return fmt.Errorf("identity oidc key %s still has allowed_client_id %s", rs.Primary.ID, clientID)
			}
		}
	}
	return nil
}

func testAccIdentityOidcKeyAllowedClientIdCheckAttrs(clientIDResource string, clientIDExpectedLength int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_identity_oidc_key.key"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		id := instanceState.ID
		client := testProvider.Meta().(*api.Client)
		resp, err := identityOidcKeyApiRead(id, client)
		if err != nil {
			return err
		}

		clientIDResource := s.Modules[0].Resources[clientIDResource]
		if clientIDResource == nil {
			return fmt.Errorf("resource not found in state")
		}
		clientIDResourceState := clientIDResource.Primary
		if instanceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		clientID := clientIDResourceState.Attributes["allowed_client_id"]

		if found, _ := util.SliceHasElement(resp["allowed_client_ids"].([]interface{}), clientID); !found {
			return fmt.Errorf("Expected to find %q in the `allowed_client_ids` of key %s but did not", clientID, id)
		}

		if clientIDExpectedLength != len(resp["allowed_client_ids"].([]interface{})) {
			return fmt.Errorf("Expected to find %d `allowed_client_ids` of key %s but found %d", clientIDExpectedLength, id, len(resp["allowed_client_ids"].([]interface{})))
		}
		return nil
	}
}

func testAccIdentityOidcKeyAllowedClientIdConfig(entityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "key" {
  name = "%s"
  algorithm = "RS256"
}

resource "vault_identity_oidc_role" "role_one" {
  name = "%s-1"
  key = vault_identity_oidc_key.key.name
}

resource "vault_identity_oidc_role" "role_two" {
  name = "%s-2"
  key = vault_identity_oidc_key.key.name
}

resource "vault_identity_oidc_role" "role_three" {
  name = "%s-3"
  key = vault_identity_oidc_key.key.name
}

resource "vault_identity_oidc_key_allowed_client_id" "role_one" {
  key_name = vault_identity_oidc_key.key.name
  allowed_client_id = vault_identity_oidc_role.role_one.client_id
}

resource "vault_identity_oidc_key_allowed_client_id" "role_two" {
  key_name = vault_identity_oidc_key.key.name
  allowed_client_id = vault_identity_oidc_role.role_two.client_id
}

resource "vault_identity_oidc_key_allowed_client_id" "role_three" {
  key_name = vault_identity_oidc_key.key.name
  allowed_client_id = vault_identity_oidc_role.role_three.client_id
}
`, entityName, entityName, entityName, entityName)
}

func testAccIdentityOidcKeyAllowedClientIdRemove(entityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "key" {
  name = "%s"
	algorithm = "RS256"

	rotation_period  = 86401
	verification_ttl = 86401
}

resource "vault_identity_oidc_role" "role_one" {
  name = "%s-1"
  key = vault_identity_oidc_key.key.name
}

resource "vault_identity_oidc_key_allowed_client_id" "role_one" {
  key_name = vault_identity_oidc_key.key.name
  allowed_client_id = vault_identity_oidc_role.role_one.client_id
}
`, entityName, entityName)
}

func testAccIdentityOidcKeyAllowedClientIdRecreate(entityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "key" {
  name = "%s"
  algorithm = "RS256"
}

resource "vault_identity_oidc_role" "role" {
  name = "%s"
  key = vault_identity_oidc_key.key.name
}

resource "vault_identity_oidc_key_allowed_client_id" "role" {
  key_name = vault_identity_oidc_key.key.name
  allowed_client_id = vault_identity_oidc_role.role.client_id
}

`, entityName, entityName)
}
