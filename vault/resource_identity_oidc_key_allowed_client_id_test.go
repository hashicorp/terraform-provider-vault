package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
	"github.com/terraform-providers/terraform-provider-vault/util"
)

func TestAccIdentityOidcKeyAllowedClientId(t *testing.T) {
	name := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckIdentityOidcRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityOidcKeyAllowedClientIdConfig(name),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityOidcKeyAllowedClientIdCheckAttrs("vault_identity_oidc_key_allowed_client_id.role_one", 3),
					testAccIdentityOidcKeyAllowedClientIdCheckAttrs("vault_identity_oidc_key_allowed_client_id.role_two", 3),
					testAccIdentityOidcKeyAllowedClientIdCheckAttrs("vault_identity_oidc_key_allowed_client_id.role_three", 3),
				),
			},
			{
				Config: testAccIdentityOidcKeyAllowedClientIdRemove(name),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityOidcKeyAllowedClientIdCheckAttrs("vault_identity_oidc_key_allowed_client_id.role_one", 1),
				),
			},
			{
				Config: testAccIdentityOidcKeyAllowedClientIdRecreate(name),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityOidcKeyAllowedClientIdCheckAttrs("vault_identity_oidc_key_allowed_client_id.role", 1),
				),
			},
		},
	})
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

		path := identityOidcKeyPath(id)
		client := testProvider.Meta().(*api.Client)
		resp, err := client.Logical().Read(path)
		if err != nil {
			return fmt.Errorf("%q doesn't exist", path)
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

		if found, _ := util.SliceHasElement(resp.Data["allowed_client_ids"].([]interface{}), clientID); !found {
			return fmt.Errorf("Expected to find %q in the `allowed_client_ids` of key %s but did not", clientID, id)
		}

		if clientIDExpectedLength != len(resp.Data["allowed_client_ids"].([]interface{})) {
			return fmt.Errorf("Expected to find %d `allowed_client_ids` of key %s but found %d", clientIDExpectedLength, id, len(resp.Data["allowed_client_ids"].([]interface{})))
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

	rotation_period  = 3600
	verification_ttl = 3600
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
