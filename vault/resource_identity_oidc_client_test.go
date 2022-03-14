package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccIdentityOIDCClient(t *testing.T) {
	name := acctest.RandomWithPrefix("test-scope")
	resourceName := "vault_identity_oidc_client.client"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckOIDCClientDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityOIDCClientConfig_basic(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "key", "default"),
					resource.TestCheckResourceAttr(resourceName, "redirect_uris.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "redirect_uris.0", "http://127.0.0.1:8251/callback"),
					resource.TestCheckResourceAttr(resourceName, "redirect_uris.1", "http://127.0.0.1:9200/v1/auth-methods/oidc:authenticate:callback"),
					resource.TestCheckResourceAttr(resourceName, "assignments.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "assignments.0", "my-assignment"),
					resource.TestCheckResourceAttr(resourceName, "id_token_ttl", "1800"),
					resource.TestCheckResourceAttr(resourceName, "access_token_ttl", "3600"),
				),
			},
			{
				Config: testAccIdentityOIDCClientConfig_update(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "key", "default"),
					resource.TestCheckResourceAttr(resourceName, "redirect_uris.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "redirect_uris.0", "http://127.0.0.1:8080/callback"),
					resource.TestCheckResourceAttr(resourceName, "redirect_uris.1", "http://127.0.0.1:8251/callback"),
					resource.TestCheckResourceAttr(resourceName, "redirect_uris.2", "http://127.0.0.1:9200/v1/auth-methods/oidc:authenticate:callback"),
					resource.TestCheckResourceAttr(resourceName, "assignments.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "assignments.0", "my-assignment"),
					resource.TestCheckResourceAttr(resourceName, "id_token_ttl", "2400"),
					resource.TestCheckResourceAttr(resourceName, "access_token_ttl", "7200"),
				),
			},
		},
	})
}

func testAccIdentityOIDCClientConfig_basic(name string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "default" {
  name               = "default"
  allowed_client_ids = ["*"]
  rotation_period    = 3600
  verification_ttl   = 3600
}

resource "vault_identity_oidc_assignment" "test" {
  name       = "my-assignment"
  entity_ids = ["ascbascas-2231a-sdfaa"]
  group_ids  = ["sajkdsad-32414-sfsada"]
}


resource "vault_identity_oidc_client" "client" {
  name          = "%s"
  key           = vault_identity_oidc_key.default.name
  redirect_uris = [
	"http://127.0.0.1:9200/v1/auth-methods/oidc:authenticate:callback",
	"http://127.0.0.1:8251/callback"
  ]
  assignments = [
    vault_identity_oidc_assignment.test.name
  ]
  id_token_ttl     = 1800
  access_token_ttl = 3600
}`, name)
}

func testAccIdentityOIDCClientConfig_update(name string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "default" {
  name               = "default"
  allowed_client_ids = ["*"]
  rotation_period    = 3600
  verification_ttl   = 3600
}

resource "vault_identity_oidc_assignment" "test" {
  name       = "my-assignment"
  entity_ids = ["ascbascas-2231a-sdfaa"]
  group_ids  = ["sajkdsad-32414-sfsada"]
}


resource "vault_identity_oidc_client" "client" {
  name          = "%s"
  key           = vault_identity_oidc_key.default.name
  redirect_uris = [
	"http://127.0.0.1:9200/v1/auth-methods/oidc:authenticate:callback", 
	"http://127.0.0.1:8251/callback",
	"http://127.0.0.1:8080/callback"
  ]
  assignments = [
    vault_identity_oidc_assignment.test.name
  ]
  id_token_ttl     = 2400
  access_token_ttl = 7200
}`, name)
}

func testAccCheckOIDCClientDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_identity_oidc_client" {
			continue
		}
		resp, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for OIDC client at %s, err=%w", rs.Primary.ID, err)
		}
		if resp != nil {
			return fmt.Errorf("OIDC client still exists at %s", rs.Primary.ID)
		}
	}
	return nil
}
