// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccIdentityOIDCProvider(t *testing.T) {
	providerName := acctest.RandomWithPrefix("test-provider")
	keyName := acctest.RandomWithPrefix("test-key")
	assignmentName := acctest.RandomWithPrefix("test-assignment")
	clientName := acctest.RandomWithPrefix("test-client")
	scopeName := acctest.RandomWithPrefix("test-scope")

	resourceName := "vault_identity_oidc_provider.test"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccCheckOIDCProviderDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityOIDCProviderConfig(keyName, assignmentName, clientName, scopeName, providerName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", providerName),
					resource.TestCheckResourceAttr(resourceName, "allowed_client_ids.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "scopes_supported.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "scopes_supported.0", scopeName),
				),
			},
		},
	})
}

func testAccIdentityOIDCProviderConfig(keyName, assignmentName, clientName, scopeName, providerName string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "test" {
  name               = "%s"
  allowed_client_ids = ["*"]
  rotation_period    = 3600
  verification_ttl   = 3600
}

resource "vault_identity_oidc_assignment" "test" {
  name       = "%s"
  entity_ids = ["fake-ascbascas-2231a-sdfaa"]
  group_ids  = ["fake-sajkdsad-32414-sfsada"]
}

resource "vault_identity_oidc_client" "test" {
  name          = "%s"
  key           = vault_identity_oidc_key.test.name
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
}

resource "vault_identity_oidc_scope" "test" {
  name        = "%s"
  template    = jsonencode(
  {
    groups   = "{{identity.entity.groups.names}}",
  }
  )
  description = "Groups scope."
}

resource "vault_identity_oidc_provider" "test" {
  name = "%s"
  https_enabled = false
  issuer_host = "127.0.0.1:8200"
  allowed_client_ids = [
     vault_identity_oidc_client.test.client_id
  ]
  scopes_supported = [
    vault_identity_oidc_scope.test.name
  ]
}`, keyName, assignmentName, clientName, scopeName, providerName)
}

func testAccCheckOIDCProviderDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_identity_oidc_provider" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		resp, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for OIDC provider at %s, err=%w", rs.Primary.ID, err)
		}
		if resp != nil {
			return fmt.Errorf("OIDC provider still exists at %s", rs.Primary.ID)
		}
	}
	return nil
}
