// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccIdentityOIDCClient(t *testing.T) {
	testutil.SkipTestAcc(t)

	keyName := acctest.RandomWithPrefix("test-key")
	assignmentName := acctest.RandomWithPrefix("test-assignment")
	clientName := acctest.RandomWithPrefix("test-client")
	resourceName := "vault_identity_oidc_client.client"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckOIDCClientDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityOIDCClientConfig_basic(keyName, assignmentName, clientName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", clientName),
					resource.TestCheckResourceAttr(resourceName, "key", keyName),
					resource.TestCheckResourceAttr(resourceName, "redirect_uris.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "redirect_uris.0", "http://127.0.0.1:8251/callback"),
					resource.TestCheckResourceAttr(resourceName, "redirect_uris.1", "http://127.0.0.1:9200/v1/auth-methods/oidc:authenticate:callback"),
					resource.TestCheckResourceAttr(resourceName, "assignments.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "assignments.0", assignmentName),
					resource.TestCheckResourceAttr(resourceName, "id_token_ttl", "1800"),
					resource.TestCheckResourceAttr(resourceName, "access_token_ttl", "3600"),
					resource.TestCheckResourceAttr(resourceName, "client_type", "confidential"),
				),
			},
			{
				Config: testAccIdentityOIDCClientConfig_update(keyName, assignmentName, clientName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", clientName),
					resource.TestCheckResourceAttr(resourceName, "key", keyName),
					resource.TestCheckResourceAttr(resourceName, "redirect_uris.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "redirect_uris.0", "http://127.0.0.1:8080/callback"),
					resource.TestCheckResourceAttr(resourceName, "redirect_uris.1", "http://127.0.0.1:8251/callback"),
					resource.TestCheckResourceAttr(resourceName, "redirect_uris.2", "http://127.0.0.1:9200/v1/auth-methods/oidc:authenticate:callback"),
					resource.TestCheckResourceAttr(resourceName, "assignments.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "assignments.0", assignmentName),
					resource.TestCheckResourceAttr(resourceName, "id_token_ttl", "2400"),
					resource.TestCheckResourceAttr(resourceName, "access_token_ttl", "7200"),
					resource.TestCheckResourceAttr(resourceName, "client_type", "confidential"),
				),
			},
		},
	})
}

func testAccIdentityOIDCClientConfig_basic(keyName, assignmentName, clientName string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "key" {
  name               = "%s"
  allowed_client_ids = ["*"]
  rotation_period    = 3600
  verification_ttl   = 3600
}

resource "vault_identity_oidc_assignment" "test" {
  name       = "%s"
  entity_ids = ["ascbascas-2231a-sdfaa"]
  group_ids  = ["sajkdsad-32414-sfsada"]
}


resource "vault_identity_oidc_client" "client" {
  name          = "%s"
  key           = vault_identity_oidc_key.key.name
  redirect_uris = [
	"http://127.0.0.1:9200/v1/auth-methods/oidc:authenticate:callback",
	"http://127.0.0.1:8251/callback"
  ]
  assignments = [
    vault_identity_oidc_assignment.test.name
  ]
  id_token_ttl     = 1800
  access_token_ttl = 3600
  client_type      = "confidential"
}`, keyName, assignmentName, clientName)
}

func testAccIdentityOIDCClientConfig_update(keyName, assignmentName, clientName string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "key" {
  name               = "%s"
  allowed_client_ids = ["*"]
  rotation_period    = 3600
  verification_ttl   = 3600
}

resource "vault_identity_oidc_assignment" "test" {
  name       = "%s"
  entity_ids = ["ascbascas-2231a-sdfaa"]
  group_ids  = ["sajkdsad-32414-sfsada"]
}


resource "vault_identity_oidc_client" "client" {
  name          = "%s"
  key           = vault_identity_oidc_key.key.name
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
  client_type      = "confidential"
}`, keyName, assignmentName, clientName)
}

func testAccCheckOIDCClientDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_identity_oidc_client" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
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
