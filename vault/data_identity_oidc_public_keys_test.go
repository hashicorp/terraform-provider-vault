// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceIdentityOIDCPublicKeys(t *testing.T) {
	t.Parallel()
	keyName := acctest.RandomWithPrefix("test-key")
	clientName := acctest.RandomWithPrefix("test-client")
	providerName := acctest.RandomWithPrefix("test-provider")

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceIdentityOIDCPublicKeys_config(keyName, clientName, providerName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_identity_oidc_public_keys.public", "name", providerName),
					resource.TestCheckResourceAttr("data.vault_identity_oidc_public_keys.public", "keys.#", "2"),
				),
			},
		},
	})
}

func testDataSourceIdentityOIDCPublicKeys_config(keyName, clientName, providerName string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "test" {
  name               = "%s"
  allowed_client_ids = ["*"]
  rotation_period    = 3600
  verification_ttl   = 3600
}

resource "vault_identity_oidc_client" "test" {
  name          = "%s"
  key           = vault_identity_oidc_key.test.name
  redirect_uris = [
	"http://127.0.0.1:9200/v1/auth-methods/oidc:authenticate:callback", 
	"http://127.0.0.1:8251/callback",
	"http://127.0.0.1:8080/callback"
  ]
  id_token_ttl     = 2400
  access_token_ttl = 7200
}

resource "vault_identity_oidc_provider" "test" {
  name = "%s"
  allowed_client_ids = [
     vault_identity_oidc_client.test.client_id
  ]
}

data "vault_identity_oidc_public_keys" "public" {
  name = vault_identity_oidc_provider.test.name
}`, keyName, clientName, providerName)
}
