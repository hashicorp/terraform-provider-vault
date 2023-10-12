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

func TestDataSourceIdentityOIDCClientCreds(t *testing.T) {
	t.Parallel()
	name := acctest.RandomWithPrefix("test-client")

	resourceName := "data.vault_identity_oidc_client_creds.creds"
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceIdentityOIDCClientCreds_config(name, ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttrSet(resourceName, "client_secret"),
				),
			},
			{
				Config: testDataSourceIdentityOIDCClientCreds_config(name+"-pub", "public"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name+"-pub"),
					resource.TestCheckResourceAttr(resourceName, "client_secret", ""),
				),
			},
		},
	})
}

func testDataSourceIdentityOIDCClientCreds_config(name string, clientType string) string {
	var clientTypeConfig string
	if clientType != "" {
		clientTypeConfig = fmt.Sprintf(`  client_type = "%s"`, clientType)
	}

	config := fmt.Sprintf(`
resource "vault_identity_oidc_key" "key" {
  name               = "%s"
  allowed_client_ids = ["*"]
  rotation_period    = 3600
  verification_ttl   = 3600
}

resource "vault_identity_oidc_client" "test" {
  name          = "%s"
  key           = vault_identity_oidc_key.key.name
  redirect_uris = [
	"http://127.0.0.1:9200/v1/auth-methods/oidc:authenticate:callback",
	"http://127.0.0.1:8251/callback",
	"http://127.0.0.1:8080/callback"
  ]
  id_token_ttl     = 2400
  access_token_ttl = 7200
  %s
}

data "vault_identity_oidc_client_creds" "creds" {
  name = vault_identity_oidc_client.test.name
}
`, name, name, clientTypeConfig)

	return config
}
