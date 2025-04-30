// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceIdentityOIDCOpenIDConfig(t *testing.T) {
	var p *schema.Provider
	testutil.SkipTestAcc(t)
	testutil.TestAccPreCheck(t)
	t.Parallel()

	providerName := acctest.RandomWithPrefix("test-provider")
	keyName := acctest.RandomWithPrefix("test-key")
	clientName := acctest.RandomWithPrefix("test-client")

	u, err := url.Parse(os.Getenv(api.EnvVaultAddress))
	if err != nil {
		t.Fatal(err)
	}

	if u.Hostname() == "localhost" {
		u.Host = fmt.Sprintf("%s:%s", "127.0.0.1", u.Port())
	}

	base, err := u.Parse(fmt.Sprintf("/v1/identity/oidc/provider/%s/", providerName))
	if err != nil {
		t.Fatal(err)
	}

	resourceName := "data.vault_identity_oidc_openid_config.config"
	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, "name", providerName),
		resource.TestCheckResourceAttr(resourceName, "issuer", strings.TrimRight(base.String(), "/")),
		resource.TestCheckResourceAttr(resourceName, "request_uri_parameter_supported", "false"),
		resource.TestCheckResourceAttr(resourceName, "id_token_signing_alg_values_supported.#", "7"),
		resource.TestCheckResourceAttr(resourceName, "scopes_supported.#", "1"),
		resource.TestCheckResourceAttr(resourceName, "scopes_supported.0", "openid"),
	}

	expectedURLs := map[string]string{
		"jwks_uri":               ".well-known/keys",
		"token_endpoint":         "token",
		"userinfo_endpoint":      "userinfo",
		"authorization_endpoint": fmt.Sprintf("/ui/vault/identity/oidc/provider/%s/authorize", providerName),
	}
	for k, v := range expectedURLs {
		i, err := base.Parse(v)
		if err != nil {
			t.Fatal(err)
		}
		checks = append(checks, resource.TestCheckResourceAttr(resourceName, k, i.String()))
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		Steps: []resource.TestStep{
			{
				Config: testDataSourceIdentityOIDCOpenIDConfig_config(keyName, clientName, providerName, u.Host),
				Check:  resource.ComposeTestCheckFunc(checks...),
			},
		},
	})
}

func testDataSourceIdentityOIDCOpenIDConfig_config(keyName, clientName, providerName, issuerHost string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "key" {
  name               = "%s"
  allowed_client_ids = ["*"]
  rotation_period    = 3600
  verification_ttl   = 3600
}

resource "vault_identity_oidc_client" "app" {
  name             = "%s"
  key              = vault_identity_oidc_key.key.name
  id_token_ttl     = 2400
  access_token_ttl = 7200

  redirect_uris = [
    "http://127.0.0.1:9200/v1/auth-methods/oidc:authenticate:callback",
    "http://127.0.0.1:8251/callback",
    "http://127.0.0.1:8080/callback"
  ]
}

resource "vault_identity_oidc_provider" "test" {
  name          = "%s"
  https_enabled = false
  issuer_host   = "%s"

  allowed_client_ids = [
    vault_identity_oidc_client.app.client_id
  ]
}

data "vault_identity_oidc_openid_config" "config" {
  name = vault_identity_oidc_provider.test.name
}
`, keyName, clientName, providerName, issuerHost)
}
