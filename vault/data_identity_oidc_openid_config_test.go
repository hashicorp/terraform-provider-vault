package vault

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceIdentityOIDCOpenIDConfig(t *testing.T) {
	name := acctest.RandomWithPrefix("test-provider")
	resourceName := "data.vault_identity_oidc_openid_config.config"
	vaultAddrEnv := os.Getenv("VAULT_ADDR")
	host := vaultAddrEnv
	if vaultAddrEnv == "http://localhost:8200" {
		host = "http://127.0.0.1:8200"
	}

	issuer := "%s/v1/identity/oidc/provider/%s"
	jwksURI := "%s/v1/identity/oidc/provider/%s/.well-known/keys"
	authorizationEndpoint := "%s/ui/vault/identity/oidc/provider/%s/authorize"
	tokenEndpoint := "%s/v1/identity/oidc/provider/%s/token"
	userInfoEndpoint := "%s/v1/identity/oidc/provider/%s/userinfo"

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceIdentityOIDCOpenIDConfig_config(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "issuer", fmt.Sprintf(issuer, host, name)),
					resource.TestCheckResourceAttr(resourceName, "jwks_uri", fmt.Sprintf(jwksURI, host, name)),
					resource.TestCheckResourceAttr(resourceName, "authorization_endpoint", fmt.Sprintf(authorizationEndpoint, host, name)),
					resource.TestCheckResourceAttr(resourceName, "token_endpoint", fmt.Sprintf(tokenEndpoint, host, name)),
					resource.TestCheckResourceAttr(resourceName, "userinfo_endpoint", fmt.Sprintf(userInfoEndpoint, host, name)),
					resource.TestCheckResourceAttr(resourceName, "request_uri_parameter_supported", "false"),
					resource.TestCheckResourceAttr(resourceName, "id_token_signing_alg_values_supported.#", "7"),
					resource.TestCheckResourceAttr(resourceName, "scopes_supported.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "scopes_supported.0", "openid"),
				),
			},
		},
	})
}

func testDataSourceIdentityOIDCOpenIDConfig_config(name string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "key" {
  name               = "key"
  allowed_client_ids = ["*"]
  rotation_period    = 3600
  verification_ttl   = 3600
}

resource "vault_identity_oidc_client" "app" {
  name          = "application"
  key           = vault_identity_oidc_key.key.name
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
     vault_identity_oidc_client.app.client_id
  ]
}

data "vault_identity_oidc_openid_config" "config" {
  name = vault_identity_oidc_provider.test.name
}`, name)
}
