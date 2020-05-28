package jwt

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/terraform-providers/terraform-provider-vault/schema"
	"github.com/terraform-providers/terraform-provider-vault/util"
	"github.com/terraform-providers/terraform-provider-vault/vault"
)

var configTestProvider = func() *schema.Provider {
	p := schema.NewProvider(vault.Provider())
	p.RegisterResource("vault_auth_backend", vault.AuthBackendResource())
	p.RegisterResource("vault_auth_jwt_config", ConfigResource())
	return p
}()

func TestConfig(t *testing.T) {
	path := acctest.RandomWithPrefix("jwt")

	resource.Test(t, resource.TestCase{
		PreCheck: func() { util.TestAccPreCheck(t) },
		Providers: map[string]terraform.ResourceProvider{
			"vault": configTestProvider.ResourceProvider(),
		},
		Steps: []resource.TestStep{
			{
				Config: basicConfig(path, "https://myco.auth0.com/", "m5i8bj3iofytj", "f4ubv72nfiu23hnsj", "demo"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_auth_jwt_config.jwt", "path", path),
					resource.TestCheckResourceAttr("vault_auth_jwt_config.jwt", "oidc_discovery_url", "https://myco.auth0.com/"),
					resource.TestCheckResourceAttr("vault_auth_jwt_config.jwt", "oidc_client_id", "m5i8bj3iofytj"),
					resource.TestCheckResourceAttr("vault_auth_jwt_config.jwt", "oidc_client_secret", "f4ubv72nfiu23hnsj"),
					resource.TestCheckResourceAttr("vault_auth_jwt_config.jwt", "default_role", "demo"),
				),
			},
			{
				Config: basicConfig(path, "https://myco.auth0.com/", "b5i8bj3iofytj", "b4ubv72nfiu23hnsj", "demo1"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_auth_jwt_config.jwt", "path", path),
					resource.TestCheckResourceAttr("vault_auth_jwt_config.jwt", "oidc_discovery_url", "https://myco.auth0.com/"),
					resource.TestCheckResourceAttr("vault_auth_jwt_config.jwt", "oidc_client_id", "b5i8bj3iofytj"),
					resource.TestCheckResourceAttr("vault_auth_jwt_config.jwt", "oidc_client_secret", "b4ubv72nfiu23hnsj"),
					resource.TestCheckResourceAttr("vault_auth_jwt_config.jwt", "default_role", "demo1"),
				),
			},
			{
				ResourceName:      "vault_auth_jwt_config.jwt",
				ImportState:       true,
				ImportStateVerify: true,
				// We ignore that the oidc_client_secret is not returned because, since
				// it's sensitive, Vault doesn't return it even when it's set.
				ImportStateVerifyIgnore: []string{"oidc_client_secret"},
			},
		},
	})
}

func basicConfig(path, oidcDiscURL, oidcClientID, oidcClientSecret, defaultRole string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "mount_jwt" {
  path = "%s"
  type = "jwt"
}
resource "vault_auth_jwt_config" "jwt" {
  path = vault_auth_backend.mount_jwt.path
  oidc_discovery_url = "%s"
  oidc_client_id = "%s"
  oidc_client_secret = "%s"
  default_role = "%s"
}
`, path, oidcDiscURL, oidcClientID, oidcClientSecret, defaultRole)
}
