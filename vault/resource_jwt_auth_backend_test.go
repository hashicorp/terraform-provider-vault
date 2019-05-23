package vault

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccJWTAuthBackend(t *testing.T) {
	path := acctest.RandomWithPrefix("jwt")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testJWTAuthBackend_Destroyed(path),
		Steps: []resource.TestStep{
			{
				Config: testAccJWTAuthBackendConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.jwt", "description", "JWT backend"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.jwt", "oidc_discovery_url", "https://myco.auth0.com/"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.jwt", "path", path),
					resource.TestCheckResourceAttrSet("vault_jwt_auth_backend.jwt", "accessor"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.jwt", "bound_issuer", ""),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.jwt", "type", "jwt"),
				),
			},
			{
				Config: testAccJWTAuthBackendConfigFull(path, "https://myco.auth0.com/", "", "api://default", "\"RS512\""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.jwt", "oidc_discovery_url", "https://myco.auth0.com/"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.jwt", "bound_issuer", "api://default"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.jwt", "jwt_supported_algs.#", "1"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.jwt", "type", "jwt"),
				),
			},
			{
				Config: testAccJWTAuthBackendConfigFull(path, "https://myco.auth0.com/", "", "api://default", "\"RS256\",\"RS512\""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.jwt", "oidc_discovery_url", "https://myco.auth0.com/"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.jwt", "bound_issuer", "api://default"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.jwt", "jwt_supported_algs.#", "2"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.jwt", "type", "jwt"),
				),
			},
		},
	})
}
func TestAccJWTAuthBackend_OIDC(t *testing.T) {
	path := acctest.RandomWithPrefix("oidc")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testJWTAuthBackend_Destroyed(path),
		Steps: []resource.TestStep{
			{
				Config: testAccJWTAuthBackendConfigOIDC(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.oidc", "oidc_discovery_url", "https://myco.auth0.com/"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.oidc", "bound_issuer", "api://default"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.oidc", "oidc_client_id", "client"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.oidc", "type", "oidc"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.oidc", "default_role", "api"),
				),
			},
		},
	})
}

func TestAccJWTAuthBackend_negative(t *testing.T) {
	path := acctest.RandomWithPrefix("jwt")
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config:      testAccJWTAuthBackendConfig(path + "/"),
				Destroy:     false,
				ExpectError: regexp.MustCompile("vault_jwt_auth_backend\\.jwt: cannot write to a path ending in '/'"),
			},
			{
				Config:      testAccJWTAuthBackendConfigFull(path, "https://myco.auth0.com/", "\"key\"", "api://default", ""),
				Destroy:     false,
				ExpectError: regexp.MustCompile("exactly one of oidc_discovery_url and jwt_validation_pubkeys should be provided"),
			},
		},
	})
}

func testAccJWTAuthBackendConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_jwt_auth_backend" "jwt" {
  description = "JWT backend"
  oidc_discovery_url = "https://myco.auth0.com/"
  path = "%s"
}
`, path)
}

func testAccJWTAuthBackendConfigFull(path string, oidcDiscoveryUrl string, validationPublicKeys string, boundIssuer string, supportedAlgs string) string {
	return fmt.Sprintf(`
resource "vault_jwt_auth_backend" "jwt" {
  description = "JWT backend"
  oidc_discovery_url = "%s"
  jwt_validation_pubkeys = [%s]
  bound_issuer = "%s"
  jwt_supported_algs = [%s]
  path = "%s"
}
`, oidcDiscoveryUrl, validationPublicKeys, boundIssuer, supportedAlgs, path)
}

func testAccJWTAuthBackendConfigOIDC(path string) string {
	return fmt.Sprintf(`
resource "vault_jwt_auth_backend" "oidc" {
  description = "OIDC backend"
  oidc_discovery_url = "https://myco.auth0.com/"
  oidc_client_id = "client"
  oidc_client_secret = "secret"
  bound_issuer = "api://default"
  path = "%s"
  type = "oidc"
  default_role = "api"
  lifecycle {
	ignore_changes = [
     # Ignore changes to odic_clie_secret inside the tests
     "oidc_client_secret"
    ]
  }
}
`, path)
}

func testJWTAuthBackend_Destroyed(path string) resource.TestCheckFunc {
	return func(s *terraform.State) error {

		client := testProvider.Meta().(*api.Client)

		authMounts, err := client.Sys().ListAuth()
		if err != nil {
			return err
		}

		if _, ok := authMounts[fmt.Sprintf("%s/", path)]; ok {
			return fmt.Errorf("auth mount not destroyed")
		}

		return nil
	}
}
