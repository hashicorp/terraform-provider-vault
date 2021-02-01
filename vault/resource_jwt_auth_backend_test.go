package vault

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/hashcode"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
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
				Config: testAccJWTAuthBackendConfigFullOIDC(path, "https://myco.auth0.com/", "api://default", "\"RS512\""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.jwt", "oidc_discovery_url", "https://myco.auth0.com/"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.jwt", "bound_issuer", "api://default"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.jwt", "jwt_supported_algs.#", "1"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.jwt", "type", "jwt"),
				),
			},
			{
				Config: testAccJWTAuthBackendConfigFullOIDC(path, "https://myco.auth0.com/", "api://default", "\"RS256\",\"RS512\""),
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
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.oidc", "oidc_client_secret", "secret"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.oidc", "type", "oidc"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.oidc", "default_role", "api"),
				),
			},
		},
	})
}

func TestAccJWTAuthBackend_OIDC_Provider_ConfigAzure(t *testing.T) {
	path := acctest.RandomWithPrefix("oidc")
	config, hash := testAccJWTAuthBackendConfigOIDCProviderConfigAzure(path)
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testJWTAuthBackend_Destroyed(path),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.gsuite", "oidc_discovery_url", "https://accounts.google.com"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.gsuite", "provider_config.#", "1"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.gsuite", fmt.Sprintf("provider_config.%d.provider", hash), "azure"),
				),
			},
		},
	})
}

func TestAccJWTAuthBackend_OIDC_Provider_ConfigGSuite(t *testing.T) {
	path := acctest.RandomWithPrefix("oidc")
	config, hash := testAccJWTAuthBackendConfigOIDCProviderConfigGSuite(path)
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testJWTAuthBackend_Destroyed(path),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.gsuite", "oidc_discovery_url", "https://accounts.google.com"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.gsuite", "provider_config.#", "1"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.gsuite", fmt.Sprintf("provider_config.%d.provider", hash), "gsuite"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.gsuite", fmt.Sprintf("provider_config.%d.gsuite_service_account", hash), "/tmp/service-account.json"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.gsuite", fmt.Sprintf("provider_config.%d.gsuite_admin_impersonate", hash), "admin@gsuitedomain.com"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.gsuite", fmt.Sprintf("provider_config.%d.fetch_groups", hash), "true"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.gsuite", fmt.Sprintf("provider_config.%d.fetch_user_info", hash), "true"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.gsuite", fmt.Sprintf("provider_config.%d.groups_recurse_max_depth", hash), "5"),
					resource.TestCheckResourceAttr("vault_jwt_auth_backend.gsuite", fmt.Sprintf("provider_config.%d.user_custom_schemas", hash), "Education,Preferences"),
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
				ExpectError: regexp.MustCompile("config is invalid: cannot write to a path ending in '/'"),
			},
			{
				Config: fmt.Sprintf(`resource "vault_jwt_auth_backend" "jwt" {
				  description = "JWT backend"
				  oidc_discovery_url = "%s"
				  jwt_validation_pubkeys = [%s]
				  bound_issuer = "%s"
				  jwt_supported_algs = [%s]
				  path = "%s"
				}`, "https://myco.auth0.com/", "\"key\"", "api://default", "", path),
				Destroy:     false,
				ExpectError: regexp.MustCompile("config is invalid: 2 problems:"),
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

func testAccJWTAuthBackendConfigFullOIDC(path string, oidcDiscoveryUrl string, boundIssuer string, supportedAlgs string) string {
	return fmt.Sprintf(`
resource "vault_jwt_auth_backend" "jwt" {
  description = "JWT backend"
  oidc_discovery_url = "%s"
  bound_issuer = "%s"
  jwt_supported_algs = [%s]
  path = "%s"
}
`, oidcDiscoveryUrl, boundIssuer, supportedAlgs, path)
}

func testAccJWTAuthBackendConfigPubKeys(path string, validationPublicKeys string, boundIssuer string, supportedAlgs string) string {
	return fmt.Sprintf(`
resource "vault_jwt_auth_backend" "jwt" {
  description = "JWT backend"
  jwt_validation_pubkeys = [%s]
  bound_issuer = "%s"
  jwt_supported_algs = [%s]
  path = "%s"
}
`, validationPublicKeys, boundIssuer, supportedAlgs, path)
}

func testAccJWTAuthBackendConfigJWKS(path string, jwks string, boundIssuer string, supportedAlgs string) string {
	return fmt.Sprintf(`
resource "vault_jwt_auth_backend" "jwt" {
  description = "JWT backend"
  jwks_url = "%s"
  bound_issuer = "%s"
  jwt_supported_algs = [%s]
  path = "%s"
}
`, jwks, boundIssuer, supportedAlgs, path)
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
}
`, path)
}

func testAccJWTAuthBackendConfigOIDCProviderConfigAzure(path string) (string, int) {
	provider := map[string]interface{}{
		"provier_config": map[string]interface{}{
			"provider": "azure",
		},
	}

	hash := jwtAuthProviderConfigHash(provider)

	return fmt.Sprintf(`
resource "vault_jwt_auth_backend" "gsuite" {
	description = "OIDC backend"
	oidc_discovery_url = "https://accounts.google.com"
	path = "%s"
	type = "oidc"
	provider_config {
		provider                 = "azure"
	}
}
`, path), hash
}

func testAccJWTAuthBackendConfigOIDCProviderConfigGSuite(path string) (string, int) {
	provider := map[string]interface{}{
		"provier_config": map[string]interface{}{
			"provider":                 "gsuite",
			"gsuite_service_account":   "/tmp/service-account.json",
			"gsuite_admin_impersonate": "admin@gsuitedomain.com",
			"fetch_groups":             true,
			"fetch_user_info":          true,
			"groups_recurse_max_depth": 5,
			"user_custom_schemas":      "Education,Preferences",
		},
	}

	hash := jwtAuthProviderConfigHash(provider)

	return fmt.Sprintf(`
resource "vault_jwt_auth_backend" "gsuite" {
	description = "OIDC backend"
	oidc_discovery_url = "https://accounts.google.com"
	path = "%s"
	type = "oidc"
	provider_config {
		provider                 = "gsuite"
		gsuite_service_account   = "/tmp/service-account.json"
		gsuite_admin_impersonate = "admin@gsuitedomain.com"
		fetch_groups             = true
		fetch_user_info          = true
		groups_recurse_max_depth = 5
		user_custom_schemas      = "Education,Preferences"
	}
}
`, path), hash
}

func mapToString(m map[string]interface{}) string {
	b := new(bytes.Buffer)
	for key, value := range m {
		fmt.Fprintf(b, "%s=\"%s\"\n", key, value)
	}
	return b.String()
}

func testAccJWTProviderConfigHash(data map[string]interface{}) int {
	var buf bytes.Buffer
	var keys []string

	for k := range data {
		keys = append(keys, k)
	}

	// The keys need to be sorted to ensure the hash is calculated correctly.
	sort.Strings(keys)
	for _, v := range keys {
		buf.WriteString(fmt.Sprintf("%s-", data[v]))
	}

	return hashcode.String(buf.String())
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

func TestAccJWTAuthBackend_missingMandatory(t *testing.T) {
	path := acctest.RandomWithPrefix("jwt")
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`resource "vault_jwt_auth_backend" "bad" {
					path = "%s"
				}`, path),
				Destroy:     false,
				ExpectError: regexp.MustCompile("exactly one of oidc_discovery_url, jwks_url or jwt_validation_pubkeys should be provided"),
			},
			{
				Config: fmt.Sprintf(`resource "vault_jwt_auth_backend" "bad" {
						path = "%s"
						oidc_discovery_url = ""
					}`, path),
				Destroy:     false,
				ExpectError: regexp.MustCompile("exactly one of oidc_discovery_url, jwks_url or jwt_validation_pubkeys should be provided"),
			},
			{
				Config: fmt.Sprintf(`resource "vault_jwt_auth_backend" "bad" {
					path = "%s"
					jwks_url = ""
				}`, path),
				Destroy:     false,
				ExpectError: regexp.MustCompile("exactly one of oidc_discovery_url, jwks_url or jwt_validation_pubkeys should be provided"),
			},
			{
				Config: fmt.Sprintf(`resource "vault_jwt_auth_backend" "bad" {
					path = "%s"
					jwt_validation_pubkeys = []
				}`, path),
				Destroy:     false,
				ExpectError: regexp.MustCompile("exactly one of oidc_discovery_url, jwks_url or jwt_validation_pubkeys should be provided"),
			},
			{
				Config: fmt.Sprintf(`
				resource "vault_identity_oidc_key" "key" {
					name = "com"
				}

				resource "vault_jwt_auth_backend" "unknown" {
					path = "%s"
					// force value to be unknown until apply phase
					oidc_discovery_url = "https://myco.auth0.${vault_identity_oidc_key.key.id}/"
				}`, path),
			},
		},
	})
}
