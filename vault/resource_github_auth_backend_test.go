package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
)

func TestAccGithubAuthBackend_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("github")
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccGithubAuthBackendConfig_basic(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "path", backend),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "organization", "vault"),
				),
			},
			{
				Config: testAccGithubAuthBackendConfig_updated(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "path", backend),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "organization", "other_vault"),
				),
			},
		},
	})
}

func TestAccGithubAuthBackend_tuning(t *testing.T) {
	backend := acctest.RandomWithPrefix("github")
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccGithubAuthBackendConfig_tuning(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "path", backend),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "tune.4271161690.default_lease_ttl", "10"),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "tune.4271161690.max_lease_ttl", "20"),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "tune.4271161690.listing_visibility", ""),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "tune.4271161690.audit_non_hmac_request_keys.#", "2"),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "tune.4271161690.audit_non_hmac_request_keys.0", "key1"),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "tune.4271161690.audit_non_hmac_request_keys.1", "key2"),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "tune.4271161690.audit_non_hmac_response_keys.#", "2"),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "tune.4271161690.audit_non_hmac_response_keys.0", "key3"),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "tune.4271161690.audit_non_hmac_response_keys.1", "key4"),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "tune.4271161690.passthrough_request_headers.#", "2"),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "tune.4271161690.passthrough_request_headers.0", "X-Custom-Header"),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "tune.4271161690.passthrough_request_headers.1", "X-Forwarded-To"),
				),
			},
			{
				Config: testAccGithubAuthBackendConfig_tuningUpdated(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "path", backend),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "tune.2934484151.default_lease_ttl", "50"),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "tune.2934484151.max_lease_ttl", "70"),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "tune.2934484151.listing_visibility", "unauth"),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "tune.2934484151.audit_non_hmac_request_keys.#", "1"),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "tune.2934484151.audit_non_hmac_request_keys.0", "key1"),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "tune.2934484151.audit_non_hmac_response_keys.#", "0"),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "tune.2934484151.passthrough_request_headers.#", "3"),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "tune.2934484151.passthrough_request_headers.0", "X-Custom-Header"),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "tune.2934484151.passthrough_request_headers.1", "X-Forwarded-To"),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "tune.2934484151.passthrough_request_headers.2", "X-Mas"),
				),
			},
		},
	})
}

func TestAccGithubAuthBackend_description(t *testing.T) {
	backend := acctest.RandomWithPrefix("github")
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccGithubAuthBackendConfig_description(backend, "Github Auth Mount"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "path", backend),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "description", "Github Auth Mount"),
				),
			},
			{
				Config: testAccGithubAuthBackendConfig_description(backend, "Github Auth Mount Updated"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "path", backend),
					resource.TestCheckResourceAttr("vault_github_auth_backend.gh", "description", "Github Auth Mount Updated"),
				),
			},
		},
	})
}

func testAccGithubAuthBackendConfig_basic(backend string) string {
	return fmt.Sprintf(`
resource "vault_github_auth_backend" "gh" {
	path = "%s"
  	organization = "vault"
}
`, backend)
}

func testAccGithubAuthBackendConfig_updated(backend string) string {
	return fmt.Sprintf(`
resource "vault_github_auth_backend" "gh" {
  	path = "%s"
  	organization = "other_vault"
}
`, backend)
}

func testAccGithubAuthBackendConfig_tuning(backend string) string {
	return fmt.Sprintf(`
resource "vault_github_auth_backend" "gh" {
  	path = "%s"
  	organization = "vault"
  
  	tune {
		default_lease_ttl = 10
		max_lease_ttl = 20
		audit_non_hmac_request_keys = ["key1", "key2"]
		audit_non_hmac_response_keys = ["key3", "key4"]
		passthrough_request_headers = ["X-Custom-Header", "X-Forwarded-To"]
	}
}
`, backend)
}

func testAccGithubAuthBackendConfig_tuningUpdated(backend string) string {
	return fmt.Sprintf(`
resource "vault_github_auth_backend" "gh" {
  	path = "%s"
  	organization = "vault"
  
  	tune {
		default_lease_ttl = 50
		max_lease_ttl = 70
		audit_non_hmac_request_keys = ["key1"]
		listing_visibility = "unauth"
		passthrough_request_headers = ["X-Custom-Header", "X-Forwarded-To", "X-Mas"]
	}
}
`, backend)
}

func testAccGithubAuthBackendConfig_description(backend string, description string) string {
	return fmt.Sprintf(`
resource "vault_github_auth_backend" "gh" {
	path = "%s"
	organization = "vault"
	description = "%s"  
}
`, backend, description)
}
