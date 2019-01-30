package vault

import (
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccGithubAuthBackend_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("github")
	resName := "vault_github_auth_backend.gh"
	var resAuth api.AuthMount
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccCheckGithubAuthMountDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGithubAuthBackendConfig_basic(backend),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAuthMountExists(resName, &resAuth),
					resource.TestCheckResourceAttr(resName, "id", backend),
					resource.TestCheckResourceAttr(resName, "path", backend),
					resource.TestCheckResourceAttr(resName, "organization", "vault"),
					resource.TestCheckResourceAttr(resName, "ttl", "20m"),
					resource.TestCheckResourceAttr(resName, "max_ttl", "50m"),
				),
			},
			{
				Config: testAccGithubAuthBackendConfig_updated(backend),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAuthMountExists(resName, &resAuth),
					resource.TestCheckResourceAttr(resName, "id", backend),
					resource.TestCheckResourceAttr(resName, "path", backend),
					resource.TestCheckResourceAttr(resName, "organization", "other_vault"),
					resource.TestCheckResourceAttr(resName, "ttl", "40m"),
					resource.TestCheckResourceAttr(resName, "max_ttl", "1h40m"),
				),
			},
		},
	})
}

func TestAccGithubAuthBackend_tuning(t *testing.T) {
	backend := acctest.RandomWithPrefix("github")
	resName := "vault_github_auth_backend.gh"
	var resAuth api.AuthMount
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccCheckGithubAuthMountDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGithubAuthBackendConfig_tuning(backend),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAuthMountExists(resName, &resAuth),
					resource.TestCheckResourceAttr(resName, "id", backend),
					resource.TestCheckResourceAttr(resName, "path", backend),
					resource.TestCheckResourceAttr(resName, "tune.2905546040.default_lease_ttl", "10m"),
					resource.TestCheckResourceAttr(resName, "tune.2905546040.max_lease_ttl", "20m"),
					resource.TestCheckResourceAttr(resName, "tune.2905546040.listing_visibility", "hidden"),
					resource.TestCheckResourceAttr(resName, "tune.2905546040.audit_non_hmac_request_keys.#", "2"),
					resource.TestCheckResourceAttr(resName, "tune.2905546040.audit_non_hmac_request_keys.0", "key1"),
					resource.TestCheckResourceAttr(resName, "tune.2905546040.audit_non_hmac_request_keys.1", "key2"),
					resource.TestCheckResourceAttr(resName, "tune.2905546040.audit_non_hmac_response_keys.#", "2"),
					resource.TestCheckResourceAttr(resName, "tune.2905546040.audit_non_hmac_response_keys.0", "key3"),
					resource.TestCheckResourceAttr(resName, "tune.2905546040.audit_non_hmac_response_keys.1", "key4"),
					resource.TestCheckResourceAttr(resName, "tune.2905546040.passthrough_request_headers.#", "2"),
					resource.TestCheckResourceAttr(resName, "tune.2905546040.passthrough_request_headers.0", "X-Custom-Header"),
					resource.TestCheckResourceAttr(resName, "tune.2905546040.passthrough_request_headers.1", "X-Forwarded-To"),
				),
			},
			{
				Config: testAccGithubAuthBackendConfig_tuningUpdated(backend),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAuthMountExists(resName, &resAuth),
					resource.TestCheckResourceAttr(resName, "id", backend),
					resource.TestCheckResourceAttr(resName, "path", backend),
					resource.TestCheckResourceAttr(resName, "tune.2753290056.default_lease_ttl", "50m"),
					resource.TestCheckResourceAttr(resName, "tune.2753290056.max_lease_ttl", "1h10m"),
					resource.TestCheckResourceAttr(resName, "tune.2753290056.listing_visibility", "unauth"),
					resource.TestCheckResourceAttr(resName, "tune.2753290056.audit_non_hmac_request_keys.#", "1"),
					resource.TestCheckResourceAttr(resName, "tune.2753290056.audit_non_hmac_request_keys.0", "key1"),
					resource.TestCheckResourceAttr(resName, "tune.2753290056.audit_non_hmac_response_keys.#", "0"),
					resource.TestCheckResourceAttr(resName, "tune.2753290056.passthrough_request_headers.#", "3"),
					resource.TestCheckResourceAttr(resName, "tune.2753290056.passthrough_request_headers.0", "X-Custom-Header"),
					resource.TestCheckResourceAttr(resName, "tune.2753290056.passthrough_request_headers.1", "X-Forwarded-To"),
					resource.TestCheckResourceAttr(resName, "tune.2753290056.passthrough_request_headers.2", "X-Mas"),
				),
			},
		},
	})
}

func TestAccGithubAuthBackend_description(t *testing.T) {
	backend := acctest.RandomWithPrefix("github")
	resName := "vault_github_auth_backend.gh"
	var resAuth api.AuthMount
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccCheckGithubAuthMountDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGithubAuthBackendConfig_description(backend, "Github Auth Mount"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAuthMountExists(resName, &resAuth),
					resource.TestCheckResourceAttr(resName, "path", backend),
					resource.TestCheckResourceAttr(resName, "description", "Github Auth Mount"),
				),
			},
			{
				Config: testAccGithubAuthBackendConfig_description(backend, "Github Auth Mount Updated"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAuthMountExists(resName, &resAuth),
					resource.TestCheckResourceAttr(resName, "path", backend),
					resource.TestCheckResourceAttr(resName, "description", "Github Auth Mount Updated"),
				),
			},
		},
	})
}

func TestAccGithubAuthBackend_importTuning(t *testing.T) {
	backend := acctest.RandomWithPrefix("github")
	resName := "vault_github_auth_backend.gh"
	var resAuth api.AuthMount
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccGithubAuthBackendConfig_tuning(backend),
				Check:  testAccCheckAuthMountExists(resName, &resAuth),
			},
			{
				ResourceName:      resName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccCheckAuthMountExists(n string, out *api.AuthMount) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testProvider.Meta().(*api.Client)
		return authMountExistsHelper(n, s, client, out)
	}
}

func testAccCheckGithubAuthMountDestroy(s *terraform.State) error {
	return testAccCheckAuthMountDestroy(s, "vault_github_auth_backend")
}

func testAccCheckAuthMountDestroy(s *terraform.State, resType string) error {
	client := testProvider.Meta().(*api.Client)
	return authMountDestroyHelper(s, client, resType)
}

func authMountExistsHelper(n string, s *terraform.State, client *api.Client, out *api.AuthMount) error {
	rs, ok := s.RootModule().Resources[n]
	if !ok {
		return fmt.Errorf("Not found: %s", n)
	}

	if rs.Primary.ID == "" {
		return fmt.Errorf("No id for %s is set", n)
	}

	auths, err := client.Sys().ListAuth()
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	resp := auths[strings.Trim(rs.Primary.ID, "/")+"/"]
	if resp == nil {
		return fmt.Errorf("auth mount %s not present", rs.Primary.ID)
	}
	log.Printf("[INFO] Auth mount resource '%v' confirmed to exist at path: %v", n, rs.Primary.ID)
	*out = *resp

	return nil
}

func authMountDestroyHelper(s *terraform.State, client *api.Client, resType string) error {
	for _, r := range s.RootModule().Resources {
		if r.Type != resType {
			continue
		}

		auths, err := client.Sys().ListAuth()
		if err != nil {
			return fmt.Errorf("error reading from Vault: %s", err)
		}

		resp := auths[strings.Trim(r.Primary.ID, "/")+"/"]
		if resp == nil {
			log.Printf("[INFO] Auth mount resource confirmed to be destroyed from path: %v", r.Primary.ID)
			return nil
		}
	}
	return fmt.Errorf("Auth mount resource still exists")
}

func testAccGithubAuthBackendConfig_basic(backend string) string {
	return fmt.Sprintf(`
resource "vault_github_auth_backend" "gh" {
	path = "%s"
	organization = "vault"
	ttl = "20m"
	max_ttl = "50m" 
}
`, backend)
}

func testAccGithubAuthBackendConfig_updated(backend string) string {
	return fmt.Sprintf(`
resource "vault_github_auth_backend" "gh" {
  	path = "%s"
	organization = "other_vault"
	ttl = "40m"
	max_ttl = "1h40m"
}
`, backend)
}

func testAccGithubAuthBackendConfig_tuning(backend string) string {
	return fmt.Sprintf(`
resource "vault_github_auth_backend" "gh" {
  	path = "%s"
  	organization = "vault"
  
  	tune {
		default_lease_ttl = "10m"
		max_lease_ttl = "20m"
		listing_visibility = "hidden"
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
		default_lease_ttl = "50m"
		max_lease_ttl = "1h10m"
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
