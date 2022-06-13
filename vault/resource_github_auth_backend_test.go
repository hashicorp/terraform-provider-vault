package vault

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// as of vault-1.10 github-auth acceptance tests should use a valid GitHub
// organization where applicable.
const testGHOrg = "hashicorp"

func TestAccGithubAuthBackend_basic(t *testing.T) {
	testutil.SkipTestAcc(t)

	orgMeta := testutil.GetGHOrgResponse(t, testGHOrg)

	path := acctest.RandomWithPrefix("github")
	resName := "vault_github_auth_backend.gh"
	var resAuth api.AuthMount

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccCheckGithubAuthMountDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGithubAuthBackendConfig_basic(path, testGHOrg),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAuthMountExists(resName, &resAuth),
					resource.TestCheckResourceAttr(resName, "id", path),
					resource.TestCheckResourceAttr(resName, "path", path),
					resource.TestCheckResourceAttr(resName, "organization", testGHOrg),
					// expect computed value for organization_id
					resource.TestCheckResourceAttr(resName, "organization_id", strconv.Itoa(orgMeta.ID)),
					resource.TestCheckResourceAttr(resName, "token_ttl", "1200"),
					resource.TestCheckResourceAttr(resName, "token_max_ttl", "3000"),
					resource.TestCheckResourceAttrPtr(resName, "accessor", &resAuth.Accessor),
				),
			},
			{
				Config: testAccGithubAuthBackendConfig_updated(path, "unknown", 2999),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAuthMountExists(resName, &resAuth),
					resource.TestCheckResourceAttr(resName, "id", path),
					resource.TestCheckResourceAttr(resName, "path", path),
					resource.TestCheckResourceAttr(resName, "organization", "unknown"),
					resource.TestCheckResourceAttr(resName, "organization_id", "2999"),
					resource.TestCheckResourceAttr(resName, "token_ttl", "2400"),
					resource.TestCheckResourceAttr(resName, "token_max_ttl", "6000"),
					resource.TestCheckResourceAttrPtr(resName, "accessor", &resAuth.Accessor),
				),
			},
		},
	})
}

func TestAccGithubAuthBackend_tuning(t *testing.T) {
	testutil.SkipTestAcc(t)

	orgMeta := testutil.GetGHOrgResponse(t, testGHOrg)

	backend := acctest.RandomWithPrefix("github")
	resName := "vault_github_auth_backend.gh"
	var resAuth api.AuthMount

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccCheckGithubAuthMountDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGithubAuthBackendConfig_tuning(backend),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAuthMountExists(resName, &resAuth),
					resource.TestCheckResourceAttr(resName, "id", backend),
					resource.TestCheckResourceAttr(resName, "path", backend),
					resource.TestCheckResourceAttr(resName, "organization", testGHOrg),
					resource.TestCheckResourceAttr(resName, "organization_id", strconv.Itoa(orgMeta.ID)),
					resource.TestCheckResourceAttr(resName, "tune.0.default_lease_ttl", "10m"),
					resource.TestCheckResourceAttr(resName, "tune.0.max_lease_ttl", "20m"),
					resource.TestCheckResourceAttr(resName, "tune.0.listing_visibility", "hidden"),
					resource.TestCheckResourceAttr(resName, "tune.0.audit_non_hmac_request_keys.#", "2"),
					resource.TestCheckResourceAttr(resName, "tune.0.audit_non_hmac_request_keys.0", "key1"),
					resource.TestCheckResourceAttr(resName, "tune.0.audit_non_hmac_request_keys.1", "key2"),
					resource.TestCheckResourceAttr(resName, "tune.0.audit_non_hmac_response_keys.#", "2"),
					resource.TestCheckResourceAttr(resName, "tune.0.audit_non_hmac_response_keys.0", "key3"),
					resource.TestCheckResourceAttr(resName, "tune.0.audit_non_hmac_response_keys.1", "key4"),
					resource.TestCheckResourceAttr(resName, "tune.0.passthrough_request_headers.#", "2"),
					resource.TestCheckResourceAttr(resName, "tune.0.passthrough_request_headers.0", "X-Custom-Header"),
					resource.TestCheckResourceAttr(resName, "tune.0.passthrough_request_headers.1", "X-Forwarded-To"),
					resource.TestCheckResourceAttr(resName, "tune.0.allowed_response_headers.#", "2"),
					resource.TestCheckResourceAttr(resName, "tune.0.allowed_response_headers.0", "X-Custom-Response-Header"),
					resource.TestCheckResourceAttr(resName, "tune.0.allowed_response_headers.1", "X-Forwarded-Response-To"),
					resource.TestCheckResourceAttr(resName, "tune.0.token_type", "batch"),
				),
			},
			{
				Config: testAccGithubAuthBackendConfig_tuningUpdated(backend),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAuthMountExists(resName, &resAuth),
					resource.TestCheckResourceAttr(resName, "id", backend),
					resource.TestCheckResourceAttr(resName, "path", backend),
					resource.TestCheckResourceAttr(resName, "organization", testGHOrg),
					resource.TestCheckResourceAttr(resName, "organization_id", strconv.Itoa(orgMeta.ID)),
					resource.TestCheckResourceAttr(resName, "tune.0.default_lease_ttl", "50m"),
					resource.TestCheckResourceAttr(resName, "tune.0.max_lease_ttl", "1h10m"),
					resource.TestCheckResourceAttr(resName, "tune.0.listing_visibility", "unauth"),
					resource.TestCheckResourceAttr(resName, "tune.0.audit_non_hmac_request_keys.#", "1"),
					resource.TestCheckResourceAttr(resName, "tune.0.audit_non_hmac_request_keys.0", "key1"),
					resource.TestCheckResourceAttr(resName, "tune.0.audit_non_hmac_response_keys.#", "0"),
					resource.TestCheckResourceAttr(resName, "tune.0.passthrough_request_headers.#", "3"),
					resource.TestCheckResourceAttr(resName, "tune.0.passthrough_request_headers.0", "X-Custom-Header"),
					resource.TestCheckResourceAttr(resName, "tune.0.passthrough_request_headers.1", "X-Forwarded-To"),
					resource.TestCheckResourceAttr(resName, "tune.0.passthrough_request_headers.2", "X-Mas"),
					resource.TestCheckResourceAttr(resName, "tune.0.allowed_response_headers.#", "3"),
					resource.TestCheckResourceAttr(resName, "tune.0.allowed_response_headers.0", "X-Custom-Response-Header"),
					resource.TestCheckResourceAttr(resName, "tune.0.allowed_response_headers.1", "X-Forwarded-Response-To"),
					resource.TestCheckResourceAttr(resName, "tune.0.allowed_response_headers.2", "X-Mas-Response"),
					resource.TestCheckResourceAttr(resName, "tune.0.token_type", "default-batch"),
				),
			},
		},
	})
}

func TestAccGithubAuthBackend_description(t *testing.T) {
	testutil.SkipTestAcc(t)

	orgMeta := testutil.GetGHOrgResponse(t, testGHOrg)

	path := acctest.RandomWithPrefix("github")
	resName := "vault_github_auth_backend.gh"
	var resAuth api.AuthMount
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccCheckGithubAuthMountDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccGithubAuthBackendConfig_description(path, testGHOrg, "Github Auth Mount"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAuthMountExists(resName, &resAuth),
					resource.TestCheckResourceAttr(resName, "path", path),
					resource.TestCheckResourceAttr(resName, "organization", testGHOrg),
					resource.TestCheckResourceAttr(resName, "organization_id", strconv.Itoa(orgMeta.ID)),
					resource.TestCheckResourceAttr(resName, "description", "Github Auth Mount"),
				),
			},
			{
				Config: testAccGithubAuthBackendConfig_description(path, testGHOrg, "Github Auth Mount Updated"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAuthMountExists(resName, &resAuth),
					resource.TestCheckResourceAttr(resName, "path", path),
					resource.TestCheckResourceAttr(resName, "organization", orgMeta.Login),
					resource.TestCheckResourceAttr(resName, "organization_id", strconv.Itoa(orgMeta.ID)),
					resource.TestCheckResourceAttr(resName, "description", "Github Auth Mount Updated"),
				),
			},
		},
	})
}

func TestAccGithubAuthBackend_importTuning(t *testing.T) {
	path := acctest.RandomWithPrefix("github")
	resName := "vault_github_auth_backend.gh"
	var resAuth api.AuthMount
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccGithubAuthBackendConfig_tuning(path),
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
		return authMountExistsHelper(n, s, out)
	}
}

func testAccCheckGithubAuthMountDestroy(s *terraform.State) error {
	return testAccCheckAuthMountDestroy(s, "vault_github_auth_backend")
}

func testAccCheckAuthMountDestroy(s *terraform.State, resType string) error {
	return authMountDestroyHelper(s, resType)
}

func authMountExistsHelper(resourceName string, s *terraform.State, out *api.AuthMount) error {
	rs, ok := s.RootModule().Resources[resourceName]
	if !ok {
		return fmt.Errorf("Not found: %s", resourceName)
	}

	if rs.Primary.ID == "" {
		return fmt.Errorf("No id for %s is set", resourceName)
	}

	client, e := provider.GetClient(rs.Primary, testProvider.Meta())
	if e != nil {
		return e
	}

	auths, err := client.Sys().ListAuth()
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	resp := auths[strings.Trim(rs.Primary.ID, "/")+"/"]
	if resp == nil {
		return fmt.Errorf("auth mount %s not present", rs.Primary.ID)
	}
	log.Printf("[INFO] Auth mount resource '%v' confirmed to exist at path: %v", resourceName, rs.Primary.ID)
	*out = *resp

	return nil
}

func authMountDestroyHelper(s *terraform.State, resType string) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != resType {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		auths, err := client.Sys().ListAuth()
		if err != nil {
			return fmt.Errorf("error reading from Vault: %s", err)
		}

		resp := auths[strings.Trim(rs.Primary.ID, "/")+"/"]
		if resp == nil {
			log.Printf("[INFO] Auth mount resource confirmed to be destroyed from path: %v", rs.Primary.ID)
			return nil
		}
	}
	return fmt.Errorf("Auth mount resource still exists")
}

func testAccGithubAuthBackendConfig_basic(path, org string) string {
	return fmt.Sprintf(`
resource "vault_github_auth_backend" "gh" {
	path = "%s"
	organization = "%s"
	token_ttl = 1200
	token_max_ttl = 3000
}
`, path, org)
}

func testAccGithubAuthBackendConfig_updated(path, org string, orgID int) string {
	return fmt.Sprintf(`
resource "vault_github_auth_backend" "gh" {
  	path = "%s"
	organization = "%s"
	organization_id = %d
	token_ttl = 2400
	token_max_ttl = 6000
}
`, path, org, orgID)
}

func testAccGithubAuthBackendConfig_tuning(path string) string {
	return fmt.Sprintf(`
resource "vault_github_auth_backend" "gh" {
  	path = "%s"
  	organization = "%s"
  
  	tune {
		default_lease_ttl = "10m"
		max_lease_ttl = "20m"
		listing_visibility = "hidden"
		audit_non_hmac_request_keys = ["key1", "key2"]
		audit_non_hmac_response_keys = ["key3", "key4"]
		passthrough_request_headers = ["X-Custom-Header", "X-Forwarded-To"]
		allowed_response_headers = ["X-Custom-Response-Header", "X-Forwarded-Response-To"]
		token_type = "batch"
	}
}
`, path, testGHOrg)
}

func testAccGithubAuthBackendConfig_tuningUpdated(path string) string {
	return fmt.Sprintf(`
resource "vault_github_auth_backend" "gh" {
  	path = "%s"
	organization = "%s"
  
  	tune {
		default_lease_ttl = "50m"
		max_lease_ttl = "1h10m"
		audit_non_hmac_request_keys = ["key1"]
		listing_visibility = "unauth"
		passthrough_request_headers = ["X-Custom-Header", "X-Forwarded-To", "X-Mas"]
		allowed_response_headers = ["X-Custom-Response-Header", "X-Forwarded-Response-To", "X-Mas-Response"]
		token_type = "default-batch"
	}
}
`, path, testGHOrg)
}

func testAccGithubAuthBackendConfig_description(path, org, description string) string {
	return fmt.Sprintf(`
resource "vault_github_auth_backend" "gh" {
	path = "%s"
	organization = "%s"
	description = "%s"  
}
`, path, org, description)
}
