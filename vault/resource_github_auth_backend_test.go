// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
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
	resourceType := "vault_github_auth_backend"
	resourceName := resourceType + ".test"
	var resAuth api.AuthMount

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeGitHub, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccGithubAuthBackendConfig_basic(path, testGHOrg),
				Check: resource.ComposeTestCheckFunc(
					testutil.TestAccCheckAuthMountExists(resourceName,
						&resAuth,
						testProvider.Meta().(*provider.ProviderMeta).MustGetClient()),
					resource.TestCheckResourceAttr(resourceName, "id", path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "organization", testGHOrg),
					// expect computed value for organization_id
					resource.TestCheckResourceAttr(resourceName, "organization_id", strconv.Itoa(orgMeta.ID)),
					resource.TestCheckResourceAttr(resourceName, "token_ttl", "1200"),
					resource.TestCheckResourceAttr(resourceName, "token_max_ttl", "3000"),
					resource.TestCheckResourceAttrPtr(resourceName, "accessor", &resAuth.Accessor),
				),
			},
			{
				Config: testAccGithubAuthBackendConfig_updated(path, "unknown", 2999),
				Check: resource.ComposeTestCheckFunc(
					testutil.TestAccCheckAuthMountExists(resourceName,
						&resAuth,
						testProvider.Meta().(*provider.ProviderMeta).MustGetClient()),
					resource.TestCheckResourceAttr(resourceName, "id", path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "organization", "unknown"),
					resource.TestCheckResourceAttr(resourceName, "organization_id", "2999"),
					resource.TestCheckResourceAttr(resourceName, "token_ttl", "2400"),
					resource.TestCheckResourceAttr(resourceName, "token_max_ttl", "6000"),
					resource.TestCheckResourceAttrPtr(resourceName, "accessor", &resAuth.Accessor),
				),
			},
		},
	})
}

func TestAccGithubAuthBackend_ns(t *testing.T) {
	testutil.SkipTestAcc(t)

	orgMeta := testutil.GetGHOrgResponse(t, testGHOrg)

	path := acctest.RandomWithPrefix("github")
	ns := acctest.RandomWithPrefix("ns")
	resourceType := "vault_github_auth_backend"
	resourceName := resourceType + ".test"
	var resAuth api.AuthMount

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeGitHub, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccGithubAuthBackendConfig_ns(ns, path, testGHOrg),
				Check: resource.ComposeTestCheckFunc(
					testutil.TestAccCheckAuthMountExists(resourceName,
						&resAuth,
						testProvider.Meta().(*provider.ProviderMeta).MustGetClient()),
					resource.TestCheckResourceAttr(resourceName, "id", path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "organization", testGHOrg),
					// expect computed value for organization_id
					resource.TestCheckResourceAttr(resourceName, "organization_id", strconv.Itoa(orgMeta.ID)),
					resource.TestCheckResourceAttr(resourceName, "token_ttl", "1200"),
					resource.TestCheckResourceAttr(resourceName, "token_max_ttl", "3000"),
					resource.TestCheckResourceAttrPtr(resourceName, "accessor", &resAuth.Accessor),
				),
			},
		},
	})
}

func TestAccGithubAuthBackend_tuning(t *testing.T) {
	testutil.SkipTestAcc(t)

	orgMeta := testutil.GetGHOrgResponse(t, testGHOrg)

	backend := acctest.RandomWithPrefix("github")
	resourceType := "vault_github_auth_backend"
	resourceName := resourceType + ".test"
	var resAuth api.AuthMount

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeGitHub, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccGithubAuthBackendConfig_tuning(backend),
				Check: resource.ComposeTestCheckFunc(
					testutil.TestAccCheckAuthMountExists(resourceName,
						&resAuth,
						testProvider.Meta().(*provider.ProviderMeta).MustGetClient()),
					resource.TestCheckResourceAttr(resourceName, "id", backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, backend),
					resource.TestCheckResourceAttr(resourceName, "organization", testGHOrg),
					resource.TestCheckResourceAttr(resourceName, "organization_id", strconv.Itoa(orgMeta.ID)),
					resource.TestCheckResourceAttr(resourceName, "tune.0.default_lease_ttl", "10m"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.max_lease_ttl", "20m"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.listing_visibility", "hidden"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.0", "key1"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.1", "key2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_response_keys.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_response_keys.0", "key3"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_response_keys.1", "key4"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.0", "X-Custom-Header"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.1", "X-Forwarded-To"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.0", "X-Custom-Response-Header"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.1", "X-Forwarded-Response-To"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.token_type", "batch"),
				),
			},
			{
				Config: testAccGithubAuthBackendConfig_tuningUpdated(backend),
				Check: resource.ComposeTestCheckFunc(
					testutil.TestAccCheckAuthMountExists(resourceName,
						&resAuth,
						testProvider.Meta().(*provider.ProviderMeta).MustGetClient()),
					resource.TestCheckResourceAttr(resourceName, "id", backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, backend),
					resource.TestCheckResourceAttr(resourceName, "organization", testGHOrg),
					resource.TestCheckResourceAttr(resourceName, "organization_id", strconv.Itoa(orgMeta.ID)),
					resource.TestCheckResourceAttr(resourceName, "tune.0.default_lease_ttl", "50m"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.max_lease_ttl", "1h10m"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.listing_visibility", "unauth"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.0", "key1"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_response_keys.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.0", "X-Custom-Header"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.1", "X-Forwarded-To"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.2", "X-Mas"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.0", "X-Custom-Response-Header"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.1", "X-Forwarded-Response-To"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.2", "X-Mas-Response"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.token_type", "default-batch"),
				),
			},
		},
	})
}

func TestAccGithubAuthBackend_description(t *testing.T) {
	testutil.SkipTestAcc(t)

	orgMeta := testutil.GetGHOrgResponse(t, testGHOrg)

	path := acctest.RandomWithPrefix("github")
	resourceType := "vault_github_auth_backend"
	resourceName := resourceType + ".test"
	var resAuth api.AuthMount
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeGitHub, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccGithubAuthBackendConfig_description(path, testGHOrg, "Github Auth Mount"),
				Check: resource.ComposeTestCheckFunc(
					testutil.TestAccCheckAuthMountExists(resourceName,
						&resAuth,
						testProvider.Meta().(*provider.ProviderMeta).MustGetClient()),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "organization", testGHOrg),
					resource.TestCheckResourceAttr(resourceName, "organization_id", strconv.Itoa(orgMeta.ID)),
					resource.TestCheckResourceAttr(resourceName, "description", "Github Auth Mount"),
				),
			},
			{
				Config: testAccGithubAuthBackendConfig_description(path, testGHOrg, "Github Auth Mount Updated"),
				Check: resource.ComposeTestCheckFunc(
					testutil.TestAccCheckAuthMountExists(resourceName,
						&resAuth,
						testProvider.Meta().(*provider.ProviderMeta).MustGetClient()),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "organization", orgMeta.Login),
					resource.TestCheckResourceAttr(resourceName, "organization_id", strconv.Itoa(orgMeta.ID)),
					resource.TestCheckResourceAttr(resourceName, "description", "Github Auth Mount Updated"),
				),
			},
		},
	})
}

func TestAccGithubAuthBackend_importTuning(t *testing.T) {
	path := acctest.RandomWithPrefix("github")
	resourceType := "vault_github_auth_backend"
	resourceName := resourceType + ".test"
	var resAuth api.AuthMount
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeGitHub, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccGithubAuthBackendConfig_tuning(path),
				Check: testutil.TestAccCheckAuthMountExists(resourceName,
					&resAuth,
					testProvider.Meta().(*provider.ProviderMeta).MustGetClient()),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "disable_remount"),
		},
	})
}

func TestGithubAuthBackend_remount(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gh")
	updatedPath := acctest.RandomWithPrefix("tf-test-gh-updated")

	orgMeta := testutil.GetGHOrgResponse(t, testGHOrg)

	resourceType := "vault_github_auth_backend"
	resourceName := resourceType + ".test"
	var resAuth api.AuthMount

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testCheckMountDestroyed(resourceType, consts.MountTypeGitHub, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccGithubAuthBackendConfig_basic(path, testGHOrg),
				Check: resource.ComposeTestCheckFunc(
					testutil.TestAccCheckAuthMountExists(resourceName,
						&resAuth,
						testProvider.Meta().(*provider.ProviderMeta).MustGetClient()),
					resource.TestCheckResourceAttr(resourceName, "id", path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "organization", testGHOrg),
					// expect computed value for organization_id
					resource.TestCheckResourceAttr(resourceName, "organization_id", strconv.Itoa(orgMeta.ID)),
					resource.TestCheckResourceAttr(resourceName, "token_ttl", "1200"),
					resource.TestCheckResourceAttr(resourceName, "token_max_ttl", "3000"),
					resource.TestCheckResourceAttrPtr(resourceName, "accessor", &resAuth.Accessor),
				),
			},
			{
				Config: testAccGithubAuthBackendConfig_basic(updatedPath, testGHOrg),
				Check: resource.ComposeTestCheckFunc(
					testutil.TestAccCheckAuthMountExists(resourceName,
						&resAuth,
						testProvider.Meta().(*provider.ProviderMeta).MustGetClient()),
					resource.TestCheckResourceAttr(resourceName, "id", updatedPath),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, updatedPath),
					resource.TestCheckResourceAttr(resourceName, "organization", testGHOrg),
					// expect computed value for organization_id
					resource.TestCheckResourceAttr(resourceName, "organization_id", strconv.Itoa(orgMeta.ID)),
					resource.TestCheckResourceAttr(resourceName, "token_ttl", "1200"),
					resource.TestCheckResourceAttr(resourceName, "token_max_ttl", "3000"),
					resource.TestCheckResourceAttrPtr(resourceName, "accessor", &resAuth.Accessor),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "disable_remount"),
		},
	})
}

func testAccGithubAuthBackendConfig_basic(path, org string) string {
	return fmt.Sprintf(`
resource "vault_github_auth_backend" "test" {
	path = "%s"
	organization = "%s"
	token_ttl = 1200
	token_max_ttl = 3000
}
`, path, org)
}

func testAccGithubAuthBackendConfig_ns(ns, path, org string) string {
	config := fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = "%s"
}

resource "vault_github_auth_backend" "test" {
  namespace     = vault_namespace.test.path
  path          = "%s"
  organization  = "%s"
  token_ttl     = 1200
  token_max_ttl = 3000
}
`, ns, path, org)

	return config
}

func testAccGithubAuthBackendConfig_updated(path, org string, orgID int) string {
	return fmt.Sprintf(`
resource "vault_github_auth_backend" "test" {
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
resource "vault_github_auth_backend" "test" {
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
resource "vault_github_auth_backend" "test" {
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
resource "vault_github_auth_backend" "test" {
	path = "%s"
	organization = "%s"
	description = "%s"  
}
`, path, org, description)
}
