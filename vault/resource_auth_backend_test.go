// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccAuthBackend(t *testing.T) {
	path := "github-" + acctest.RandString(10)

	resourceName := "vault_auth_backend.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceAuth_initialConfig(path + consts.PathDelim),
				ExpectError: regexp.MustCompile(
					fmt.Sprintf(`value "%s" for %q contains leading/trailing %q`,
						path+consts.PathDelim, "path", consts.PathDelim),
				),
			},
			{
				Config: testResourceAuth_initialConfig(consts.PathDelim + path),
				ExpectError: regexp.MustCompile(
					fmt.Sprintf(`value "%s" for %q contains leading/trailing %q`,
						consts.PathDelim+path, "path", consts.PathDelim),
				),
			},
			{
				Config: testResourceAuth_initialConfig(path),
				Check:  testResourceAuth_initialCheck(path),
			},
			{
				Config: testResourceAuth_updatedConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "Test auth backend updated"),
					resource.TestCheckResourceAttr(resourceName, "type", "github"),
					resource.TestCheckResourceAttr(resourceName, "path", path),
				),
			},
		},
	})
}

func TestAccAuthBackend_remount(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-auth")
	updatedPath := acctest.RandomWithPrefix("tf-test-auth-updated")

	resourceName := "vault_auth_backend.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceAuth_initialConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "description", "Test auth backend"),
					resource.TestCheckResourceAttr(resourceName, "type", "github"),
				),
			},
			{
				Config: testResourceAuth_initialConfig(updatedPath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", updatedPath),
					resource.TestCheckResourceAttr(resourceName, "description", "Test auth backend"),
					resource.TestCheckResourceAttr(resourceName, "type", "github"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "disable_remount"),
		},
	})
}

func testAccCheckAuthBackendDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_auth_backend" {
			continue
		}
		instanceState := rs.Primary
		if instanceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		auths, err := client.Sys().ListAuth()
		if err != nil {
			return err
		}

		if _, ok := auths[instanceState.ID]; ok {
			return fmt.Errorf("Auth backend still exists")
		}
	}
	return nil
}

func testResourceAuth_initialConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
	description = "Test auth backend"
	type 		= "github"
	path 		= "%s"
	local 		= true
}`, path)
}

func testResourceAuth_updatedConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
	description = "Test auth backend updated"
	type 		= "github"
	path 		= "%s"
	local 		= true
}`, path)
}

func testResourceAuth_initialCheck(expectedPath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_auth_backend.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		path := instanceState.ID

		if path != instanceState.Attributes["path"] {
			return fmt.Errorf("id doesn't match path")
		}

		if path != expectedPath {
			return fmt.Errorf("unexpected auth path %q, expected %q", path, expectedPath)
		}

		if instanceState.Attributes["type"] != "github" {
			return fmt.Errorf("unexpected auth type")
		}

		if instanceState.Attributes["description"] != "Test auth backend" {
			return fmt.Errorf("unexpected auth description")
		}

		if instanceState.Attributes["local"] != "true" {
			return fmt.Errorf("unexpected auth local")
		}

		client, e := provider.GetClient(instanceState, testProvider.Meta())
		if e != nil {
			return e
		}

		auths, err := client.Sys().ListAuth()
		if err != nil {
			return fmt.Errorf("error reading back auth: %s", err)
		}

		found := false
		for serverPath, serverAuth := range auths {
			if serverPath == expectedPath+"/" {
				found = true
				if serverAuth.Type != "github" {
					return fmt.Errorf("unexpected auth type")
				}
				if serverAuth.Description != "Test auth backend" {
					return fmt.Errorf("unexpected auth description")
				}
				if serverAuth.Local != true {
					return fmt.Errorf("unexpected auth local")
				}
				break
			}
		}

		if !found {
			return fmt.Errorf("could not find auth backend %q in %+v", expectedPath, auths)
		}

		return nil
	}
}

func TestAccAuthBackend_tuning(t *testing.T) {
	testutil.SkipTestAcc(t)

	resType := "vault_auth_backend"
	backend := acctest.RandomWithPrefix("github")
	resName := resType + ".test"
	var resAuthFirst api.AuthMount

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resType, consts.MountTypeGitHub, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testResourceAuthTune_initialConfig(backend),
				Check: resource.ComposeTestCheckFunc(
					testutil.TestAccCheckAuthMountExists(resName,
						&resAuthFirst,
						testProvider.Meta().(*provider.ProviderMeta).MustGetClient()),
					resource.TestCheckResourceAttr(resName, "path", backend),
					resource.TestCheckResourceAttr(resName, "id", backend),
					resource.TestCheckResourceAttr(resName, "type", "github"),
					resource.TestCheckResourceAttr(resName, "tune.#", "1"),
					resource.TestCheckResourceAttr(resName, "tune.0.allowed_response_headers.#", "2"),
					resource.TestCheckResourceAttr(resName, "tune.0.allowed_response_headers.0", "X-Custom-Response-Header"),
					resource.TestCheckResourceAttr(resName, "tune.0.allowed_response_headers.1", "X-Forwarded-Response-To"),
					// ensure the global default effect from Vault tune API is ignored,
					// these fields should stay empty
					resource.TestCheckResourceAttr(resName, "tune.0.default_lease_ttl", ""),
					resource.TestCheckResourceAttr(resName, "tune.0.max_lease_ttl", ""),
					resource.TestCheckResourceAttr(resName, "tune.0.listing_visibility", ""),
					resource.TestCheckResourceAttr(resName, "tune.0.token_type", ""),
					resource.TestCheckResourceAttrPtr(resName, "accessor", &resAuthFirst.Accessor),
					checkAuthMount(backend, "github",
						listingVisibility(""),
						defaultLeaseTTL(2764800), // 768h
						maxLeaseTTL(2764800),     // 768h
						tokenType("default-service"),
					),
				),
			},
			{
				Config: testResourceAuthTune_updateConfig(backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPtr(resName, "accessor", &resAuthFirst.Accessor),
					resource.TestCheckResourceAttr(resName, "path", backend),
					resource.TestCheckResourceAttr(resName, "id", backend),
					resource.TestCheckResourceAttr(resName, "type", "github"),
					resource.TestCheckResourceAttr(resName, "tune.#", "1"),
					resource.TestCheckResourceAttr(resName, "tune.0.default_lease_ttl", "200s"),
					resource.TestCheckResourceAttr(resName, "tune.0.max_lease_ttl", "500s"),
					resource.TestCheckResourceAttr(resName, "tune.0.listing_visibility", "unauth"),
					resource.TestCheckResourceAttr(resName, "tune.0.token_type", "default-batch"),
					checkAuthMount(backend, "github",
						listingVisibility("unauth"),
						defaultLeaseTTL(200),
						maxLeaseTTL(500),
						tokenType("default-batch"),
					),
				),
			},
		},
	})
}

func TestAccAuthBackend_importTune(t *testing.T) {
	testutil.SkipTestAcc(t)

	resType := "vault_auth_backend"
	backend := acctest.RandomWithPrefix("github-import")
	resName := resType + ".test"
	var resAuthFirst api.AuthMount

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resType, consts.MountTypeGitHub, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testResourceAuthTune_import(backend),
				Check: resource.ComposeTestCheckFunc(
					testutil.TestAccCheckAuthMountExists(resName,
						&resAuthFirst,
						testProvider.Meta().(*provider.ProviderMeta).MustGetClient()),
					resource.TestCheckResourceAttrPtr(resName, "accessor", &resAuthFirst.Accessor),
					resource.TestCheckResourceAttr(resName, "path", backend),
					resource.TestCheckResourceAttr(resName, "id", backend),
					resource.TestCheckResourceAttr(resName, "type", "github"),
					resource.TestCheckResourceAttr(resName, "tune.#", "1"),
					resource.TestCheckResourceAttr(resName, "tune.0.default_lease_ttl", "10m"),
					resource.TestCheckResourceAttr(resName, "tune.0.max_lease_ttl", "20m"),
					resource.TestCheckResourceAttr(resName, "tune.0.listing_visibility", "hidden"),
					resource.TestCheckResourceAttr(resName, "tune.0.token_type", "batch"),
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
				),
			},
			testutil.GetImportTestStep(resName, false, nil, "disable_remount"),
		},
	})
}

func testResourceAuthTune_initialConfig(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
	type = "github"
	path = "%s"
	tune {
		allowed_response_headers = ["X-Custom-Response-Header", "X-Forwarded-Response-To"]
	}
}`, backend)
}

func testResourceAuthTune_updateConfig(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
	type = "github"
	path = "%s"
	tune {
		listing_visibility = "unauth"
		max_lease_ttl      = "500s"
		default_lease_ttl  = "200s"
		token_type         = "default-batch"
	}
}`, backend)
}

func testResourceAuthTune_import(path string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
  	type = "github"
	path = "%s"

  	tune {
		default_lease_ttl = "10m"
		max_lease_ttl = "20m"
		listing_visibility = "hidden"
		token_type = "batch"
		audit_non_hmac_request_keys = ["key1", "key2"]
		audit_non_hmac_response_keys = ["key3", "key4"]
		passthrough_request_headers = ["X-Custom-Header", "X-Forwarded-To"]
		allowed_response_headers = ["X-Custom-Response-Header", "X-Forwarded-Response-To"]
	}
}
`, path)
}

// checkAuthMount verifies the auth type and configuration of an auth mount.
func checkAuthMount(backend string, authType string, checkers ...func(*api.MountConfigOutput) error) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()
		authMount, err := client.Sys().GetAuth(backend)
		if err != nil {
			return fmt.Errorf("error getting auth backend: %s", err)
		}

		if authMount.Type != authType {
			return fmt.Errorf("unexpected auth type: expected %q but got %q", authType, authMount.Type)
		}

		// Read and check auth tune
		mountConfigOutput, err := client.Sys().MountConfig("auth/" + backend)
		if err != nil {
			return fmt.Errorf("error reading auth tune: %s", err)
		}

		for _, checker := range checkers {
			if err := checker(mountConfigOutput); err != nil {
				return err
			}
		}

		return nil
	}
}

func listingVisibility(expected string) func(*api.MountConfigOutput) error {
	return func(output *api.MountConfigOutput) error {
		actual := output.ListingVisibility
		if actual != expected {
			return fmt.Errorf("unexpected auth listing_visibility: expected %q but got %q", expected, actual)
		}
		return nil
	}
}

func defaultLeaseTTL(expected int) func(*api.MountConfigOutput) error {
	return func(output *api.MountConfigOutput) error {
		actual := output.DefaultLeaseTTL
		if actual != expected {
			return fmt.Errorf("unexpected auth default_lease_ttl: expected %d but got %d", expected, actual)
		}
		return nil
	}
}

func maxLeaseTTL(expected int) func(*api.MountConfigOutput) error {
	return func(output *api.MountConfigOutput) error {
		actual := output.MaxLeaseTTL
		if actual != expected {
			return fmt.Errorf("unexpected auth max_lease_ttl: expected %d but got %d", expected, actual)
		}
		return nil
	}
}

func tokenType(expected string) func(*api.MountConfigOutput) error {
	return func(output *api.MountConfigOutput) error {
		actual := output.TokenType
		if actual != expected {
			return fmt.Errorf("unexpected auth token_type: expected %q but got %q", expected, actual)
		}
		return nil
	}
}
