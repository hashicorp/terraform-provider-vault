// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

var (
	// Common regexp patterns used across GCP ephemeral resource tests
	regexpNonEmpty = regexp.MustCompile(`^.+$`)
)

// TestAccGCPOAuth2AccessToken_basic tests generating OAuth2 access tokens
// from different GCP credential types (roleset, static account, impersonated account)
// and demonstrates realistic resource mutation patterns
func TestAccGCPOAuth2AccessToken_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-gcp")
	roleset := acctest.RandomWithPrefix("tf-roleset")
	staticAccount := acctest.RandomWithPrefix("tf-static")
	impersonatedAccount := acctest.RandomWithPrefix("tf-impersonated")

	creds, project := testutil.GetTestGCPCreds(t)
	serviceAccountEmail := testutil.SkipTestEnvUnset(t, "GOOGLE_SERVICE_ACCOUNT_EMAIL")[0]

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				// Step 1: Create and use roleset
				Config: testAccGCPOAuth2AccessTokenRolesetConfig(backend, roleset, creds, project),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.gcp_token", tfjsonpath.New("data").AtMapKey("token"), knownvalue.StringRegexp(regexpNonEmpty)),
					statecheck.ExpectKnownValue("echo.gcp_token", tfjsonpath.New("data").AtMapKey("lease_start_time"), knownvalue.StringRegexp(regexpNonEmpty)),
					statecheck.ExpectKnownValue("echo.gcp_token", tfjsonpath.New("data").AtMapKey(consts.FieldLeaseRenewable), knownvalue.Bool(false)),
				},
			},
			{
				// Step 2: Mutate to use static_account instead of roleset
				Config: testAccGCPOAuth2AccessTokenStaticAccountConfig(backend, staticAccount, creds, serviceAccountEmail),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.gcp_token", tfjsonpath.New("data").AtMapKey("token"), knownvalue.StringRegexp(regexpNonEmpty)),
					statecheck.ExpectKnownValue("echo.gcp_token", tfjsonpath.New("data").AtMapKey("lease_start_time"), knownvalue.StringRegexp(regexpNonEmpty)),
				},
			},
			{
				// Step 3: Mutate to use impersonated_account
				Config: testAccGCPOAuth2AccessTokenImpersonatedAccountConfig(backend, impersonatedAccount, creds, serviceAccountEmail),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.gcp_token", tfjsonpath.New("data").AtMapKey("token"), knownvalue.StringRegexp(regexpNonEmpty)),
					statecheck.ExpectKnownValue("echo.gcp_token", tfjsonpath.New("data").AtMapKey("lease_start_time"), knownvalue.StringRegexp(regexpNonEmpty)),
				},
			},
			{
				// Step 4: Switch back to roleset to verify bidirectional mutation
				Config: testAccGCPOAuth2AccessTokenRolesetConfig(backend, roleset, creds, project),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.gcp_token", tfjsonpath.New("data").AtMapKey("token"), knownvalue.StringRegexp(regexpNonEmpty)),
					statecheck.ExpectKnownValue("echo.gcp_token", tfjsonpath.New("data").AtMapKey("lease_start_time"), knownvalue.StringRegexp(regexpNonEmpty)),
					statecheck.ExpectKnownValue("echo.gcp_token", tfjsonpath.New("data").AtMapKey(consts.FieldLeaseRenewable), knownvalue.Bool(false)),
				},
			},
		},
	})
}

// TestAccGCPOAuth2AccessToken_validation tests various validation and error scenarios
// including missing fields, conflicting fields, and invalid configurations
func TestAccGCPOAuth2AccessToken_validation(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-gcp")
	roleset := acctest.RandomWithPrefix("tf-roleset")
	staticAccount := acctest.RandomWithPrefix("tf-static")

	creds, project := testutil.GetTestGCPCreds(t)
	serviceAccountEmail := testutil.SkipTestEnvUnset(t, "GOOGLE_SERVICE_ACCOUNT_EMAIL")[0]

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				// Step 1: Missing all credential fields should error
				Config:      testAccGCPOAuth2AccessTokenMissingFieldsConfig(backend, creds),
				ExpectError: regexp.MustCompile(`One of 'roleset', 'static_account', or 'impersonated_account' must be\s+provided`),
			},
			{
				// Step 2: Providing both roleset and static_account should error
				Config:      testAccGCPOAuth2AccessTokenBothFieldsConfig(backend, roleset, staticAccount, creds, project, serviceAccountEmail),
				ExpectError: regexp.MustCompile(`Only one of 'roleset', 'static_account', or 'impersonated_account' can be\s+provided`),
			},
			{
				// Step 3: Invalid backend path should error
				Config:      testAccGCPOAuth2AccessTokenInvalidBackendConfig(roleset),
				ExpectError: regexp.MustCompile("(Error generating GCP OAuth2 access token|No credentials found)"),
			},
			{
				// Step 4: Invalid roleset name should error
				Config:      testAccGCPOAuth2AccessTokenInvalidRolesetConfig(backend, creds),
				ExpectError: regexp.MustCompile("(Error generating GCP OAuth2 access token|No credentials found)"),
			},
		},
	})
}

// TestAccGCPOAuth2AccessToken_optionalFeatures tests optional configuration features
// including namespace (Enterprise) and max_retries settings
func TestAccGCPOAuth2AccessToken_optionalFeatures(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-gcp")
	roleset := acctest.RandomWithPrefix("tf-roleset")
	namespace := acctest.RandomWithPrefix("tf-ns")

	creds, project := testutil.GetTestGCPCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				// Step 1: Test with namespace (Enterprise feature)
				Config: testAccGCPOAuth2AccessTokenWithNamespaceConfig(backend, roleset, namespace, creds, project),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.gcp_token", tfjsonpath.New("data").AtMapKey("token"), knownvalue.StringRegexp(regexpNonEmpty)),
					statecheck.ExpectKnownValue("echo.gcp_token", tfjsonpath.New("data").AtMapKey("lease_start_time"), knownvalue.StringRegexp(regexpNonEmpty)),
				},
			},
			{
				// Step 2: Test with custom max_retries value
				Config: testAccGCPOAuth2AccessTokenWithMaxRetriesConfig(backend, roleset, creds, project),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.gcp_token", tfjsonpath.New("data").AtMapKey("token"), knownvalue.StringRegexp(regexpNonEmpty)),
					statecheck.ExpectKnownValue("echo.gcp_token", tfjsonpath.New("data").AtMapKey("lease_start_time"), knownvalue.StringRegexp(regexpNonEmpty)),
				},
			},
		},
	})
}

// Config functions

func testAccGCPOAuth2AccessTokenRolesetConfig(backend, roleset, credentials, project string) string {
	return fmt.Sprintf(`
resource "vault_gcp_secret_backend" "gcp" {
  path        = "%s"
  credentials = <<CREDS
%s
CREDS
}

resource "vault_gcp_secret_roleset" "roleset" {
  backend      = vault_gcp_secret_backend.gcp.path
  roleset      = "%s"
  secret_type  = "access_token"
  project      = "%s"
  token_scopes = ["https://www.googleapis.com/auth/cloud-platform"]

  binding {
    resource = "//cloudresourcemanager.googleapis.com/projects/%s"
    roles    = ["roles/viewer"]
  }
}

ephemeral "vault_gcp_oauth2_access_token" "token" {
  mount_id = vault_gcp_secret_roleset.roleset.id
  mount    = vault_gcp_secret_backend.gcp.path
  roleset  = vault_gcp_secret_roleset.roleset.roleset
}

provider "echo" {
  data = ephemeral.vault_gcp_oauth2_access_token.token
}

resource "echo" "gcp_token" {}
`, backend, credentials, roleset, project, project)
}

func testAccGCPOAuth2AccessTokenStaticAccountConfig(backend, staticAccount, credentials, serviceAccountEmail string) string {
	return fmt.Sprintf(`
resource "vault_gcp_secret_backend" "gcp" {
  path        = "%s"
  credentials = <<CREDS
%s
CREDS
}

resource "vault_gcp_secret_static_account" "static" {
  backend               = vault_gcp_secret_backend.gcp.path
  static_account        = "%s"
  secret_type           = "access_token"
  service_account_email = "%s"
  token_scopes          = ["https://www.googleapis.com/auth/cloud-platform"]
}

ephemeral "vault_gcp_oauth2_access_token" "token" {
  mount_id       = vault_gcp_secret_static_account.static.id
  mount          = vault_gcp_secret_backend.gcp.path
  static_account = vault_gcp_secret_static_account.static.static_account
}

provider "echo" {
  data = ephemeral.vault_gcp_oauth2_access_token.token
}

resource "echo" "gcp_token" {}
`, backend, credentials, staticAccount, serviceAccountEmail)
}

func testAccGCPOAuth2AccessTokenImpersonatedAccountConfig(backend, impersonatedAccount, credentials, serviceAccountEmail string) string {
	return fmt.Sprintf(`
resource "vault_gcp_secret_backend" "gcp" {
  path        = "%s"
  credentials = <<CREDS
%s
CREDS
}

resource "vault_gcp_secret_impersonated_account" "impersonated" {
  backend               = vault_gcp_secret_backend.gcp.path
  impersonated_account  = "%s"
  service_account_email = "%s"
  token_scopes          = ["https://www.googleapis.com/auth/cloud-platform"]
}

ephemeral "vault_gcp_oauth2_access_token" "token" {
  mount_id            = vault_gcp_secret_impersonated_account.impersonated.id
  mount               = vault_gcp_secret_backend.gcp.path
  impersonated_account = vault_gcp_secret_impersonated_account.impersonated.impersonated_account
}

provider "echo" {
  data = ephemeral.vault_gcp_oauth2_access_token.token
}

resource "echo" "gcp_token" {}
`, backend, credentials, impersonatedAccount, serviceAccountEmail)
}

func testAccGCPOAuth2AccessTokenMissingFieldsConfig(backend, credentials string) string {
	return fmt.Sprintf(`
resource "vault_gcp_secret_backend" "gcp" {
  path        = "%s"
  credentials = <<CREDS
%s
CREDS
}

ephemeral "vault_gcp_oauth2_access_token" "token" {
  mount = vault_gcp_secret_backend.gcp.path
}

provider "echo" {
  data = ephemeral.vault_gcp_oauth2_access_token.token
}

resource "echo" "gcp_token" {}
`, backend, credentials)
}

func testAccGCPOAuth2AccessTokenBothFieldsConfig(backend, roleset, staticAccount, credentials, project, serviceAccountEmail string) string {
	return fmt.Sprintf(`
resource "vault_gcp_secret_backend" "gcp" {
  path        = "%s"
  credentials = <<CREDS
%s
CREDS
}

resource "vault_gcp_secret_roleset" "roleset" {
  backend      = vault_gcp_secret_backend.gcp.path
  roleset      = "%s"
  secret_type  = "access_token"
  project      = "%s"
  token_scopes = ["https://www.googleapis.com/auth/cloud-platform"]

  binding {
    resource = "//cloudresourcemanager.googleapis.com/projects/%s"
    roles    = ["roles/viewer"]
  }
}

resource "vault_gcp_secret_static_account" "static" {
  backend               = vault_gcp_secret_backend.gcp.path
  static_account        = "%s"
  secret_type           = "access_token"
  service_account_email = "%s"
  token_scopes          = ["https://www.googleapis.com/auth/cloud-platform"]
}

ephemeral "vault_gcp_oauth2_access_token" "token" {
  mount          = vault_gcp_secret_backend.gcp.path
  roleset        = vault_gcp_secret_roleset.roleset.roleset
  static_account = vault_gcp_secret_static_account.static.static_account
}

provider "echo" {
  data = ephemeral.vault_gcp_oauth2_access_token.token
}

resource "echo" "gcp_token" {}
`, backend, credentials, roleset, project, project, staticAccount, serviceAccountEmail)
}

func testAccGCPOAuth2AccessTokenInvalidBackendConfig(roleset string) string {
	return fmt.Sprintf(`
ephemeral "vault_gcp_oauth2_access_token" "token" {
  mount   = "nonexistent-backend"
  roleset = "%s"
}

provider "echo" {
  data = ephemeral.vault_gcp_oauth2_access_token.token
}

resource "echo" "gcp_token" {}
`, roleset)
}

func testAccGCPOAuth2AccessTokenInvalidRolesetConfig(backend, credentials string) string {
	return fmt.Sprintf(`
resource "vault_gcp_secret_backend" "gcp" {
  path        = "%s"
  credentials = <<CREDS
%s
CREDS
}

ephemeral "vault_gcp_oauth2_access_token" "token" {
  mount   = vault_gcp_secret_backend.gcp.path
  roleset = "nonexistent-roleset"
}

provider "echo" {
  data = ephemeral.vault_gcp_oauth2_access_token.token
}

resource "echo" "gcp_token" {}
`, backend, credentials)
}

func testAccGCPOAuth2AccessTokenWithNamespaceConfig(backend, roleset, namespace, credentials, project string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = "%s"
}

resource "vault_gcp_secret_backend" "gcp" {
  namespace   = vault_namespace.test.path
  path        = "%s"
  credentials = <<CREDS
%s
CREDS
}

resource "vault_gcp_secret_roleset" "roleset" {
  namespace    = vault_namespace.test.path
  backend      = vault_gcp_secret_backend.gcp.path
  roleset      = "%s"
  secret_type  = "access_token"
  project      = "%s"
  token_scopes = ["https://www.googleapis.com/auth/cloud-platform"]

  binding {
    resource = "//cloudresourcemanager.googleapis.com/projects/%s"
    roles    = ["roles/viewer"]
  }
}

ephemeral "vault_gcp_oauth2_access_token" "token" {
  namespace = vault_namespace.test.path
  mount_id  = vault_gcp_secret_roleset.roleset.id
  mount     = vault_gcp_secret_backend.gcp.path
  roleset   = vault_gcp_secret_roleset.roleset.roleset
}

provider "echo" {
  data = ephemeral.vault_gcp_oauth2_access_token.token
}

resource "echo" "gcp_token" {}
`, namespace, backend, credentials, roleset, project, project)
}

func testAccGCPOAuth2AccessTokenWithMaxRetriesConfig(backend, roleset, credentials, project string) string {
	return fmt.Sprintf(`
resource "vault_gcp_secret_backend" "gcp" {
  path        = "%s"
  credentials = <<CREDS
%s
CREDS
}

resource "vault_gcp_secret_roleset" "roleset" {
  backend      = vault_gcp_secret_backend.gcp.path
  roleset      = "%s"
  secret_type  = "access_token"
  project      = "%s"
  token_scopes = ["https://www.googleapis.com/auth/cloud-platform"]

  binding {
    resource = "//cloudresourcemanager.googleapis.com/projects/%s"
    roles    = ["roles/viewer"]
  }
}

ephemeral "vault_gcp_oauth2_access_token" "token" {
  mount_id    = vault_gcp_secret_roleset.roleset.id
  mount       = vault_gcp_secret_backend.gcp.path
  roleset     = vault_gcp_secret_roleset.roleset.roleset
  max_retries = 5
}

provider "echo" {
  data = ephemeral.vault_gcp_oauth2_access_token.token
}

resource "echo" "gcp_token" {}
`, backend, credentials, roleset, project, project)
}
