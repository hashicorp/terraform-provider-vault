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

// TestAccGCPOAuth2AccessToken_roleset tests generating an OAuth2 access token
// from a GCP roleset with all ephemeral resource attributes
func TestAccGCPOAuth2AccessToken_roleset(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-gcp")
	roleset := acctest.RandomWithPrefix("tf-roleset")

	creds, project := testutil.GetTestGCPCreds(t)

	nonEmpty := regexp.MustCompile(`^.+$`)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccGCPOAuth2AccessTokenRolesetConfig(backend, roleset, creds, project),
				ConfigStateChecks: []statecheck.StateCheck{
					// Verify token is set and not empty
					statecheck.ExpectKnownValue("echo.gcp_token", tfjsonpath.New("data").AtMapKey("token"), knownvalue.StringRegexp(nonEmpty)),
					// Verify lease_start_time is set
					statecheck.ExpectKnownValue("echo.gcp_token", tfjsonpath.New("data").AtMapKey("lease_start_time"), knownvalue.StringRegexp(nonEmpty)),
					// Verify lease_renewable is set to false
					statecheck.ExpectKnownValue("echo.gcp_token", tfjsonpath.New("data").AtMapKey(consts.FieldLeaseRenewable), knownvalue.Bool(false)),
				},
			},
		},
	})
}

// TestAccGCPOAuth2AccessToken_staticAccount tests generating an OAuth2 access token
// from a GCP static account
func TestAccGCPOAuth2AccessToken_staticAccount(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-gcp")
	staticAccount := acctest.RandomWithPrefix("tf-static")

	creds, _ := testutil.GetTestGCPCreds(t)
	serviceAccountEmail := testutil.SkipTestEnvUnset(t, "GOOGLE_SERVICE_ACCOUNT_EMAIL")[0]

	nonEmpty := regexp.MustCompile(`^.+$`)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccGCPOAuth2AccessTokenStaticAccountConfig(backend, staticAccount, creds, serviceAccountEmail),
				ConfigStateChecks: []statecheck.StateCheck{
					// Verify token is set and not empty
					statecheck.ExpectKnownValue("echo.gcp_token", tfjsonpath.New("data").AtMapKey("token"), knownvalue.StringRegexp(nonEmpty)),
					// Verify lease_start_time is set
					statecheck.ExpectKnownValue("echo.gcp_token", tfjsonpath.New("data").AtMapKey("lease_start_time"), knownvalue.StringRegexp(nonEmpty)),
				},
			},
		},
	})
}

// TestAccGCPOAuth2AccessToken_impersonatedAccount tests generating an OAuth2 access token
// from a GCP impersonated account
func TestAccGCPOAuth2AccessToken_impersonatedAccount(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-gcp")
	impersonatedAccount := acctest.RandomWithPrefix("tf-impersonated")

	creds, _ := testutil.GetTestGCPCreds(t)
	serviceAccountEmail := testutil.SkipTestEnvUnset(t, "GOOGLE_SERVICE_ACCOUNT_EMAIL")[0]

	nonEmpty := regexp.MustCompile(`^.+$`)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccGCPOAuth2AccessTokenImpersonatedAccountConfig(backend, impersonatedAccount, creds, serviceAccountEmail),
				ConfigStateChecks: []statecheck.StateCheck{
					// Verify token is set and not empty
					statecheck.ExpectKnownValue("echo.gcp_token", tfjsonpath.New("data").AtMapKey("token"), knownvalue.StringRegexp(nonEmpty)),
					// Verify lease_start_time is set
					statecheck.ExpectKnownValue("echo.gcp_token", tfjsonpath.New("data").AtMapKey("lease_start_time"), knownvalue.StringRegexp(nonEmpty)),
				},
			},
		},
	})
}

// TestAccGCPOAuth2AccessToken_missingRolesetAndStaticAccount tests error handling
// when neither roleset, static_account, nor impersonated_account is provided
func TestAccGCPOAuth2AccessToken_missingRolesetAndStaticAccount(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-gcp")

	creds, _ := testutil.GetTestGCPCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config:      testAccGCPOAuth2AccessTokenMissingFieldsConfig(backend, creds),
				ExpectError: regexp.MustCompile(`One of 'roleset', 'static_account', or 'impersonated_account' must be\s+provided`),
			},
		},
	})
}

// TestAccGCPOAuth2AccessToken_bothRolesetAndStaticAccount tests error handling
// when both roleset and static_account are provided
func TestAccGCPOAuth2AccessToken_bothRolesetAndStaticAccount(t *testing.T) {
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
				Config:      testAccGCPOAuth2AccessTokenBothFieldsConfig(backend, roleset, staticAccount, creds, project, serviceAccountEmail),
				ExpectError: regexp.MustCompile(`Only one of 'roleset', 'static_account', or 'impersonated_account' can be\s+provided`),
			},
		},
	})
}

// TestAccGCPOAuth2AccessToken_invalidBackend tests error handling
// when an invalid backend path is provided
func TestAccGCPOAuth2AccessToken_invalidBackend(t *testing.T) {
	roleset := acctest.RandomWithPrefix("tf-roleset")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config:      testAccGCPOAuth2AccessTokenInvalidBackendConfig(roleset),
				ExpectError: regexp.MustCompile("(Error generating GCP OAuth2 access token|No credentials found)"),
			},
		},
	})
}

// TestAccGCPOAuth2AccessToken_invalidRoleset tests error handling
// when an invalid roleset is provided
func TestAccGCPOAuth2AccessToken_invalidRoleset(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-gcp")

	creds, _ := testutil.GetTestGCPCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config:      testAccGCPOAuth2AccessTokenInvalidRolesetConfig(backend, creds),
				ExpectError: regexp.MustCompile("(Error generating GCP OAuth2 access token|No credentials found)"),
			},
		},
	})
}

// TestAccGCPOAuth2AccessToken_withNamespace tests generating an OAuth2 access token
// with a namespace specified (Enterprise feature)
func TestAccGCPOAuth2AccessToken_withNamespace(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-gcp")
	roleset := acctest.RandomWithPrefix("tf-roleset")
	namespace := acctest.RandomWithPrefix("tf-ns")

	creds, project := testutil.GetTestGCPCreds(t)

	nonEmpty := regexp.MustCompile(`^.+$`)

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
				Config: testAccGCPOAuth2AccessTokenWithNamespaceConfig(backend, roleset, namespace, creds, project),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.gcp_token", tfjsonpath.New("data").AtMapKey("token"), knownvalue.StringRegexp(nonEmpty)),
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
  backend  = vault_gcp_secret_backend.gcp.path
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
  backend        = vault_gcp_secret_backend.gcp.path
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
  backend             = vault_gcp_secret_backend.gcp.path
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
  backend = vault_gcp_secret_backend.gcp.path
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
  backend        = vault_gcp_secret_backend.gcp.path
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
  backend = "nonexistent-backend"
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
  backend = vault_gcp_secret_backend.gcp.path
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
  backend   = vault_gcp_secret_backend.gcp.path
  roleset   = vault_gcp_secret_roleset.roleset.roleset
}

provider "echo" {
  data = ephemeral.vault_gcp_oauth2_access_token.token
}

resource "echo" "gcp_token" {}
`, namespace, backend, credentials, roleset, project, project)
}
