// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets_test

import (
	"encoding/json"
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
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccGCPServiceAccountKey_roleset tests generating a service account key
// from a GCP roleset with all ephemeral resource attributes
func TestAccGCPServiceAccountKey_roleset(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-gcp")
	roleset := acctest.RandomWithPrefix("tf-roleset")

	// Get GCP credentials and project
	creds, project := testutil.GetTestGCPCreds(t)

	nonEmpty := regexp.MustCompile(`^.+$`)
	emailRegex := regexp.MustCompile(`^.+@.+\.iam\.gserviceaccount\.com$`)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccGCPServiceAccountKeyRolesetConfig(backend, roleset, creds, project),
				ConfigStateChecks: []statecheck.StateCheck{
					// Verify private_key_data contains expected JSON structure (matches service_account type and has private_key)
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("private_key_data"), knownvalue.StringRegexp(regexp.MustCompile(`(?s).*"type":\s*"service_account".*`))),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("private_key_data"), knownvalue.StringRegexp(regexp.MustCompile(`(?s).*"private_key":\s*"-----BEGIN PRIVATE KEY-----.*`))),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("private_key_data"), knownvalue.StringRegexp(regexp.MustCompile(`(?s).*"client_email":\s*".+@.+\.iam\.gserviceaccount\.com".*`))),
					// Verify private_key_type is set
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("private_key_type"), knownvalue.StringExact("TYPE_GOOGLE_CREDENTIALS_FILE")),
					// Verify service_account_email matches expected pattern
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("service_account_email"), knownvalue.StringRegexp(emailRegex)),
					// Verify lease fields are set
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey(consts.FieldLeaseID), knownvalue.StringRegexp(nonEmpty)),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey(consts.FieldLeaseDuration), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("lease_start_time"), knownvalue.StringRegexp(nonEmpty)),
					// lease_renewable can be true or false depending on Vault configuration
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey(consts.FieldLeaseRenewable), knownvalue.NotNull()),
				},
			},
		},
	})
}

// NOTE: TestAccGCPServiceAccountKey_rolesetWithoutEphemeralAttrs is not included because
// ephemeral resources are evaluated during the plan phase, which means the roleset must
// already exist. The mount_id attribute is specifically designed to create this dependency.
// Without mount_id, there's no way to ensure the roleset exists when the ephemeral resource
// is evaluated, making this test scenario impractical for ephemeral resources.

// TestAccGCPServiceAccountKey_staticAccount tests generating a service account key
// from a GCP static account
func TestAccGCPServiceAccountKey_staticAccount(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-gcp")
	staticAccount := acctest.RandomWithPrefix("tf-static")

	creds, _ := testutil.GetTestGCPCreds(t)

	// Extract service account email from credentials
	var credsMap map[string]interface{}
	if err := json.Unmarshal([]byte(creds), &credsMap); err != nil {
		t.Fatalf("Failed to parse GCP credentials: %v", err)
	}
	serviceAccountEmail, ok := credsMap["client_email"].(string)
	if !ok || serviceAccountEmail == "" {
		t.Fatal("GCP credentials must contain client_email field")
	}

	nonEmpty := regexp.MustCompile(`^.+$`)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccGCPServiceAccountKeyStaticAccountConfig(backend, staticAccount, creds, serviceAccountEmail),
				ConfigStateChecks: []statecheck.StateCheck{
					// Verify private_key_data contains expected JSON structure
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("private_key_data"), knownvalue.StringRegexp(regexp.MustCompile(`(?s).*"type":\s*"service_account".*`))),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("private_key_data"), knownvalue.StringRegexp(regexp.MustCompile(`(?s).*"private_key":\s*"-----BEGIN PRIVATE KEY-----.*`))),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("service_account_email"), knownvalue.StringExact(serviceAccountEmail)),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey(consts.FieldLeaseID), knownvalue.StringRegexp(nonEmpty)),
				},
			},
		},
	})
}

// TestAccGCPServiceAccountKey_withKeyOptions tests generating a service account key
// with custom key_algorithm and key_type options
func TestAccGCPServiceAccountKey_withKeyOptions(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-gcp")
	roleset := acctest.RandomWithPrefix("tf-roleset")

	creds, project := testutil.GetTestGCPCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccGCPServiceAccountKeyWithOptionsConfig(backend, roleset, creds, project),
				ConfigStateChecks: []statecheck.StateCheck{
					// Verify private_key_data contains expected JSON structure
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("private_key_data"), knownvalue.StringRegexp(regexp.MustCompile(`(?s).*"type":\s*"service_account".*`))),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("private_key_data"), knownvalue.StringRegexp(regexp.MustCompile(`(?s).*"private_key":\s*"-----BEGIN PRIVATE KEY-----.*`))),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("private_key_type"), knownvalue.StringExact("TYPE_GOOGLE_CREDENTIALS_FILE")),
				},
			},
		},
	})
}

// TestAccGCPServiceAccountKey_missingRolesetAndStaticAccount tests error handling
// when neither roleset nor static_account is provided
func TestAccGCPServiceAccountKey_missingRolesetAndStaticAccount(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-gcp")

	creds, _ := testutil.GetTestGCPCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config:      testAccGCPServiceAccountKeyMissingFieldsConfig(backend, creds),
				ExpectError: regexp.MustCompile("Either 'roleset' or 'static_account' must be provided"),
			},
		},
	})
}

// TestAccGCPServiceAccountKey_bothRolesetAndStaticAccount tests error handling
// when both roleset and static_account are provided
func TestAccGCPServiceAccountKey_bothRolesetAndStaticAccount(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-gcp")
	roleset := acctest.RandomWithPrefix("tf-roleset")
	staticAccount := acctest.RandomWithPrefix("tf-static")

	creds, project := testutil.GetTestGCPCreds(t)

	var credsMap map[string]interface{}
	if err := json.Unmarshal([]byte(creds), &credsMap); err != nil {
		t.Fatalf("Failed to parse GCP credentials: %v", err)
	}
	serviceAccountEmail := credsMap["client_email"].(string)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config:      testAccGCPServiceAccountKeyBothFieldsConfig(backend, roleset, staticAccount, creds, project, serviceAccountEmail),
				ExpectError: regexp.MustCompile("Only one of 'roleset' or 'static_account' can be provided"),
			},
		},
	})
}

// TestAccGCPServiceAccountKey_invalidBackend tests error handling
// when an invalid backend path is provided
func TestAccGCPServiceAccountKey_invalidBackend(t *testing.T) {
	roleset := acctest.RandomWithPrefix("tf-roleset")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config:      testAccGCPServiceAccountKeyInvalidBackendConfig(roleset),
				ExpectError: regexp.MustCompile("Error generating GCP service account key"),
			},
		},
	})
}

// Config functions

func testAccGCPServiceAccountKeyRolesetConfig(backend, roleset, credentials, project string) string {
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
  secret_type  = "service_account_key"
  project      = "%s"
  token_scopes = ["https://www.googleapis.com/auth/cloud-platform"]

  binding {
    resource = "//cloudresourcemanager.googleapis.com/projects/%s"
    roles    = ["roles/viewer"]
  }
}

ephemeral "vault_gcp_service_account_key" "key" {
  mount_id = vault_gcp_secret_roleset.roleset.id
  backend  = vault_gcp_secret_backend.gcp.path
  roleset  = vault_gcp_secret_roleset.roleset.roleset
}

provider "echo" {
  data = ephemeral.vault_gcp_service_account_key.key
}

resource "echo" "gcp_key" {}
`, backend, credentials, roleset, project, project)
}

func testAccGCPServiceAccountKeyStaticAccountConfig(backend, staticAccount, credentials, serviceAccountEmail string) string {
	return fmt.Sprintf(`
resource "vault_gcp_secret_backend" "gcp" {
  path        = "%s"
  credentials = <<CREDS
%s
CREDS
}

resource "vault_gcp_secret_static_account" "static" {
  backend            = vault_gcp_secret_backend.gcp.path
  static_account     = "%s"
  secret_type        = "service_account_key"
  service_account_email = "%s"
  token_scopes       = ["https://www.googleapis.com/auth/cloud-platform"]
}

ephemeral "vault_gcp_service_account_key" "key" {
  mount_id       = vault_gcp_secret_static_account.static.id
  backend        = vault_gcp_secret_backend.gcp.path
  static_account = vault_gcp_secret_static_account.static.static_account
}

provider "echo" {
  data = ephemeral.vault_gcp_service_account_key.key
}

resource "echo" "gcp_key" {}
`, backend, credentials, staticAccount, serviceAccountEmail)
}

func testAccGCPServiceAccountKeyWithOptionsConfig(backend, roleset, credentials, project string) string {
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
  secret_type  = "service_account_key"
  project      = "%s"
  token_scopes = ["https://www.googleapis.com/auth/cloud-platform"]

  binding {
    resource = "//cloudresourcemanager.googleapis.com/projects/%s"
    roles    = ["roles/viewer"]
  }
}

ephemeral "vault_gcp_service_account_key" "key" {
  mount_id      = vault_gcp_secret_roleset.roleset.id
  backend       = vault_gcp_secret_backend.gcp.path
  roleset       = vault_gcp_secret_roleset.roleset.roleset
  key_algorithm = "KEY_ALG_RSA_2048"
  key_type      = "TYPE_GOOGLE_CREDENTIALS_FILE"
}

provider "echo" {
  data = ephemeral.vault_gcp_service_account_key.key
}

resource "echo" "gcp_key" {}
`, backend, credentials, roleset, project, project)
}

func testAccGCPServiceAccountKeyMissingFieldsConfig(backend, credentials string) string {
	return fmt.Sprintf(`
resource "vault_gcp_secret_backend" "gcp" {
  path        = "%s"
  credentials = <<CREDS
%s
CREDS
}

ephemeral "vault_gcp_service_account_key" "key" {
  backend = vault_gcp_secret_backend.gcp.path
}

provider "echo" {
  data = ephemeral.vault_gcp_service_account_key.key
}

resource "echo" "gcp_key" {}
`, backend, credentials)
}

func testAccGCPServiceAccountKeyBothFieldsConfig(backend, roleset, staticAccount, credentials, project, serviceAccountEmail string) string {
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
  secret_type  = "service_account_key"
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
  secret_type           = "service_account_key"
  service_account_email = "%s"
  token_scopes          = ["https://www.googleapis.com/auth/cloud-platform"]
}

ephemeral "vault_gcp_service_account_key" "key" {
  backend        = vault_gcp_secret_backend.gcp.path
  roleset        = vault_gcp_secret_roleset.roleset.roleset
  static_account = vault_gcp_secret_static_account.static.static_account
}

provider "echo" {
  data = ephemeral.vault_gcp_service_account_key.key
}

resource "echo" "gcp_key" {}
`, backend, credentials, roleset, project, project, staticAccount, serviceAccountEmail)
}

func testAccGCPServiceAccountKeyInvalidBackendConfig(roleset string) string {
	return fmt.Sprintf(`
ephemeral "vault_gcp_service_account_key" "key" {
  backend = "nonexistent-backend"
  roleset = "%s"
}

provider "echo" {
  data = ephemeral.vault_gcp_service_account_key.key
}

resource "echo" "gcp_key" {}
`, roleset)
}

// Made with Bob
