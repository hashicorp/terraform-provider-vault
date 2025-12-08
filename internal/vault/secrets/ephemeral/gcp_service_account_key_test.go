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

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const (
	// Common GCP service account email pattern (without anchors)
	gcpServiceAccountEmailPattern = `.+@.+\.iam\.gserviceaccount\.com`
)

var (
	// Common regexp patterns used across GCP ephemeral resource tests
	regexpGCPServiceAccountEmail = regexp.MustCompile(fmt.Sprintf(`^%s$`, gcpServiceAccountEmailPattern))
	regexpGCPServiceAccountType  = regexp.MustCompile(`(?s).*"type":\s*"service_account".*`)
	regexpGCPPrivateKey          = regexp.MustCompile(`(?s).*"private_key":\s*"-----BEGIN PRIVATE KEY-----.*`)
	regexpGCPClientEmail         = regexp.MustCompile(fmt.Sprintf(`(?s).*"client_email":\s*"%s".*`, gcpServiceAccountEmailPattern))
)

// TestAccGCPServiceAccountKey_basic tests generating service account keys
// from different GCP credential types (roleset and static account)
// and demonstrates realistic resource mutation patterns
func TestAccGCPServiceAccountKey_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-gcp")
	roleset := acctest.RandomWithPrefix("tf-roleset")
	staticAccount := acctest.RandomWithPrefix("tf-static")

	creds, project := testutil.GetTestGCPCreds(t)

	// Extract service account email from credentials
	var credsMap map[string]interface{}
	if err := json.Unmarshal([]byte(creds), &credsMap); err != nil {
		t.Fatalf("Failed to parse GCP credentials: %v", err)
	}
	serviceAccountEmail, ok := credsMap["client_email"].(string)
	if !ok || serviceAccountEmail == "" {
		t.Fatal("GCP credentials must contain client_email field")
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				// Step 1: Create and use roleset
				Config: testAccGCPServiceAccountKeyRolesetConfig(backend, roleset, creds, project),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("private_key_data"), knownvalue.StringRegexp(regexpGCPServiceAccountType)),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("private_key_data"), knownvalue.StringRegexp(regexpGCPPrivateKey)),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("private_key_data"), knownvalue.StringRegexp(regexpGCPClientEmail)),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("private_key_type"), knownvalue.StringExact("TYPE_GOOGLE_CREDENTIALS_FILE")),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("service_account_email"), knownvalue.StringRegexp(regexpGCPServiceAccountEmail)),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey(consts.FieldLeaseID), knownvalue.StringRegexp(regexpNonEmpty)),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey(consts.FieldLeaseDuration), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("lease_start_time"), knownvalue.StringRegexp(regexpNonEmpty)),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey(consts.FieldLeaseRenewable), knownvalue.NotNull()),
				},
			},
			{
				// Step 2: Mutate to use static_account instead of roleset
				Config: testAccGCPServiceAccountKeyStaticAccountConfig(backend, staticAccount, creds, serviceAccountEmail),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("private_key_data"), knownvalue.StringRegexp(regexpGCPServiceAccountType)),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("private_key_data"), knownvalue.StringRegexp(regexpGCPPrivateKey)),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("service_account_email"), knownvalue.StringRegexp(regexpGCPServiceAccountEmail)),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey(consts.FieldLeaseID), knownvalue.StringRegexp(regexpNonEmpty)),
				},
			},
			{
				// Step 3: Switch back to roleset to verify bidirectional mutation
				Config: testAccGCPServiceAccountKeyRolesetConfig(backend, roleset, creds, project),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("private_key_data"), knownvalue.StringRegexp(regexpGCPServiceAccountType)),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("private_key_data"), knownvalue.StringRegexp(regexpGCPPrivateKey)),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("private_key_type"), knownvalue.StringExact("TYPE_GOOGLE_CREDENTIALS_FILE")),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("service_account_email"), knownvalue.StringRegexp(regexpGCPServiceAccountEmail)),
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

// TestAccGCPServiceAccountKey_validation tests various validation and error scenarios
// including missing fields, conflicting fields, and invalid configurations
func TestAccGCPServiceAccountKey_validation(t *testing.T) {
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
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				// Step 1: Missing both roleset and static_account should error
				Config:      testAccGCPServiceAccountKeyMissingFieldsConfig(backend, creds),
				ExpectError: regexp.MustCompile("Either 'roleset' or 'static_account' must be provided"),
			},
			{
				// Step 2: Providing both roleset and static_account should error
				Config:      testAccGCPServiceAccountKeyBothFieldsConfig(backend, roleset, staticAccount, creds, project, serviceAccountEmail),
				ExpectError: regexp.MustCompile("Only one of 'roleset' or 'static_account' can be provided"),
			},
			{
				// Step 3: Invalid backend path should error
				Config:      testAccGCPServiceAccountKeyInvalidBackendConfig(roleset),
				ExpectError: regexp.MustCompile("Error generating GCP service account key"),
			},
		},
	})
}

// TestAccGCPServiceAccountKey_optionalFeatures tests optional configuration features
// including custom key_algorithm and key_type settings
func TestAccGCPServiceAccountKey_optionalFeatures(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-gcp")
	roleset := acctest.RandomWithPrefix("tf-roleset")

	creds, project := testutil.GetTestGCPCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				// Test with custom key_algorithm and key_type options
				Config: testAccGCPServiceAccountKeyWithOptionsConfig(backend, roleset, creds, project),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("private_key_data"), knownvalue.StringRegexp(regexpGCPServiceAccountType)),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("private_key_data"), knownvalue.StringRegexp(regexpGCPPrivateKey)),
					statecheck.ExpectKnownValue("echo.gcp_key", tfjsonpath.New("data").AtMapKey("private_key_type"), knownvalue.StringExact("TYPE_GOOGLE_CREDENTIALS_FILE")),
				},
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
  mount    = vault_gcp_secret_backend.gcp.path
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
  mount          = vault_gcp_secret_backend.gcp.path
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
  mount         = vault_gcp_secret_backend.gcp.path
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
  mount = vault_gcp_secret_backend.gcp.path
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
  mount          = vault_gcp_secret_backend.gcp.path
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
  mount   = "nonexistent-backend"
  roleset = "%s"
}

provider "echo" {
  data = ephemeral.vault_gcp_service_account_key.key
}

resource "echo" "gcp_key" {}
`, roleset)
}
