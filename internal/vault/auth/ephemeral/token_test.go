// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralauth_test

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
)

// TestAccToken_basic confirms that a basic service token can be created
//
// Uses the Echo Provider to test values set in ephemeral resources
// see documentation here for more details:
// https://developer.hashicorp.com/terraform/plugin/testing/acceptance-tests/ephemeral-resources#using-echo-provider-in-acceptance-tests
func TestAccToken_basic(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	// Service tokens start with "hvs."
	expectedTokenRegex, err := regexp.Compile("^hvs\\.")
	if err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		PreCheck: func() { acctestutil.TestAccPreCheck(t) },
		// Include the provider we want to test (v5)
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		// Include `echo` as a v6 provider from `terraform-plugin-testing`
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testTokenConfig_basic(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldClientToken), knownvalue.StringRegexp(expectedTokenRegex)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldAccessor), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldLeaseDuration), knownvalue.NotNull()),
				},
			},
		},
	})
}

// TestAccToken_batch confirms that a batch token can be created
func TestAccToken_batch(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	// Batch tokens start with "hvb."
	expectedTokenRegex, err := regexp.Compile("^hvb\\.")
	if err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testTokenConfig_batch(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldClientToken), knownvalue.StringRegexp(expectedTokenRegex)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldType), knownvalue.StringExact("batch")),
				},
			},
		},
	})
}

// TestAccToken_withPolicies confirms that a token with policies can be created
func TestAccToken_withPolicies(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	policyName := acctest.RandomWithPrefix("test-policy")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testTokenConfig_withPolicies(policyName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldClientToken), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldTokenPolicies), knownvalue.NotNull()),
				},
			},
		},
	})
}

// TestAccToken_orphan confirms that an orphan token can be created
func TestAccToken_orphan(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testTokenConfig_orphan(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldClientToken), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldOrphan), knownvalue.Bool(true)),
				},
			},
		},
	})
}

// TestAccToken_withRole confirms that a token can be created with a role
func TestAccToken_withRole(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	roleName := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			// Step 1: Create the role first
			{
				Config: testTokenConfig_roleOnly(roleName),
			},
			// Step 2: Use the role with ephemeral token
			{
				Config: testTokenConfig_withRole(roleName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldClientToken), knownvalue.NotNull()),
				},
			},
		},
	})
}

// TestAccToken_wrapped confirms that a wrapped token can be created
func TestAccToken_wrapped(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testTokenConfig_wrapped(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldWrappedToken), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldWrappingAccessor), knownvalue.NotNull()),
				},
			},
		},
	})
}

// TestAccToken_withEntityAlias confirms that a token can be created with entity alias
func TestAccToken_withEntityAlias(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	roleName := acctest.RandomWithPrefix("test-role")
	entityName := acctest.RandomWithPrefix("test-entity")
	aliasName := acctest.RandomWithPrefix("test-alias")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			// Step 1: Create all dependencies first
			{
				Config: testTokenConfig_entityAliasSetup(roleName, entityName, aliasName),
			},
			// Step 2: Use the role and entity alias with ephemeral token
			{
				Config: testTokenConfig_withEntityAlias(roleName, entityName, aliasName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldClientToken), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldEntityID), knownvalue.NotNull()),
				},
			},
		},
	})
}

// TestAccToken_batchTokenAutoDetectionViaRole confirms batch token auto-detection via role
func TestAccToken_batchTokenAutoDetectionViaRole(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	roleName := acctest.RandomWithPrefix("batch-role")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			// Step 1: Create the batch role first
			{
				Config: testTokenConfig_batchRoleOnly(roleName),
			},
			// Step 2: Use the batch role with ephemeral token
			{
				Config: testTokenConfig_batchTokenAutoDetectionViaRole(roleName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldClientToken), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldType), knownvalue.StringExact("batch")),
				},
			},
		},
	})
}

// TestAccToken_full confirms that a token with all optional fields can be created
func TestAccToken_full(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	policyName := acctest.RandomWithPrefix("test-policy")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testTokenConfig_full(policyName),
				ConfigStateChecks: []statecheck.StateCheck{
					// Basic token fields
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldClientToken), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldAccessor), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldLeaseDuration), knownvalue.NotNull()),

					// Orphan status (no_parent = true)
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldOrphan), knownvalue.Bool(true)),

					// Display name validation
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldDisplayName), knownvalue.StringExact("test")),

					// Token type validation
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldType), knownvalue.StringExact("service")),

					// Token policies should exist (validates policies were set)
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey(consts.FieldTokenPolicies), knownvalue.NotNull()),
				},
			},
		},
	})
}

// Config functions

func testTokenConfig_basic() string {
	return `
ephemeral "vault_token" "test" {
  policies = ["default"]
  ttl      = "1h"
}

provider "echo" {
  data = ephemeral.vault_token.test
}

resource "echo" "test" {}
`
}

func testTokenConfig_batch() string {
	return `
ephemeral "vault_token" "test" {
  type     = "batch"
  policies = ["default"]
  ttl      = "1h"
}

provider "echo" {
  data = ephemeral.vault_token.test
}

resource "echo" "test" {}
`
}

func testTokenConfig_withPolicies(policyName string) string {
	return fmt.Sprintf(`
resource "vault_policy" "test" {
  name = "%s"
  policy = <<EOT
path "secret/*" {
  capabilities = ["read"]
}
EOT
}

ephemeral "vault_token" "test" {
  policies = [vault_policy.test.name]
  ttl      = "1h"
}

provider "echo" {
  data = ephemeral.vault_token.test
}

resource "echo" "test" {}
`, policyName)
}

func testTokenConfig_withMetadata() string {
	return `
ephemeral "vault_token" "test" {
  policies = ["default"]
  ttl      = "1h"
  metadata = {
    user = "test-user"
    env  = "test"
  }
}

provider "echo" {
  data = ephemeral.vault_token.test
}

resource "echo" "test" {}
`
}

func testTokenConfig_orphan() string {
	return `
ephemeral "vault_token" "test" {
  policies  = ["default"]
  ttl       = "1h"
  no_parent = true
}

provider "echo" {
  data = ephemeral.vault_token.test
}

resource "echo" "test" {}
`
}

func testTokenConfig_withNumUses() string {
	return `
ephemeral "vault_token" "test" {
  policies = ["default"]
  ttl      = "1h"
  num_uses = 5
}

provider "echo" {
  data = ephemeral.vault_token.test
}

resource "echo" "test" {}
`
}

func testTokenConfig_roleOnly(roleName string) string {
	return fmt.Sprintf(`
resource "vault_token_auth_backend_role" "test" {
  role_name        = "%s"
  allowed_policies = ["default"]
  orphan           = true
}
`, roleName)
}

func testTokenConfig_withRole(roleName string) string {
	return fmt.Sprintf(`
resource "vault_token_auth_backend_role" "test" {
  role_name        = "%s"
  allowed_policies = ["default"]
  orphan           = true
}

ephemeral "vault_token" "test" {
  role_name = vault_token_auth_backend_role.test.role_name
}

provider "echo" {
  data = ephemeral.vault_token.test
}

resource "echo" "test" {}
`, roleName)
}

func testTokenConfig_periodic() string {
	return `
ephemeral "vault_token" "test" {
  policies = ["default"]
  period   = "24h"
}

provider "echo" {
  data = ephemeral.vault_token.test
}

resource "echo" "test" {}
`
}

func testTokenConfig_wrapped() string {
	return `
ephemeral "vault_token" "test" {
  policies     = ["default"]
  ttl          = "1h"
  wrapping_ttl = "5m"
}

provider "echo" {
  data = ephemeral.vault_token.test
}

resource "echo" "test" {}
`
}

func testTokenConfig_entityAliasSetup(roleName, entityName, aliasName string) string {
	return fmt.Sprintf(`
resource "vault_policy" "test" {
  name = "test-policy"
  policy = <<EOT
path "secret/*" {
  capabilities = ["read"]
}
EOT
}

resource "vault_auth_backend" "test" {
  type = "userpass"
  path = "userpass-test"
}

resource "vault_identity_entity" "test" {
  name = "%s"
}

resource "vault_identity_entity_alias" "test" {
  name           = "%s"
  mount_accessor = vault_auth_backend.test.accessor
  canonical_id   = vault_identity_entity.test.id
}

resource "vault_token_auth_backend_role" "test" {
  role_name              = "%s"
  allowed_policies       = [vault_policy.test.name]
  allowed_entity_aliases = [vault_identity_entity_alias.test.name]
}
`, entityName, aliasName, roleName)
}

func testTokenConfig_withEntityAlias(roleName, entityName, aliasName string) string {
	return fmt.Sprintf(`
resource "vault_policy" "test" {
  name = "test-policy"
  policy = <<EOT
path "secret/*" {
  capabilities = ["read"]
}
EOT
}

resource "vault_auth_backend" "test" {
  type = "userpass"
  path = "userpass-test"
}

resource "vault_identity_entity" "test" {
  name = "%s"
}

resource "vault_identity_entity_alias" "test" {
  name           = "%s"
  mount_accessor = vault_auth_backend.test.accessor
  canonical_id   = vault_identity_entity.test.id
}

resource "vault_token_auth_backend_role" "test" {
  role_name              = "%s"
  allowed_policies       = [vault_policy.test.name]
  allowed_entity_aliases = [vault_identity_entity_alias.test.name]
}

ephemeral "vault_token" "test" {
  role_name    = vault_token_auth_backend_role.test.role_name
  entity_alias = vault_identity_entity_alias.test.name
}

provider "echo" {
  data = ephemeral.vault_token.test
}

resource "echo" "test" {}
`, entityName, aliasName, roleName)
}

func testTokenConfig_batchRoleOnly(roleName string) string {
	return fmt.Sprintf(`
resource "vault_policy" "test" {
  name = "test-policy"
  policy = <<EOT
path "secret/*" {
  capabilities = ["read"]
}
EOT
}

resource "vault_token_auth_backend_role" "batch" {
  role_name        = "%s"
  token_type       = "batch"
  orphan           = true
  renewable        = false
  allowed_policies = [vault_policy.test.name]
}
`, roleName)
}

func testTokenConfig_batchTokenAutoDetectionViaRole(roleName string) string {
	return fmt.Sprintf(`
resource "vault_policy" "test" {
  name = "test-policy"
  policy = <<EOT
path "secret/*" {
  capabilities = ["read"]
}
EOT
}

resource "vault_token_auth_backend_role" "batch" {
  role_name        = "%s"
  token_type       = "batch"
  orphan           = true
  renewable        = false
  allowed_policies = [vault_policy.test.name]
}

ephemeral "vault_token" "test" {
  role_name = vault_token_auth_backend_role.batch.role_name
}

provider "echo" {
  data = ephemeral.vault_token.test
}

resource "echo" "test" {}
`, roleName)
}

func testTokenConfig_full(policyName string) string {
	return fmt.Sprintf(`
resource "vault_policy" "test" {
  name = "%s"
  policy = <<EOT
path "secret/*" {
  capabilities = ["read"]
}
EOT
}

ephemeral "vault_token" "test" {
  policies          = [vault_policy.test.name]
  no_parent         = true
  no_default_policy = true
  renewable         = true
  ttl               = "60s"
  explicit_max_ttl  = "1h"
  display_name      = "test"
  num_uses          = 1
  period            = "0"
  metadata = {
    fizz = "buzz"
  }
}

provider "echo" {
  data = ephemeral.vault_token.test
}

resource "echo" "test" {}
`, policyName)
}

func testTokenConfig_withCustomID(customID string) string {
	return fmt.Sprintf(`
ephemeral "vault_token" "test" {
  id       = "%s"
  policies = ["default"]
  ttl      = "1h"
}

provider "echo" {
  data = ephemeral.vault_token.test
}

resource "echo" "test" {}
`, customID)
}

// Made with Bob
