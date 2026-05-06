// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package radius_test

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const testAccRadiusDefaultVaultAddr = "http://localhost:8200"

type radiusLoginParams struct {
	host     string
	secret   string
	username string
	password string
}

// TestAccRadiusAuthLogin_basic confirms that a dynamic RADIUS authentication
// works correctly.
//
// The test uses multiple steps similar to the CF auth pattern:
//  1. Create the RADIUS auth infrastructure (auth backend + config + user).
//  2. Add the ephemeral login resource - a successful apply proves Vault
//     accepts the RADIUS credentials.
//  3. Add a Vault provider alias authenticated with the issued client_token
//     and read auth/token/lookup-self, proving the token is usable.
func TestAccRadiusAuthLogin_basic(t *testing.T) {
	p := radiusLoginParamsFromEnv(t)
	mount := acctest.RandomWithPrefix("tf-test-radius")
	nonEmptyRegex := regexp.MustCompile("^.+$")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			// Step 1: Apply only the RADIUS infrastructure. Ephemeral resources are
			// opened during Terraform plan, so the auth mount must already exist
			// before the login resource is introduced in step 2.
			{
				Config: testAccRadiusAuthInfraConfig_basic(mount, p),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 2: Add the ephemeral login resource on top of the existing
			// infrastructure. A successful apply proves Vault accepted the
			// RADIUS credentials.
			{
				Config: testAccRadiusAuthLoginConfig_basic(mount, p),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"echo.test_radius",
						tfjsonpath.New("data").AtMapKey(consts.FieldClientToken),
						knownvalue.StringRegexp(nonEmptyRegex),
					),
					statecheck.ExpectKnownValue(
						"echo.test_radius",
						tfjsonpath.New("data").AtMapKey(consts.FieldAccessor),
						knownvalue.StringRegexp(nonEmptyRegex),
					),
					statecheck.ExpectKnownValue(
						"echo.test_radius",
						tfjsonpath.New("data").AtMapKey(consts.FieldLeaseDuration),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						"echo.test_radius",
						tfjsonpath.New("data").AtMapKey(consts.FieldRenewable),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						"echo.test_radius",
						tfjsonpath.New("data").AtMapKey(consts.FieldPolicies),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						"echo.test_radius",
						tfjsonpath.New("data").AtMapKey(consts.FieldTokenPolicies),
						knownvalue.NotNull(),
					),
				},
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 3: Forward client_token to a provider alias and call
			// auth/token/lookup-self. Non-empty data proves the token is
			// a real, working Vault credential.
			{
				Config: testAccRadiusAuthLoginWithTokenUseConfig_basic(mount, p),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.vault_generic_secret.token_self", "data.%"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
		},
	})
}

// TestAccRadiusAuthLogin_namespace tests RADIUS auth login in a Vault
// Enterprise namespace.
func TestAccRadiusAuthLogin_namespace(t *testing.T) {
	p := radiusLoginParamsFromEnv(t)
	namespace := acctest.RandomWithPrefix("ns")
	mount := acctest.RandomWithPrefix("tf-test-radius")
	nonEmptyRegex := regexp.MustCompile("^.+$")

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
				Config: testAccRadiusAuthLoginConfig_namespace(namespace, mount, p),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"echo.test_radius_ns",
						tfjsonpath.New("data").AtMapKey(consts.FieldClientToken),
						knownvalue.StringRegexp(nonEmptyRegex),
					),
					statecheck.ExpectKnownValue(
						"echo.test_radius_ns",
						tfjsonpath.New("data").AtMapKey(consts.FieldAccessor),
						knownvalue.StringRegexp(nonEmptyRegex),
					),
					statecheck.ExpectKnownValue(
						"echo.test_radius_ns",
						tfjsonpath.New("data").AtMapKey(consts.FieldLeaseDuration),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						"echo.test_radius_ns",
						tfjsonpath.New("data").AtMapKey(consts.FieldRenewable),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						"echo.test_radius_ns",
						tfjsonpath.New("data").AtMapKey(consts.FieldPolicies),
						knownvalue.NotNull(),
					),
					statecheck.ExpectKnownValue(
						"echo.test_radius_ns",
						tfjsonpath.New("data").AtMapKey(consts.FieldTokenPolicies),
						knownvalue.NotNull(),
					),
				},
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
		},
	})
}

func testAccRadiusAuthBackendConfigMountOnly(mount string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
  type = "radius"
  path = %q
}
`, mount)
}

func testAccRadiusAuthInfraConfig_basic(mount string, p radiusLoginParams) string {
	return fmt.Sprintf(`
%s

%s
`,
		testAccRadiusAuthBackendConfigMountOnly(mount),
		testAccRadiusAuthInfraResources(p),
	)
}

func testAccRadiusAuthInfraResources(p radiusLoginParams) string {
	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
  mount        = vault_auth_backend.test.path
  host         = %q
  secret_wo    = %q
  secret_wo_version = 1
  dial_timeout = 30
  read_timeout = 30
}

resource "vault_policy" "token_creator" {
  name   = "token-creator"
  policy = <<EOT
path "auth/token/create" {
  capabilities = ["create", "update"]
}
EOT
}

resource "vault_radius_auth_backend_user" "test" {
  mount    = vault_auth_backend.test.path
  username = %q
  policies = ["default", "token-creator"]
}
`, p.host, p.secret, p.username)
}

func testAccRadiusAuthLoginConfig_basic(mount string, p radiusLoginParams) string {
	return fmt.Sprintf(`
%s

ephemeral "vault_radius_auth_login" "test" {
  mount_id = vault_auth_backend.test.id
  mount    = vault_auth_backend.test.path
  username = vault_radius_auth_backend_user.test.username
  password = %q
}

provider "echo" {
  data = ephemeral.vault_radius_auth_login.test
}

resource "echo" "test_radius" {}
`,
		testAccRadiusAuthInfraConfig_basic(mount, p),
		p.password,
	)
}

func testAccRadiusAuthLoginWithTokenUseConfig_basic(mount string, p radiusLoginParams) string {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = testAccRadiusDefaultVaultAddr
	}

	return fmt.Sprintf(`
%s

ephemeral "vault_radius_auth_login" "test" {
  mount_id = vault_auth_backend.test.id
  mount    = vault_auth_backend.test.path
  username = vault_radius_auth_backend_user.test.username
  password = %q
}

# A second Vault provider instance authenticated with the RADIUS-issued token.
provider "vault" {
  alias   = "radius_auth"
  address = %q
  token   = ephemeral.vault_radius_auth_login.test.client_token
}

# Token self-lookup via the RADIUS-authenticated provider alias.
# Any valid Vault token may call this via the built-in default policy.
data "vault_generic_secret" "token_self" {
  provider = vault.radius_auth
  path     = "auth/token/lookup-self"
}
`,
		testAccRadiusAuthInfraConfig_basic(mount, p),
		p.password,
		vaultAddr,
	)
}

func testAccRadiusAuthLoginConfig_namespace(namespace, mount string, p radiusLoginParams) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
	path = %q
}

resource "vault_auth_backend" "test" {
	namespace = vault_namespace.test.path
	type      = "radius"
	path      = %q
}

resource "vault_radius_auth_backend" "test" {
	namespace    = vault_namespace.test.path
	mount        = vault_auth_backend.test.path
	host         = %q
	secret_wo    = %q
    secret_wo_version = 1
	dial_timeout = 30
	read_timeout = 30
}

resource "vault_policy" "token_creator" {
	namespace = vault_namespace.test.path
	name      = "token-creator"
	policy = <<EOT
path "auth/token/create" {
	capabilities = ["create", "update"]
}
EOT
}

resource "vault_radius_auth_backend_user" "test" {
	namespace = vault_namespace.test.path
	mount     = vault_auth_backend.test.path
	username  = %q
	policies  = ["default", "token-creator"]
}

ephemeral "vault_radius_auth_login" "test" {
  namespace = vault_namespace.test.path
  mount_id  = vault_auth_backend.test.id
  mount     = vault_auth_backend.test.path
  username  = vault_radius_auth_backend_user.test.username
  password  = %q
}

provider "echo" {
  data = ephemeral.vault_radius_auth_login.test
}

resource "echo" "test_radius_ns" {}
`, namespace, mount, p.host, p.secret, p.username, p.password)
}

func radiusLoginParamsFromEnv(t *testing.T) radiusLoginParams {
	t.Helper()

	testutil.SkipTestEnvUnset(t,
		"VAULT_ACC_TEST_RADIUS_HOST",
		"VAULT_ACC_TEST_RADIUS_SECRET",
		"VAULT_ACC_TEST_RADIUS_USERNAME",
		"VAULT_ACC_TEST_RADIUS_PASSWORD",
	)

	return radiusLoginParams{
		host:     os.Getenv("VAULT_ACC_TEST_RADIUS_HOST"),
		secret:   os.Getenv("VAULT_ACC_TEST_RADIUS_SECRET"),
		username: os.Getenv("VAULT_ACC_TEST_RADIUS_USERNAME"),
		password: os.Getenv("VAULT_ACC_TEST_RADIUS_PASSWORD"),
	}
}
