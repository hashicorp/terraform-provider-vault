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

// TestAccRadiusAuthLogin_basic confirms that a dynamic RADIUS authentication
// works correctly
//
// The test uses multiple steps similar to the CF auth pattern:
//  1. Create the RADIUS auth infrastructure (auth backend + config + user).
//  2. Add the ephemeral login resource - a successful apply proves Vault
//     accepts the RADIUS credentials.
//  3. Add a Vault provider alias authenticated with the issued client_token
//     and read auth/token/lookup-self, proving the token is usable.
func TestAccRadiusAuthLogin_basic(t *testing.T) {
	testAccRadiusAuthLogin(t, "")
}

// TestAccRadiusAuthLogin_namespace tests RADIUS auth login in a Vault Enterprise namespace
func TestAccRadiusAuthLogin_namespace(t *testing.T) {
	testAccRadiusAuthLogin(t, acctest.RandomWithPrefix("ns"))
}

func testAccRadiusAuthLogin(t *testing.T, namespace string) {
	t.Helper()

	testutil.SkipTestEnvUnset(t,
		"VAULT_ACC_TEST_RADIUS_HOST",
		"VAULT_ACC_TEST_RADIUS_SECRET",
		"VAULT_ACC_TEST_RADIUS_USERNAME",
		"VAULT_ACC_TEST_RADIUS_PASSWORD",
	)

	mount := acctest.RandomWithPrefix("tf-test-radius")
	username := os.Getenv("VAULT_ACC_TEST_RADIUS_USERNAME")
	password := os.Getenv("VAULT_ACC_TEST_RADIUS_PASSWORD")
	nonEmptyRegex := testAccRadiusNonEmptyRegex(t)

	echoResourceName := "echo.test_radius"
	tokenSelfResourceName := "data.vault_generic_secret.token_self"
	infraConfig := testAccRadiusAuthInfraConfig_basic(mount, username)
	loginConfig := testAccRadiusAuthLoginConfig_basic(mount, username, password)
	tokenUseConfig := testAccRadiusAuthLoginWithTokenUseConfig_basic(mount, username, password)
	preCheck := func() { acctestutil.TestAccPreCheck(t) }

	if namespace != "" {
		echoResourceName = "echo.test_radius_ns"
		tokenSelfResourceName = "data.vault_generic_secret.token_self_ns"
		infraConfig = testAccRadiusAuthInfraConfig_namespace(namespace, mount, username)
		loginConfig = testAccRadiusAuthLoginConfig_namespace(namespace, mount, username, password)
		tokenUseConfig = testAccRadiusAuthLoginWithTokenUseConfig_namespace(namespace, mount, username, password)
		preCheck = func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		}
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 preCheck,
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: testAccRadiusProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config:           infraConfig,
				ConfigPlanChecks: testAccRadiusEmptyPlanChecks(),
			},
			{
				Config:            loginConfig,
				ConfigStateChecks: testAccRadiusLoginStateChecks(echoResourceName, nonEmptyRegex),
			},
			{
				Config: tokenUseConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(tokenSelfResourceName, "data.%"),
				),
				ConfigPlanChecks: testAccRadiusEmptyPlanChecks(),
			},
		},
	})
}

// testAccRadiusAuthBackendMountOnly creates only the auth backend mount
func testAccRadiusAuthBackendMountOnly(mount string) string {
	return testAccRadiusAuthLoginBackendMountConfig("", mount)
}

func testAccRadiusAuthLoginBackendMountConfig(namespace, mount string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
%s  type = "radius"
  path = %q
}
`, testAccRadiusNamespaceLine(namespace), mount)
}

// testAccRadiusAuthBackendInfra creates the complete RADIUS infrastructure
// (mount + backend config + policy + user) without ephemeral login
func testAccRadiusAuthBackendInfra(mount, username string) string {
	host, secret := testAccRadiusAuthServerConfig()

	return fmt.Sprintf(`
%s
%s
`,
		testAccRadiusAuthBackendMountOnly(mount),
		testAccRadiusAuthInfraResources("", host, secret, username),
	)
}

// testAccRadiusAuthInfraConfig_basic creates the RADIUS infrastructure without ephemeral login
func testAccRadiusAuthInfraConfig_basic(mount, username string) string {
	return testAccRadiusAuthBackendInfra(mount, username)
}

func testAccRadiusAuthEphemeralLoginConfig(namespace, password string) string {
	return fmt.Sprintf(`
ephemeral "vault_radius_auth_login" "test" {
%s  mount_id = vault_auth_backend.test.id
  mount    = vault_auth_backend.test.path
  username = vault_radius_auth_backend_user.test.username
  password = %q
}
`, testAccRadiusNamespaceLine(namespace), password)
}

// testAccRadiusAuthEphemeralLogin returns the ephemeral login configuration block
func testAccRadiusAuthEphemeralLogin(password string) string {
	return testAccRadiusAuthEphemeralLoginConfig("", password)
}

func testAccRadiusAuthInfraConfig(namespace, mount, username string) string {
	if namespace == "" {
		return testAccRadiusAuthBackendInfra(mount, username)
	}

	return testAccRadiusAuthBackendInfra_namespace(namespace, mount, username)
}

func testAccRadiusAuthLoginConfig(namespace, mount, username, password string) string {
	echoResourceName := "test_radius"
	loginConfig := testAccRadiusAuthEphemeralLogin(password)
	if namespace != "" {
		echoResourceName = "test_radius_ns"
		loginConfig = testAccRadiusAuthEphemeralLogin_namespace(namespace, password)
	}

	return fmt.Sprintf(`
%s
%s

provider "echo" {
  data = ephemeral.vault_radius_auth_login.test
}

resource "echo" %q {}
`,
		testAccRadiusAuthInfraConfig(namespace, mount, username),
		loginConfig,
		echoResourceName,
	)
}

func testAccRadiusAuthLoginWithTokenUseConfig(namespace, mount, username, password string) string {
	vaultAddr := testAccRadiusVaultAddr()
	providerAlias := "radius_auth"
	providerNamespace := ""
	tokenSelfDataName := "token_self"
	loginConfig := testAccRadiusAuthEphemeralLogin(password)
	if namespace != "" {
		providerAlias = "radius_auth_ns"
		providerNamespace = "  namespace = vault_namespace.test.path\n"
		tokenSelfDataName = "token_self_ns"
		loginConfig = testAccRadiusAuthEphemeralLogin_namespace(namespace, password)
	}

	return fmt.Sprintf(`
%s
%s

# A second Vault provider instance authenticated with the RADIUS-issued token.
provider "vault" {
  alias   = %q
  address = %q
%s  token   = ephemeral.vault_radius_auth_login.test.client_token
}

# Token self-lookup via the RADIUS-authenticated provider alias.
data "vault_generic_secret" %q {
  provider = vault.%s
  path     = "auth/token/lookup-self"
}
`,
		testAccRadiusAuthInfraConfig(namespace, mount, username),
		loginConfig,
		providerAlias,
		vaultAddr,
		providerNamespace,
		tokenSelfDataName,
		providerAlias,
	)
}

// testAccRadiusAuthLoginConfig_basic adds ephemeral login to existing infrastructure
func testAccRadiusAuthLoginConfig_basic(mount, username, password string) string {
	return testAccRadiusAuthLoginConfig("", mount, username, password)
}

// testAccRadiusAuthLoginWithTokenUseConfig_basic uses the ephemeral token with a provider alias
func testAccRadiusAuthLoginWithTokenUseConfig_basic(mount, username, password string) string {
	return testAccRadiusAuthLoginWithTokenUseConfig("", mount, username, password)
}

// testAccRadiusAuthBackendInfra_namespace creates RADIUS infrastructure in a namespace
func testAccRadiusAuthBackendInfra_namespace(namespace, mount, username string) string {
	host, secret := testAccRadiusAuthServerConfig()

	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = %q
}

%s
%s
`,
		namespace,
		testAccRadiusAuthLoginBackendMountConfig("vault_namespace.test.path", mount),
		testAccRadiusAuthInfraResources("vault_namespace.test.path", host, secret, username),
	)
}

// testAccRadiusAuthEphemeralLogin_namespace returns ephemeral login config in a namespace
func testAccRadiusAuthEphemeralLogin_namespace(namespace, password string) string {
	return testAccRadiusAuthEphemeralLoginConfig("vault_namespace.test.path", password)
}

// testAccRadiusAuthInfraConfig_namespace creates RADIUS infrastructure in a namespace
func testAccRadiusAuthInfraConfig_namespace(namespace, mount, username string) string {
	return testAccRadiusAuthBackendInfra_namespace(namespace, mount, username)
}

// testAccRadiusAuthLoginConfig_namespace adds ephemeral login in a namespace
func testAccRadiusAuthLoginConfig_namespace(namespace, mount, username, password string) string {
	return testAccRadiusAuthLoginConfig(namespace, mount, username, password)
}

// testAccRadiusAuthLoginWithTokenUseConfig_namespace uses the namespaced token with provider alias
func testAccRadiusAuthLoginWithTokenUseConfig_namespace(namespace, mount, username, password string) string {
	return testAccRadiusAuthLoginWithTokenUseConfig(namespace, mount, username, password)
}

func testAccRadiusAuthServerConfig() (string, string) {
	return os.Getenv("VAULT_ACC_TEST_RADIUS_HOST"), os.Getenv("VAULT_ACC_TEST_RADIUS_SECRET")
}

func testAccRadiusVaultAddr() string {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		return testAccRadiusDefaultVaultAddr
	}

	return vaultAddr
}

func testAccRadiusNonEmptyRegex(t *testing.T) *regexp.Regexp {
	t.Helper()

	nonEmptyRegex, err := regexp.Compile("^.+$")
	if err != nil {
		t.Fatal(err)
	}

	return nonEmptyRegex
}

func testAccRadiusProtoV6ProviderFactories() map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"echo": echoprovider.NewProviderServer(),
	}
}

func testAccRadiusEmptyPlanChecks() resource.ConfigPlanChecks {
	return resource.ConfigPlanChecks{
		PostApplyPostRefresh: []plancheck.PlanCheck{
			plancheck.ExpectEmptyPlan(),
		},
	}
}

func testAccRadiusLoginStateChecks(echoResourceName string, nonEmptyRegex *regexp.Regexp) []statecheck.StateCheck {
	return []statecheck.StateCheck{
		statecheck.ExpectKnownValue(
			echoResourceName,
			tfjsonpath.New("data").AtMapKey(consts.FieldClientToken),
			knownvalue.StringRegexp(nonEmptyRegex),
		),
		statecheck.ExpectKnownValue(
			echoResourceName,
			tfjsonpath.New("data").AtMapKey(consts.FieldAccessor),
			knownvalue.StringRegexp(nonEmptyRegex),
		),
		statecheck.ExpectKnownValue(
			echoResourceName,
			tfjsonpath.New("data").AtMapKey(consts.FieldLeaseDuration),
			knownvalue.NotNull(),
		),
	}
}

func testAccRadiusAuthInfraResources(namespace, host, secret, username string) string {
	namespaceLine := testAccRadiusNamespaceLine(namespace)

	return fmt.Sprintf(`
resource "vault_radius_auth_backend" "test" {
%smount        = vault_auth_backend.test.path
  host         = %q
  secret_wo    = %q
  dial_timeout = 30
  read_timeout = 30
}

resource "vault_policy" "token_creator" {
%sname   = "token-creator"
  policy = <<EOT
path "auth/token/create" {
  capabilities = ["create", "update"]
}
EOT
}

resource "vault_radius_auth_backend_user" "test" {
%smount    = vault_auth_backend.test.path
  username = %q
  policies = ["default", "token-creator"]
}
`, namespaceLine, host, secret, namespaceLine, namespaceLine, username)
}

func testAccRadiusNamespaceLine(namespace string) string {
	if namespace == "" {
		return ""
	}

	return fmt.Sprintf("  namespace = %s\n", namespace)
}
