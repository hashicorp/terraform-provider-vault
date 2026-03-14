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
	// Skip test unless RADIUS server is configured
	testutil.SkipTestEnvUnset(t,
		"VAULT_ACC_TEST_RADIUS_HOST",
		"VAULT_ACC_TEST_RADIUS_SECRET",
		"VAULT_ACC_TEST_RADIUS_USERNAME",
		"VAULT_ACC_TEST_RADIUS_PASSWORD",
	)

	mount := acctest.RandomWithPrefix("tf-test-radius")
	username := os.Getenv("VAULT_ACC_TEST_RADIUS_USERNAME")
	password := os.Getenv("VAULT_ACC_TEST_RADIUS_PASSWORD")

	// Regex to ensure token and accessor are set
	nonEmptyRegex, err := regexp.Compile("^.+$")
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
			// Step 1: Apply only the RADIUS infrastructure. Ephemeral resources are
			// opened during Terraform plan, so the RADIUS mount must already exist
			// before the login resource is introduced in step 2.
			{
				Config: testAccRadiusAuthInfraConfig_basic(mount, username),
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
				Config: testAccRadiusAuthLoginConfig_basic(mount, username, password),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test_radius",
						tfjsonpath.New("data").AtMapKey(consts.FieldClientToken),
						knownvalue.StringRegexp(nonEmptyRegex)),
					statecheck.ExpectKnownValue("echo.test_radius",
						tfjsonpath.New("data").AtMapKey(consts.FieldAccessor),
						knownvalue.StringRegexp(nonEmptyRegex)),
					statecheck.ExpectKnownValue("echo.test_radius",
						tfjsonpath.New("data").AtMapKey(consts.FieldLeaseDuration),
						knownvalue.NotNull()),
				},
			},
			// Step 3: Use the token with a provider alias to call auth/token/lookup-self.
			// This proves the token is not only issued but actually usable.
			{
				Config: testAccRadiusAuthLoginWithTokenUseConfig_basic(mount, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(
						"data.vault_generic_secret.token_self", "data.%"),
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

// TestAccRadiusAuthLogin_namespace tests RADIUS auth login in a Vault Enterprise namespace
func TestAccRadiusAuthLogin_namespace(t *testing.T) {
	// Skip test unless RADIUS server is configured
	testutil.SkipTestEnvUnset(t,
		"VAULT_ACC_TEST_RADIUS_HOST",
		"VAULT_ACC_TEST_RADIUS_SECRET",
		"VAULT_ACC_TEST_RADIUS_USERNAME",
		"VAULT_ACC_TEST_RADIUS_PASSWORD",
	)

	namespace := acctest.RandomWithPrefix("ns")
	mount := acctest.RandomWithPrefix("tf-test-radius")
	username := os.Getenv("VAULT_ACC_TEST_RADIUS_USERNAME")
	password := os.Getenv("VAULT_ACC_TEST_RADIUS_PASSWORD")

	// Regex to ensure token and accessor are set
	nonEmptyRegex, err := regexp.Compile("^.+$")
	if err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		// Include the provider we want to test (v5)
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		// Include `echo` as a v6 provider from `terraform-plugin-testing`
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			// Step 1: Create namespace and RADIUS infrastructure
			{
				Config: testAccRadiusAuthInfraConfig_namespace(namespace, mount, username),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 2: Add ephemeral login in the namespace
			{
				Config: testAccRadiusAuthLoginConfig_namespace(namespace, mount, username, password),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test_radius_ns",
						tfjsonpath.New("data").AtMapKey(consts.FieldClientToken),
						knownvalue.StringRegexp(nonEmptyRegex)),
					statecheck.ExpectKnownValue("echo.test_radius_ns",
						tfjsonpath.New("data").AtMapKey(consts.FieldAccessor),
						knownvalue.StringRegexp(nonEmptyRegex)),
					statecheck.ExpectKnownValue("echo.test_radius_ns",
						tfjsonpath.New("data").AtMapKey(consts.FieldLeaseDuration),
						knownvalue.NotNull()),
				},
			},
			// Step 3: Use the namespaced token with provider alias
			{
				Config: testAccRadiusAuthLoginWithTokenUseConfig_namespace(namespace, mount, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(
						"data.vault_generic_secret.token_self_ns", "data.%"),
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

// testAccRadiusAuthBackendMountOnly creates only the auth backend mount
func testAccRadiusAuthBackendMountOnly(mount string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
  type = "radius"
  path = %q
}
`, mount)
}

// testAccRadiusAuthBackendInfra creates the complete RADIUS infrastructure
// (mount + backend config + policy + user) without ephemeral login
func testAccRadiusAuthBackendInfra(mount, username string) string {
	host := os.Getenv("VAULT_ACC_TEST_RADIUS_HOST")
	secret := os.Getenv("VAULT_ACC_TEST_RADIUS_SECRET")

	return fmt.Sprintf(`
%s

resource "vault_radius_auth_backend" "test" {
	mount        = vault_auth_backend.test.path
  host         = %q
  secret_wo    = %q
  dial_timeout = 30
  read_timeout = 30
  
  #depends_on = [vault_auth_backend.test]
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
  
  #depends_on = [vault_radius_auth_backend.test, vault_policy.token_creator]
}
`,
		testAccRadiusAuthBackendMountOnly(mount),
		host, secret, username,
	)
}

// testAccRadiusAuthInfraConfig_basic creates the RADIUS infrastructure without ephemeral login
func testAccRadiusAuthInfraConfig_basic(mount, username string) string {
	return testAccRadiusAuthBackendInfra(mount, username)
}

// testAccRadiusAuthEphemeralLogin returns the ephemeral login configuration block
func testAccRadiusAuthEphemeralLogin(password string) string {
	return fmt.Sprintf(`
ephemeral "vault_radius_auth_login" "test" {
  mount_id = vault_auth_backend.test.id
  mount    = vault_auth_backend.test.path
  username = vault_radius_auth_backend_user.test.username
  password = %q
  
  #depends_on = [vault_radius_auth_backend_user.test]
}
`, password)
}

// testAccRadiusAuthLoginConfig_basic adds ephemeral login to existing infrastructure
func testAccRadiusAuthLoginConfig_basic(mount, username, password string) string {
	return fmt.Sprintf(`
%s
%s

provider "echo" {
  data = ephemeral.vault_radius_auth_login.test
}

resource "echo" "test_radius" {}
`,
		testAccRadiusAuthBackendInfra(mount, username),
		testAccRadiusAuthEphemeralLogin(password),
	)
}

// testAccRadiusAuthLoginWithTokenUseConfig_basic uses the ephemeral token with a provider alias
func testAccRadiusAuthLoginWithTokenUseConfig_basic(mount, username, password string) string {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "http://localhost:8200"
	}

	return fmt.Sprintf(`
%s
%s

# A second Vault provider instance authenticated with the RADIUS-issued token.
provider "vault" {
  alias   = "radius_auth"
  address = %q
  token   = ephemeral.vault_radius_auth_login.test.client_token
}

# Token self-lookup via the RADIUS-authenticated provider alias.
data "vault_generic_secret" "token_self" {
  provider = vault.radius_auth
  path     = "auth/token/lookup-self"
}
`,
		testAccRadiusAuthBackendInfra(mount, username),
		testAccRadiusAuthEphemeralLogin(password),
		vaultAddr,
	)
}

// testAccRadiusAuthBackendInfra_namespace creates RADIUS infrastructure in a namespace
func testAccRadiusAuthBackendInfra_namespace(namespace, mount, username string) string {
	host := os.Getenv("VAULT_ACC_TEST_RADIUS_HOST")
	secret := os.Getenv("VAULT_ACC_TEST_RADIUS_SECRET")

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
  dial_timeout = 30
  read_timeout = 30
  
  #depends_on = [vault_auth_backend.test]
}

resource "vault_policy" "token_creator" {
  namespace = vault_namespace.test.path
  name      = "token-creator"
  policy    = <<EOT
path "auth/token/create" {
  capabilities = ["create", "update"]
}
EOT

  #depends_on = [vault_namespace.test]
}

resource "vault_radius_auth_backend_user" "test" {
  namespace = vault_namespace.test.path
  mount     = vault_auth_backend.test.path
  username  = %q
  policies  = ["default", "token-creator"] 
  
  #depends_on = [vault_radius_auth_backend.test, vault_policy.token_creator]
}
`,
		namespace, mount, host, secret, username,
	)
}

// testAccRadiusAuthEphemeralLogin_namespace returns ephemeral login config in a namespace
func testAccRadiusAuthEphemeralLogin_namespace(namespace, password string) string {
	return fmt.Sprintf(`
ephemeral "vault_radius_auth_login" "test" {
  namespace = vault_namespace.test.path
  mount_id  = vault_auth_backend.test.id
  mount     = vault_auth_backend.test.path
  username  = vault_radius_auth_backend_user.test.username
  password  = %q
  
  #depends_on = [vault_radius_auth_backend_user.test]
}
`, password)
}

// testAccRadiusAuthInfraConfig_namespace creates RADIUS infrastructure in a namespace
func testAccRadiusAuthInfraConfig_namespace(namespace, mount, username string) string {
	return testAccRadiusAuthBackendInfra_namespace(namespace, mount, username)
}

// testAccRadiusAuthLoginConfig_namespace adds ephemeral login in a namespace
func testAccRadiusAuthLoginConfig_namespace(namespace, mount, username, password string) string {
	return fmt.Sprintf(`
%s
%s

provider "echo" {
  data = ephemeral.vault_radius_auth_login.test
}

resource "echo" "test_radius_ns" {}
`,
		testAccRadiusAuthBackendInfra_namespace(namespace, mount, username),
		testAccRadiusAuthEphemeralLogin_namespace(namespace, password),
	)
}

// testAccRadiusAuthLoginWithTokenUseConfig_namespace uses the namespaced token with provider alias
func testAccRadiusAuthLoginWithTokenUseConfig_namespace(namespace, mount, username, password string) string {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "http://localhost:8200"
	}

	return fmt.Sprintf(`
%s
%s

# A second Vault provider instance authenticated with the namespaced RADIUS-issued token.
provider "vault" {
  alias     = "radius_auth_ns"
  address   = %q
  namespace = vault_namespace.test.path
  token     = ephemeral.vault_radius_auth_login.test.client_token
}

# Token self-lookup via the namespaced RADIUS-authenticated provider alias.
data "vault_generic_secret" "token_self_ns" {
  provider = vault.radius_auth_ns
  path     = "auth/token/lookup-self"
}
`,
		testAccRadiusAuthBackendInfra_namespace(namespace, mount, username),
		testAccRadiusAuthEphemeralLogin_namespace(namespace, password),
		vaultAddr,
	)
}
