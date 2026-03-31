// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package userpass_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

const testAccUserpassAuthBackendUserResourceAddress = "vault_userpass_auth_backend_user.test"

var testAccUserpassAuthBackendUserImportIgnore = []string{consts.FieldPasswordWO, consts.FieldPasswordHashWO}

func TestAccUserpassAuthBackendUser(t *testing.T) {
	mount := acctest.RandomWithPrefix("userpass-mount")
	username := acctest.RandomWithPrefix("userpass-user")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUserpassAuthBackendUserConfigPasswordWithTokenFields(mount, username, "initial-password"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldUsername, username),
					resource.TestCheckNoResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldPasswordWO),
					resource.TestCheckNoResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldPasswordHashWO),
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldTokenTTL, "3600"),
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldTokenMaxTTL, "7200"),
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldTokenPolicies+".#", "2"),
					resource.TestCheckTypeSetElemAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldTokenPolicies+".*", "default"),
					resource.TestCheckTypeSetElemAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldTokenPolicies+".*", "dev"),
				),
				ConfigPlanChecks: testAccUserpassAuthBackendUserEmptyPlanChecks(),
			},
			testAccUserpassAuthBackendUserImportStep(mount, username),
		},
	})
}

func TestAccUserpassAuthBackendUser_passwordHash(t *testing.T) {
	mount := acctest.RandomWithPrefix("userpass-mount")
	username := acctest.RandomWithPrefix("userpass-user")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion117)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUserpassAuthBackendUserConfigHash(mount, username, "$2a$10$V1HAj0oLIhJtqkj3w0zGx.fjMxmVnY2m0sI4GTiD6W69eCi7epTzW", true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldUsername, username),
					resource.TestCheckNoResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldPasswordWO),
					resource.TestCheckNoResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldPasswordHashWO),
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldTokenTTL, "3600"),
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldTokenMaxTTL, "7200"),
				),
				ConfigPlanChecks: testAccUserpassAuthBackendUserEmptyPlanChecks(),
			},
			testAccUserpassAuthBackendUserImportStep(mount, username),
		},
	})
}

func TestAccUserpassAuthBackendUser_namespace(t *testing.T) {
	mount := acctest.RandomWithPrefix("userpass-mount")
	username := acctest.RandomWithPrefix("userpass-user")
	namespace := acctest.RandomWithPrefix("ns")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUserpassAuthBackendUserConfigNamespace(namespace, mount, username, "initial-password"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldNamespace, namespace),
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldUsername, username),
					resource.TestCheckNoResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldPasswordWO),
				),
				ConfigPlanChecks: testAccUserpassAuthBackendUserEmptyPlanChecks(),
			},
			testAccUserpassAuthBackendUserImportStepWithNamespace(t, mount, username, namespace),
		},
	})
}

func TestAccUserpassAuthBackendUser_passwordWO(t *testing.T) {
	mount := acctest.RandomWithPrefix("userpass-mount")
	username := acctest.RandomWithPrefix("userpass-user")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUserpassAuthBackendUserConfigPassword(mount, username, "initial-password"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldUsername, username),
					resource.TestCheckNoResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldPasswordWO),
				),
				ConfigPlanChecks: testAccUserpassAuthBackendUserEmptyPlanChecks(),
			},
			{
				Config: testAccUserpassAuthBackendUserConfigPassword(mount, username, "new-password"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckNoResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldPasswordWO),
				),
				ConfigPlanChecks: testAccUserpassAuthBackendUserEmptyPlanChecks(),
			},
			testAccUserpassAuthBackendUserImportStep(mount, username),
		},
	})
}

func TestAccUserpassAuthBackendUser_passwordHashValidator(t *testing.T) {
	mount := acctest.RandomWithPrefix("userpass-mount")
	username := acctest.RandomWithPrefix("userpass-user")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccUserpassAuthBackendUserConfigHash(mount, username, "invalid-bcrypt-hash", false),
				ExpectError: regexp.MustCompile("must be a bcrypt hash"),
			},
		},
	})
}

func TestAccUserpassAuthBackendUser_bothCredentialsSet(t *testing.T) {
	mount := acctest.RandomWithPrefix("userpass-mount")
	username := acctest.RandomWithPrefix("userpass-user")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion117)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccUserpassAuthBackendUserConfigBothCredentials(mount, username),
				ExpectError: regexp.MustCompile(`(?s)Invalid Attribute Combination.*(password_hash_wo.*cannot be specified when .*password_wo|password_wo.*cannot be specified when .*password_hash_wo)`),
			},
		},
	})
}

func TestAccUserpassAuthBackendUser_updatePasswordAndPolicies(t *testing.T) {
	mount := acctest.RandomWithPrefix("userpass-mount")
	username := acctest.RandomWithPrefix("userpass-user")

	initialPassword := "initial-password"
	updatedPassword := "updated-password"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUserpassAuthBackendUserConfigPasswordAndPolicies(mount, username, initialPassword, []string{"default", "dev"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldUsername, username),
					resource.TestCheckNoResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldPasswordWO),
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldTokenPolicies+".#", "2"),
					resource.TestCheckTypeSetElemAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldTokenPolicies+".*", "default"),
					resource.TestCheckTypeSetElemAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldTokenPolicies+".*", "dev"),
					testCheckUserpassLoginPassword(testAccUserpassAuthBackendUserResourceAddress, initialPassword),
				),
				ConfigPlanChecks: testAccUserpassAuthBackendUserEmptyPlanChecks(),
			},
			{
				Config: testAccUserpassAuthBackendUserConfigPasswordAndPolicies(mount, username, updatedPassword, []string{"default", "ops"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckNoResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldPasswordWO),
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldTokenPolicies+".#", "2"),
					resource.TestCheckTypeSetElemAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldTokenPolicies+".*", "default"),
					resource.TestCheckTypeSetElemAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldTokenPolicies+".*", "ops"),
					testCheckUserpassLoginPassword(testAccUserpassAuthBackendUserResourceAddress, updatedPassword),
				),
				ConfigPlanChecks: testAccUserpassAuthBackendUserEmptyPlanChecks(),
			},
		},
	})
}

func testAccUserpassAuthBackendUserEmptyPlanChecks() resource.ConfigPlanChecks {
	return resource.ConfigPlanChecks{
		PostApplyPostRefresh: []plancheck.PlanCheck{
			plancheck.ExpectEmptyPlan(),
		},
	}
}

func testAccUserpassAuthBackendUserImportID(mount, username string) string {
	return fmt.Sprintf("auth/%s/users/%s", mount, username)
}

func testAccUserpassAuthBackendUserImportStep(mount, username string) resource.TestStep {
	return resource.TestStep{
		ResourceName:                         testAccUserpassAuthBackendUserResourceAddress,
		ImportState:                          true,
		ImportStateId:                        testAccUserpassAuthBackendUserImportID(mount, username),
		ImportStateVerify:                    true,
		ImportStateVerifyIdentifierAttribute: consts.FieldMount,
		ImportStateVerifyIgnore:              testAccUserpassAuthBackendUserImportIgnore,
	}
}

func testAccUserpassAuthBackendUserImportStepWithNamespace(t *testing.T, mount, username, namespace string) resource.TestStep {
	return resource.TestStep{
		PreConfig: func() {
			t.Setenv(consts.EnvVarVaultNamespaceImport, namespace)
		},
		ResourceName:                         testAccUserpassAuthBackendUserResourceAddress,
		ImportState:                          true,
		ImportStateId:                        testAccUserpassAuthBackendUserImportID(mount, username),
		ImportStateVerify:                    true,
		ImportStateVerifyIdentifierAttribute: consts.FieldMount,
		ImportStateVerifyIgnore:              testAccUserpassAuthBackendUserImportIgnore,
	}
}

func testCheckUserpassLoginPassword(resourceName, password string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found in state: %s", resourceName)
		}

		client, err := provider.GetClient(rs.Primary, acctestutil.TestProvider.Meta())
		if err != nil {
			return err
		}

		mount := rs.Primary.Attributes[consts.FieldMount]
		username := rs.Primary.Attributes[consts.FieldUsername]
		if mount == "" || username == "" {
			return fmt.Errorf("missing mount or username in state for %s", resourceName)
		}

		loginPath := fmt.Sprintf("auth/%s/login/%s", mount, username)
		secret, err := client.Logical().Write(loginPath, map[string]any{"password": password})
		if err != nil {
			return fmt.Errorf("failed userpass login with expected password on %q: %w", loginPath, err)
		}
		if secret == nil || secret.Auth == nil {
			return fmt.Errorf("missing auth response for login path %q", loginPath)
		}

		return nil
	}
}

func testAccUserpassAuthBackendUserConfigPassword(mount, username, password string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = %q
}

resource "vault_userpass_auth_backend_user" "test" {
	mount       = vault_auth_backend.userpass.path
	username    = %q
	password_wo = %q
}
`, mount, username, password)
}

func testAccUserpassAuthBackendUserConfigPasswordWithTokenFields(mount, username, password string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = %q
}

resource "vault_userpass_auth_backend_user" "test" {
	mount                   = vault_auth_backend.userpass.path
	username                = %q
	password_wo             = %q
	token_ttl               = 3600
	token_max_ttl           = 7200
	token_policies          = ["default", "dev"]
	token_num_uses          = 3
	token_period            = 45
	token_no_default_policy = true
}
`, mount, username, password)
}

func testAccUserpassAuthBackendUserConfigHash(mount, username, passwordHash string, withTokenFields bool) string {
	tokenFields := ""
	if withTokenFields {
		tokenFields = `
  token_ttl      = 3600
  token_max_ttl  = 7200
  token_policies = ["default", "dev"]`
	}

	return fmt.Sprintf(`
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = %q
}

resource "vault_userpass_auth_backend_user" "test" {
	mount         = vault_auth_backend.userpass.path
	username      = %q
	password_hash_wo = %q%s
}
`, mount, username, passwordHash, tokenFields)
}

func testAccUserpassAuthBackendUserConfigNamespace(namespace, mount, username, password string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
	path = %q
}

resource "vault_auth_backend" "userpass" {
	type      = "userpass"
	path      = %q
	namespace = vault_namespace.test.path
}

resource "vault_userpass_auth_backend_user" "test" {
	namespace   = vault_namespace.test.path
	mount       = vault_auth_backend.userpass.path
	username    = %q
	password_wo = %q
}
`, namespace, mount, username, password)
}

func testAccUserpassAuthBackendUserConfigTokenZeroValues(mount, username, password string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = %q
}

resource "vault_userpass_auth_backend_user" "test" {
	mount                   = vault_auth_backend.userpass.path
	username                = %q
	password_wo             = %q
	token_no_default_policy = false
	token_num_uses          = 0
	token_period            = 0
	alias_metadata = {
	  team = "platform"
	  env  = "dev"
	}
}
`, mount, username, password)
}

func testAccUserpassAuthBackendUserConfigBothCredentials(mount, username string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = %q
}

resource "vault_userpass_auth_backend_user" "test" {
	mount         = vault_auth_backend.userpass.path
	username      = %q
	password_wo   = "initial-password"
	password_hash_wo = "$2a$10$V1HAj0oLIhJtqkj3w0zGx.fjMxmVnY2m0sI4GTiD6W69eCi7epTzW"
}
`, mount, username)
}

func testAccUserpassAuthBackendUserConfigPasswordAndPolicies(mount, username, password string, policies []string) string {
	quotedPolicies := make([]string, 0, len(policies))
	for _, p := range policies {
		quotedPolicies = append(quotedPolicies, fmt.Sprintf("%q", p))
	}

	return fmt.Sprintf(`
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = %q
}

resource "vault_userpass_auth_backend_user" "test" {
	mount          = vault_auth_backend.userpass.path
	username       = %q
	password_wo    = %q
	token_policies = [%s]
}
`, mount, username, password, strings.Join(quotedPolicies, ", "))
}
