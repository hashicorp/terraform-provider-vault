// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package userpass_test

import (
	"context"
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
	"github.com/hashicorp/vault/api"
)

const testAccUserpassAuthBackendUserResourceAddress = "vault_userpass_auth_backend_user.test"

const userpassInvalidCredentialsMessage = "invalid username or password"

var testAccUserpassAuthBackendUserImportIgnore = []string{
	consts.FieldPasswordWO,
	consts.FieldPasswordHashWO,
	consts.FieldPasswordWOVersion,
	consts.FieldPasswordHashWOVersion,
}

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

func TestAccUserpassAuthBackendUser_passwordWOVersion(t *testing.T) {
	mount := acctest.RandomWithPrefix("userpass-mount")
	username := acctest.RandomWithPrefix("userpass-user")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUserpassAuthBackendUserConfigPasswordWithVersion(mount, username, "initial-password", 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldUsername, username),
					resource.TestCheckNoResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldPasswordWO),
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldPasswordWOVersion, "1"),
					testCheckUserpassLoginPassword(testAccUserpassAuthBackendUserResourceAddress, "initial-password"),
				),
				ConfigPlanChecks: testAccUserpassAuthBackendUserEmptyPlanChecks(),
			},
			{
				Config: testAccUserpassAuthBackendUserConfigPasswordWithVersion(mount, username, "updated-password", 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckNoResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldPasswordWO),
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldPasswordWOVersion, "2"),
					testCheckUserpassLoginPassword(testAccUserpassAuthBackendUserResourceAddress, "updated-password"),
				),
				ConfigPlanChecks: testAccUserpassAuthBackendUserEmptyPlanChecks(),
			},
			testAccUserpassAuthBackendUserImportStep(mount, username),
		},
	})
}

func TestAccUserpassAuthBackendUser_passwordWOWithoutVersionIncrement(t *testing.T) {
	mount := acctest.RandomWithPrefix("userpass-mount")
	username := acctest.RandomWithPrefix("userpass-user")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUserpassAuthBackendUserConfigPasswordWithVersion(mount, username, "initial-password", 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldPasswordWOVersion, "1"),
					testCheckUserpassLoginPassword(testAccUserpassAuthBackendUserResourceAddress, "initial-password"),
				),
				ConfigPlanChecks: testAccUserpassAuthBackendUserEmptyPlanChecks(),
			},
			{
				Config: testAccUserpassAuthBackendUserConfigPasswordWithVersion(mount, username, "updated-password", 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldPasswordWOVersion, "1"),
					testCheckUserpassLoginPassword(testAccUserpassAuthBackendUserResourceAddress, "initial-password"),
					testCheckUserpassLoginPasswordFails(testAccUserpassAuthBackendUserResourceAddress, "updated-password", userpassInvalidCredentialsMessage),
				),
				ConfigPlanChecks: testAccUserpassAuthBackendUserEmptyPlanChecks(),
			},
		},
	})
}

func TestAccUserpassAuthBackendUser_passwordHashWOVersion(t *testing.T) {
	mount := acctest.RandomWithPrefix("userpass-mount")
	username := acctest.RandomWithPrefix("userpass-user")

	// bcrypt hash for "initial-password"
	initialHash := "$2a$10$V1HAj0oLIhJtqkj3w0zGx.fjMxmVnY2m0sI4GTiD6W69eCi7epTzW"
	// bcrypt hash for "updated-password"
	updatedHash := "$2a$10$8K1p/a0dL1LH6Mqi/2HYiuyRdvEyavS1pBpCOgEKQVqfhU7wOLCRC"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion117)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUserpassAuthBackendUserConfigHashWithVersion(mount, username, initialHash, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldUsername, username),
					resource.TestCheckNoResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldPasswordHashWO),
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldPasswordHashWOVersion, "1"),
				),
				ConfigPlanChecks: testAccUserpassAuthBackendUserEmptyPlanChecks(),
			},
			{
				Config: testAccUserpassAuthBackendUserConfigHashWithVersion(mount, username, updatedHash, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckNoResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldPasswordHashWO),
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldPasswordHashWOVersion, "2"),
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
	invalidPrefixHash := "$2x$10$V1HAj0oLIhJtqkj3w0zGx.fjMxmVnY2m0sI4GTiD6W69eCi7epTzW"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccUserpassAuthBackendUserConfigHash(mount, username, "invalid-bcrypt-hash", false),
				ExpectError: regexp.MustCompile("password hash has incorrect length"),
			},
			{
				Config:      testAccUserpassAuthBackendUserConfigHash(mount, username, invalidPrefixHash, false),
				ExpectError: regexp.MustCompile("password hash has incorrect prefix"),
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
				ExpectError: regexp.MustCompile(`(?s)Invalid Attribute Combination.*one \(and only one\) of.*\[password_(wo|hash_wo)`),
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

func TestAccUserpassAuthBackendUser_aliasMetadata(t *testing.T) {
	mount := acctest.RandomWithPrefix("userpass-mount")
	username := acctest.RandomWithPrefix("userpass-user")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion121)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccUserpassAuthBackendUserConfigAliasMetadata(mount, username, "initial-password"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldUsername, username),
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldAliasMetadata+".%", "2"),
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldAliasMetadata+".team", "platform"),
					resource.TestCheckResourceAttr(testAccUserpassAuthBackendUserResourceAddress, consts.FieldAliasMetadata+".env", "dev"),
				),
				ConfigPlanChecks: testAccUserpassAuthBackendUserEmptyPlanChecks(),
			},
			testAccUserpassAuthBackendUserImportStep(mount, username),
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
		loginPath, secret, err := performUserpassLogin(s, resourceName, password)
		if err != nil {
			return fmt.Errorf("failed userpass login with expected password on %q: %w", loginPath, err)
		}
		if secret == nil || secret.Auth == nil {
			return fmt.Errorf("missing auth response for login path %q", loginPath)
		}

		return nil
	}
}

func testCheckUserpassLoginPasswordFails(resourceName, password, wantMessage string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		loginPath, secret, err := performUserpassLogin(s, resourceName, password)
		if err == nil {
			if secret != nil && secret.Auth != nil {
				return fmt.Errorf("unexpected successful userpass login on %q with password that should not have been applied", loginPath)
			}
			return fmt.Errorf("expected userpass login failure on %q but received no error", loginPath)
		}

		if !strings.Contains(err.Error(), wantMessage) {
			return fmt.Errorf("unexpected userpass login failure on %q: got %q, want substring %q", loginPath, err.Error(), wantMessage)
		}

		return nil
	}
}

func performUserpassLogin(s *terraform.State, resourceName, password string) (string, *api.Secret, error) {
	rs, ok := s.RootModule().Resources[resourceName]
	if !ok {
		return "", nil, fmt.Errorf("resource not found in state: %s", resourceName)
	}

	client, err := provider.GetClient(rs.Primary, acctestutil.TestProvider.Meta())
	if err != nil {
		return "", nil, err
	}

	mount := rs.Primary.Attributes[consts.FieldMount]
	username := rs.Primary.Attributes[consts.FieldUsername]
	if mount == "" || username == "" {
		return "", nil, fmt.Errorf("missing mount or username in state for %s", resourceName)
	}

	loginPath := fmt.Sprintf("auth/%s/login/%s", mount, username)
	secret, err := client.Logical().WriteWithContext(context.Background(), loginPath, map[string]any{"password": password})

	return loginPath, secret, err
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

func testAccUserpassAuthBackendUserConfigPasswordWithVersion(mount, username, password string, version int) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = %q
}

resource "vault_userpass_auth_backend_user" "test" {
	mount                = vault_auth_backend.userpass.path
	username             = %q
	password_wo          = %q
	password_wo_version  = %d
}
`, mount, username, password, version)
}

func testAccUserpassAuthBackendUserConfigHashWithVersion(mount, username, passwordHash string, version int) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = %q
}

resource "vault_userpass_auth_backend_user" "test" {
	mount                     = vault_auth_backend.userpass.path
	username                  = %q
	password_hash_wo          = %q
	password_hash_wo_version  = %d
}
`, mount, username, passwordHash, version)
}

func testAccUserpassAuthBackendUserConfigAliasMetadata(mount, username, password string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = %q
}

resource "vault_userpass_auth_backend_user" "test" {
	mount                = vault_auth_backend.userpass.path
	username             = %q
	password_wo          = %q
	password_wo_version  = 1
	alias_metadata = {
		team = "platform"
		env  = "dev"
	}
}
`, mount, username, password)
}
