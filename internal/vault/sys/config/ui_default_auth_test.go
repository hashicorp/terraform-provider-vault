// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccConfigUIDefaultAuth(t *testing.T) {
	configName := acctest.RandomWithPrefix("test-config")
	resourceName := "vault_config_ui_default_auth.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion120)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfigUIDefaultAuthConfig(configName, "ldap", `["userpass", "token"]`, "false"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, configName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultAuthType, "ldap"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackupAuthTypes+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackupAuthTypes+".0", "userpass"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackupAuthTypes+".1", "token"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableInheritance, "false"),
				),
			},
			{
				Config: testAccConfigUIDefaultAuthConfig(configName, "oidc", `["github", "token"]`, "true"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, configName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultAuthType, "oidc"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackupAuthTypes+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackupAuthTypes+".0", "github"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackupAuthTypes+".1", "token"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableInheritance, "true"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

func TestAccConfigUIDefaultAuthMinimal(t *testing.T) {
	configName := acctest.RandomWithPrefix("test-config")
	resourceName := "vault_config_ui_default_auth.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion120)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfigUIDefaultAuthConfigMinimal(configName, "token"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, configName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultAuthType, "token"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

func TestAccConfigUIDefaultAuthWithNamespacePath(t *testing.T) {
	configName := acctest.RandomWithPrefix("test-config")
	resourceName := "vault_config_ui_default_auth.test"
	namespacePath := "admin"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion120)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfigUIDefaultAuthConfigWithNamespacePath(configName, "jwt", namespacePath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, configName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultAuthType, "jwt"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespacePath, namespacePath),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

func TestAccConfigUIDefaultAuthAllAuthTypes(t *testing.T) {
	configName := acctest.RandomWithPrefix("test-config")
	resourceName := "vault_config_ui_default_auth.test"

	// Test all valid auth types
	authTypes := []string{"github", "jwt", "ldap", "oidc", "okta", "radius", "saml", "token", "userpass"}

	for _, authType := range authTypes {
		t.Run(authType, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck: func() {
					acctestutil.TestAccPreCheck(t)
					acctestutil.TestEntPreCheck(t)
					acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion120)
				},
				ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config: testAccConfigUIDefaultAuthConfigMinimal(configName, authType),
						Check: resource.ComposeTestCheckFunc(
							resource.TestCheckResourceAttr(resourceName, consts.FieldName, configName),
							resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultAuthType, authType),
						),
					},
				},
			})
		})
	}
}

func TestAccConfigUIDefaultAuthConfigNotFound(t *testing.T) {
	configName := acctest.RandomWithPrefix("test-config")
	resourceName := "vault_config_ui_default_auth.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion120)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfigUIDefaultAuthConfigMinimal(configName, "token"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, configName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultAuthType, "token"),
					// Manually delete the config via Vault API
					testAccConfigUIDefaultAuthDelete(configName),
				),
				ExpectNonEmptyPlan: true,
			},
			{
				Config: testAccConfigUIDefaultAuthConfigMinimal(configName, "token"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, configName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultAuthType, "token"),
				),
			},
		},
	})
}

// testAccConfigUIDefaultAuthDelete deletes a config via the provider's configured client
func testAccConfigUIDefaultAuthDelete(name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, err := provider.GetClient("", acctestutil.TestProvider.Meta())
		if err != nil {
			return err
		}

		path := fmt.Sprintf("sys/config/ui/login/default-auth/%s", name)
		_, err = client.Logical().Delete(path)
		return err
	}
}

func testAccConfigUIDefaultAuthConfig(name, defaultAuthType, backupAuthTypes, disableInheritance string) string {
	return fmt.Sprintf(`
resource "vault_config_ui_default_auth" "test" {
  name                = "%s"
  default_auth_type   = "%s"
  backup_auth_types   = %s
  disable_inheritance = %s
}`, name, defaultAuthType, backupAuthTypes, disableInheritance)
}

func testAccConfigUIDefaultAuthConfigMinimal(name, defaultAuthType string) string {
	return fmt.Sprintf(`
resource "vault_config_ui_default_auth" "test" {
  name              = "%s"
  default_auth_type = "%s"
}`, name, defaultAuthType)
}

func testAccConfigUIDefaultAuthConfigWithNamespacePath(name, defaultAuthType, namespacePath string) string {
	return fmt.Sprintf(`
resource "vault_config_ui_default_auth" "test" {
  name              = "%s"
  default_auth_type = "%s"
  namespace_path    = "%s"
}`, name, defaultAuthType, namespacePath)
}
