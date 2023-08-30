// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAzureSecretBackendRole(t *testing.T) {
	subscriptionID := os.Getenv("ARM_SUBSCRIPTION_ID")
	if subscriptionID == "" {
		t.Skip("ARM_SUBSCRIPTION_ID not set")
	}
	tenantID := os.Getenv("ARM_TENANT_ID")
	clientID := os.Getenv("ARM_CLIENT_ID")
	clientSecret := os.Getenv("ARM_CLIENT_SECRET")
	resourceGroup := os.Getenv("ARM_RESOURCE_GROUP")

	path := acctest.RandomWithPrefix("tf-test-azure")
	role := acctest.RandomWithPrefix("tf-test-azure-role")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccAzureSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAzureSecretBackendRoleInitialConfig(subscriptionID, tenantID, clientID, clientSecret, path, role, resourceGroup),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_azure_secret_backend_role.test_azure_roles", "role", role+"-azure-roles"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend_role.test_azure_roles", "description", "Test for Vault Provider"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend_role.test_azure_roles", "azure_roles.#", "1"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend_role.test_azure_roles", "azure_roles.0.role_name", "Reader"),
					resource.TestCheckResourceAttrSet("vault_azure_secret_backend_role.test_azure_roles", "azure_roles.0.scope"),
					resource.TestCheckResourceAttrSet("vault_azure_secret_backend_role.test_azure_roles", "azure_roles.0.role_id"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend_role.test_azure_groups", "role", role+"-azure-groups"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend_role.test_azure_groups", "description", "Test for Vault Provider"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend_role.test_azure_groups", "azure_groups.#", "1"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend_role.test_azure_groups", "azure_groups.0.group_name", "foobar"),
					resource.TestCheckResourceAttrSet("vault_azure_secret_backend_role.test_azure_groups", "azure_groups.0.object_id"),
				),
			},
			{
				// permanently delete application registration when true
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !meta.IsAPISupported(provider.VaultVersion112), nil
				},
				Config: testAzureSecretBackendRolePermanentlyDelete(subscriptionID, tenantID, clientID, clientSecret, path, role, resourceGroup),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_azure_secret_backend_role.test_azure_roles", "role", role+"-azure-roles"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend_role.test_azure_roles", "description", "Test for Vault Provider"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend_role.test_azure_roles", "permanently_delete", "false"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend_role.test_azure_roles", "azure_roles.#", "1"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend_role.test_azure_roles", "azure_roles.0.role_name", "Reader"),
					resource.TestCheckResourceAttrSet("vault_azure_secret_backend_role.test_azure_roles", "azure_roles.0.scope"),
					resource.TestCheckResourceAttrSet("vault_azure_secret_backend_role.test_azure_roles", "azure_roles.0.role_id"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend_role.test_azure_groups", "role", role+"-azure-groups"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend_role.test_azure_groups", "description", "Test for Vault Provider"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend_role.test_azure_groups", "permanently_delete", "true"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend_role.test_azure_groups", "azure_groups.#", "1"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend_role.test_azure_groups", "azure_groups.0.group_name", "foobar"),
					resource.TestCheckResourceAttrSet("vault_azure_secret_backend_role.test_azure_groups", "azure_groups.0.object_id"),
				),
			},
			{
				Config:      testAzureSecretBackendRoleConfigError(subscriptionID, tenantID, clientID, clientSecret, path, role, resourceGroup),
				ExpectError: regexp.MustCompile("must specify at most one of 'role_name' or 'role_id'"),
			},
		},
	})
}

func testAccAzureSecretBackendRoleCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_azure_secret_backend" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		mounts, err := client.Sys().ListMounts()
		if err != nil {
			return err
		}

		for path, mount := range mounts {
			path = strings.Trim(path, "/")
			rsPath := strings.Trim(rs.Primary.Attributes["path"], "/")
			if mount.Type == "azure" && path == rsPath {
				return fmt.Errorf("Mount %q still exists", path)
			}
		}
	}
	return nil
}

func testAzureSecretBackendRoleConfigError(subscriptionID string, tenantID string, clientID string, clientSecret string, path string, role string, resourceGroup string) string {
	return fmt.Sprintf(`
resource "vault_azure_secret_backend" "azure" {
  subscription_id = "%s"
  tenant_id       = "%s"
  client_id       = "%s"
  client_secret   = "%s"
  path            = "%s"
}

resource "vault_azure_secret_backend_role" "test_azure_roles_error" {
  backend     = vault_azure_secret_backend.azure.path
  role        = "%[6]s-azure-roles"
  ttl         = 300
  max_ttl     = 600
  description = "Test for Vault Provider"

  azure_roles {
    role_name = "Reader"
    role_id   = "/subscriptions/%[1]s/providers/Microsoft.Authorization/roleDefinitions/%[5]s"
    scope     = "/subscriptions/%[1]s/resourceGroups/%[7]s"
  }
}
`, subscriptionID, tenantID, clientID, clientSecret, path, role, resourceGroup)
}

func testAzureSecretBackendRoleInitialConfig(subscriptionID string, tenantID string, clientID string, clientSecret string, path string, role string, resourceGroup string) string {
	return fmt.Sprintf(`
resource "vault_azure_secret_backend" "azure" {
  subscription_id = "%s"
  tenant_id       = "%s"
  client_id       = "%s"
  client_secret   = "%s"
  path            = "%s"
}

resource "vault_azure_secret_backend_role" "test_azure_roles" {
  backend     = vault_azure_secret_backend.azure.path
  role        = "%[6]s-azure-roles"
  ttl         = 300
  max_ttl     = 600
  description = "Test for Vault Provider"

  azure_roles {
    role_name = "Reader"
    scope =  "/subscriptions/%[1]s/resourceGroups/%[7]s"
  }
}

resource "vault_azure_secret_backend_role" "test_azure_groups" {
  backend     = vault_azure_secret_backend.azure.path
  role        = "%[6]s-azure-groups"
  ttl         = 300
  max_ttl     = 600
  description = "Test for Vault Provider"

  azure_groups {
    group_name = "foobar"
  }
}
`, subscriptionID, tenantID, clientID, clientSecret, path, role, resourceGroup)
}

func testAzureSecretBackendRolePermanentlyDelete(subscriptionID string, tenantID string, clientID string, clientSecret string, path string, role string, resourceGroup string) string {
	return fmt.Sprintf(`
resource "vault_azure_secret_backend" "azure" {
  subscription_id = "%s"
  tenant_id       = "%s"
  client_id       = "%s"
  client_secret   = "%s"
  path            = "%s"
}

resource "vault_azure_secret_backend_role" "test_azure_roles" {
  backend     = vault_azure_secret_backend.azure.path
  role        = "%[6]s-azure-roles"
  ttl         = 300
  max_ttl     = 600
  description = "Test for Vault Provider"

  azure_roles {
    role_name = "Reader"
    scope =  "/subscriptions/%[1]s/resourceGroups/%[7]s"
  }
}

resource "vault_azure_secret_backend_role" "test_azure_groups" {
  backend            = vault_azure_secret_backend.azure.path
  role               = "%[6]s-azure-groups"
  ttl                = 300
  max_ttl            = 600
  description        = "Test for Vault Provider"
  permanently_delete = true

  azure_groups {
    group_name = "foobar"
  }
}
`, subscriptionID, tenantID, clientID, clientSecret, path, role, resourceGroup)
}
