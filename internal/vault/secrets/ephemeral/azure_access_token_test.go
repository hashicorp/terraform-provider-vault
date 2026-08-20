// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets_test

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
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccAzureAccessToken_basic verifies that the ephemeral resource retrieves a
// non-empty access token and populates all computed fields from a Vault Azure
// static role.
func TestAccAzureAccessToken_basic(t *testing.T) {
	conf := testutil.GetTestAzureConfExistingSP(t)
	conf.Scope = testutil.SkipTestEnvUnset(t, "AZURE_ROLE_SCOPE")[0]

	backend := acctest.RandomWithPrefix("tf-test-azure")
	role := acctest.RandomWithPrefix("tf-role")
	nonEmpty := regexp.MustCompile(`^.+$`)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccAzureAccessTokenConfig(backend, role, conf),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.azure_token", tfjsonpath.New("data").AtMapKey("access_token"), knownvalue.StringRegexp(nonEmpty)),
					statecheck.ExpectKnownValue("echo.azure_token", tfjsonpath.New("data").AtMapKey("token_type"), knownvalue.StringExact("Bearer")),
					statecheck.ExpectKnownValue("echo.azure_token", tfjsonpath.New("data").AtMapKey("expires_in"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.azure_token", tfjsonpath.New("data").AtMapKey("ext_expires_in"), knownvalue.NotNull()),
				},
			},
		},
	})
}

// TestAccAzureAccessToken_invalidRole verifies that the ephemeral resource
// returns a meaningful error when the specified role does not exist in Vault.
func TestAccAzureAccessToken_invalidRole(t *testing.T) {
	conf := testutil.GetTestAzureConfExistingSP(t)
	conf.Scope = testutil.SkipTestEnvUnset(t, "AZURE_ROLE_SCOPE")[0]

	backend := acctest.RandomWithPrefix("tf-test-azure")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccAzureAccessTokenInvalidRoleConfig(backend, conf),
				ExpectError: regexp.MustCompile(`Unable to get Azure access token`),
			},
		},
	})
}

// TestAccAzureAccessToken_invalidMount verifies that referencing a Vault mount
// path that does not exist produces a meaningful error.
func TestAccAzureAccessToken_invalidMount(t *testing.T) {
	conf := testutil.GetTestAzureConfExistingSP(t)
	conf.Scope = testutil.SkipTestEnvUnset(t, "AZURE_ROLE_SCOPE")[0]

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccAzureAccessTokenInvalidMountConfig(conf),
				ExpectError: regexp.MustCompile(`Unable to get Azure access token`),
			},
		},
	})
}

// TestAccAzureAccessToken_customRetry verifies that the ephemeral resource
// succeeds when max_retries and retry_delay are explicitly set, confirming
// the override path through Open() is exercised and the schema validator
// accepts the values.
func TestAccAzureAccessToken_customRetry(t *testing.T) {
	conf := testutil.GetTestAzureConfExistingSP(t)
	conf.Scope = testutil.SkipTestEnvUnset(t, "AZURE_ROLE_SCOPE")[0]

	backend := acctest.RandomWithPrefix("tf-test-azure")
	role := acctest.RandomWithPrefix("tf-role")
	nonEmpty := regexp.MustCompile(`^.+$`)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccAzureAccessTokenCustomRetryConfig(backend, role, conf),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.azure_token", tfjsonpath.New("data").AtMapKey("access_token"), knownvalue.StringRegexp(nonEmpty)),
					statecheck.ExpectKnownValue("echo.azure_token", tfjsonpath.New("data").AtMapKey("token_type"), knownvalue.StringExact("Bearer")),
					statecheck.ExpectKnownValue("echo.azure_token", tfjsonpath.New("data").AtMapKey("expires_in"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.azure_token", tfjsonpath.New("data").AtMapKey("ext_expires_in"), knownvalue.NotNull()),
				},
			},
		},
	})
}

// TestAccAzureAccessToken_namespace verifies that the ephemeral resource works
// correctly when scoped to a Vault namespace (Enterprise only).
func TestAccAzureAccessToken_namespace(t *testing.T) {
	conf := testutil.GetTestAzureConfExistingSP(t)
	conf.Scope = testutil.SkipTestEnvUnset(t, "AZURE_ROLE_SCOPE")[0]

	backend := acctest.RandomWithPrefix("tf-test-azure")
	role := acctest.RandomWithPrefix("tf-role")
	namespace := acctest.RandomWithPrefix("tf-ns")
	nonEmpty := regexp.MustCompile(`^.+$`)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccAzureAccessTokenNamespaceConfig(backend, role, namespace, conf),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.azure_token", tfjsonpath.New("data").AtMapKey("access_token"), knownvalue.StringRegexp(nonEmpty)),
					statecheck.ExpectKnownValue("echo.azure_token", tfjsonpath.New("data").AtMapKey("token_type"), knownvalue.StringExact("Bearer")),
					statecheck.ExpectKnownValue("echo.azure_token", tfjsonpath.New("data").AtMapKey("expires_in"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.azure_token", tfjsonpath.New("data").AtMapKey("ext_expires_in"), knownvalue.NotNull()),
				},
			},
		},
	})
}

// azurePluginMountHCL returns the HCL blocks that enable the vault-plugin-secrets-azure
// mount and write the backend config. vault_azure_secret_backend always enables the
// built-in "azure" mount type and cannot be used for the plugin variant.
func azurePluginMountHCL(mountRef, backend string, conf *testutil.AzureTestConf) string {
	return fmt.Sprintf(`
resource "vault_mount" "%[1]s" {
  path = "%[2]s"
  type = "vault-plugin-secrets-azure"
}

resource "vault_generic_endpoint" "%[1]s_config" {
  depends_on           = [vault_mount.%[1]s]
  path                 = "%[2]s/config"
  ignore_absent_fields = true

  data_json = jsonencode({
    subscription_id = "%[3]s"
    tenant_id       = "%[4]s"
    client_id       = "%[5]s"
    client_secret   = "%[6]s"
  })
}
`, mountRef, backend, conf.SubscriptionID, conf.TenantID, conf.ClientID, conf.ClientSecret)
}

func testAccAzureAccessTokenConfig(backend, role string, conf *testutil.AzureTestConf) string {
	return azurePluginMountHCL("azure", backend, conf) + fmt.Sprintf(`
resource "vault_azure_secret_backend_static_role" "role" {
  depends_on            = [vault_generic_endpoint.azure_config]
  backend               = vault_mount.azure.path
  role                  = "%[1]s"
  application_object_id = "%[2]s"
  ttl                   = 31536000
}

ephemeral "vault_azure_access_token" "token" {
  mount_id = vault_azure_secret_backend_static_role.role.id
  mount    = vault_mount.azure.path
  role     = vault_azure_secret_backend_static_role.role.role
  scope    = "%[3]s"
}

provider "echo" {
  data = ephemeral.vault_azure_access_token.token
}

resource "echo" "azure_token" {}
`, role, conf.AppObjectID, conf.Scope)
}

func testAccAzureAccessTokenCustomRetryConfig(backend, role string, conf *testutil.AzureTestConf) string {
	return azurePluginMountHCL("azure", backend, conf) + fmt.Sprintf(`
resource "vault_azure_secret_backend_static_role" "role" {
  depends_on            = [vault_generic_endpoint.azure_config]
  backend               = vault_mount.azure.path
  role                  = "%[1]s"
  application_object_id = "%[2]s"
  ttl                   = 31536000
}

ephemeral "vault_azure_access_token" "token" {
  mount_id    = vault_azure_secret_backend_static_role.role.id
  mount       = vault_mount.azure.path
  role        = vault_azure_secret_backend_static_role.role.role
  scope       = "%[3]s"
  max_retries = 6
  retry_delay = 10
}

provider "echo" {
  data = ephemeral.vault_azure_access_token.token
}

resource "echo" "azure_token" {}
`, role, conf.AppObjectID, conf.Scope)
}

func testAccAzureAccessTokenInvalidRoleConfig(backend string, conf *testutil.AzureTestConf) string {
	return azurePluginMountHCL("azure", backend, conf) + fmt.Sprintf(`
ephemeral "vault_azure_access_token" "token" {
  mount_id = vault_generic_endpoint.azure_config.id
  mount    = vault_mount.azure.path
  role     = "nonexistent-role"
  scope    = "%[1]s"
}
`, conf.Scope)
}

func testAccAzureAccessTokenInvalidMountConfig(conf *testutil.AzureTestConf) string {
	return fmt.Sprintf(`
ephemeral "vault_azure_access_token" "token" {
  mount = "nonexistent-mount"
  role  = "my-role"
  scope = "%[1]s"
}
`, conf.Scope)
}

func testAccAzureAccessTokenNamespaceConfig(backend, role, namespace string, conf *testutil.AzureTestConf) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = "%[1]s"
}

resource "vault_mount" "azure" {
  namespace = vault_namespace.test.path
  path      = "%[2]s"
  type      = "vault-plugin-secrets-azure"
}

resource "vault_generic_endpoint" "azure_config" {
  depends_on           = [vault_mount.azure]
  namespace            = vault_namespace.test.path
  path                 = "%[2]s/config"
  ignore_absent_fields = true

  data_json = jsonencode({
    subscription_id = "%[3]s"
    tenant_id       = "%[4]s"
    client_id       = "%[5]s"
    client_secret   = "%[6]s"
  })
}

resource "vault_azure_secret_backend_static_role" "role" {
  depends_on            = [vault_generic_endpoint.azure_config]
  namespace             = vault_namespace.test.path
  backend               = vault_mount.azure.path
  role                  = "%[7]s"
  application_object_id = "%[8]s"
  ttl                   = 31536000
}

ephemeral "vault_azure_access_token" "token" {
  namespace = vault_namespace.test.path
  mount_id  = vault_azure_secret_backend_static_role.role.id
  mount     = vault_mount.azure.path
  role      = vault_azure_secret_backend_static_role.role.role
  scope     = "%[9]s"
}

provider "echo" {
  data = ephemeral.vault_azure_access_token.token
}

resource "echo" "azure_token" {}
`, namespace, backend, conf.SubscriptionID, conf.TenantID, conf.ClientID, conf.ClientSecret, role, conf.AppObjectID, conf.Scope)
}
