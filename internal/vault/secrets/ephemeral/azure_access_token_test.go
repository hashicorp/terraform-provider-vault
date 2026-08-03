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
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion121)
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
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion121)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
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
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion121)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config:      testAccAzureAccessTokenInvalidMountConfig(conf),
				ExpectError: regexp.MustCompile(`Unable to get Azure access token`),
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
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion121)
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

// TODO: replace terraform_data workaround with vault_azure_secret_backend once
// the token/ endpoint ships in an official Vault release.
func testAccAzureAccessTokenConfig(backend, role string, conf *testutil.AzureTestConf) string {
	return fmt.Sprintf(`
resource "terraform_data" "azure_mount" {
  input = "%[1]s"

  provisioner "local-exec" {
    command = "vault secrets enable -path=%[1]s vault-plugin-secrets-azure && vault write %[1]s/config subscription_id='%[2]s' tenant_id='%[3]s' client_id='%[4]s' client_secret='%[5]s'"
  }

  provisioner "local-exec" {
    when    = destroy
    command = "vault secrets disable ${self.output}"
  }
}

resource "vault_azure_secret_backend_static_role" "role" {
  depends_on            = [terraform_data.azure_mount]
  backend               = terraform_data.azure_mount.output
  role                  = "%[6]s"
  application_object_id = "%[7]s"
  ttl                   = 31536000
}

ephemeral "vault_azure_access_token" "token" {
  mount_id = vault_azure_secret_backend_static_role.role.id
  mount    = terraform_data.azure_mount.output
  role     = vault_azure_secret_backend_static_role.role.role
  scope    = "%[8]s"
}

provider "echo" {
  data = ephemeral.vault_azure_access_token.token
}

resource "echo" "azure_token" {}
`, backend, conf.SubscriptionID, conf.TenantID, conf.ClientID, conf.ClientSecret, role, conf.AppObjectID, conf.Scope)
}

// TODO: replace terraform_data workaround with vault_azure_secret_backend once
// the token/ endpoint ships in an official Vault release.
func testAccAzureAccessTokenInvalidRoleConfig(backend string, conf *testutil.AzureTestConf) string {
	return fmt.Sprintf(`
resource "terraform_data" "azure_mount" {
  input = "%[1]s"

  provisioner "local-exec" {
    command = "vault secrets enable -path=%[1]s vault-plugin-secrets-azure && vault write %[1]s/config subscription_id='%[2]s' tenant_id='%[3]s' client_id='%[4]s' client_secret='%[5]s'"
  }

  provisioner "local-exec" {
    when    = destroy
    command = "vault secrets disable ${self.output}"
  }
}

ephemeral "vault_azure_access_token" "token" {
  mount_id = terraform_data.azure_mount.id
  mount    = terraform_data.azure_mount.output
  role     = "nonexistent-role"
  scope    = "%[6]s"
}

provider "echo" {
  data = ephemeral.vault_azure_access_token.token
}

resource "echo" "azure_token" {}
`, backend, conf.SubscriptionID, conf.TenantID, conf.ClientID, conf.ClientSecret, conf.Scope)
}

func testAccAzureAccessTokenInvalidMountConfig(conf *testutil.AzureTestConf) string {
	return fmt.Sprintf(`
ephemeral "vault_azure_access_token" "token" {
  mount = "nonexistent-mount"
  role  = "my-role"
  scope = "%[1]s"
}

provider "echo" {
  data = ephemeral.vault_azure_access_token.token
}

resource "echo" "azure_token" {}
`, conf.Scope)
}

// TODO: replace terraform_data workaround with vault_azure_secret_backend once
// the token/ endpoint ships in an official Vault release.
func testAccAzureAccessTokenNamespaceConfig(backend, role, namespace string, conf *testutil.AzureTestConf) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = "%[1]s"
}

resource "terraform_data" "azure_mount" {
  depends_on = [vault_namespace.test]
  input      = "%[2]s"

  provisioner "local-exec" {
    command = "VAULT_NAMESPACE=%[1]s vault secrets enable -path=%[2]s vault-plugin-secrets-azure && VAULT_NAMESPACE=%[1]s vault write %[2]s/config subscription_id='%[3]s' tenant_id='%[4]s' client_id='%[5]s' client_secret='%[6]s'"
  }

  provisioner "local-exec" {
    when    = destroy
    command = "VAULT_NAMESPACE=%[1]s vault secrets disable ${self.output}"
  }
}

resource "vault_azure_secret_backend_static_role" "role" {
  depends_on            = [terraform_data.azure_mount]
  namespace             = vault_namespace.test.path
  backend               = terraform_data.azure_mount.output
  role                  = "%[7]s"
  application_object_id = "%[8]s"
  ttl                   = 31536000
}

ephemeral "vault_azure_access_token" "token" {
  namespace = vault_namespace.test.path
  mount_id  = vault_azure_secret_backend_static_role.role.id
  mount     = terraform_data.azure_mount.output
  role      = vault_azure_secret_backend_static_role.role.role
  scope     = "%[9]s"
}

provider "echo" {
  data = ephemeral.vault_azure_access_token.token
}

resource "echo" "azure_token" {}
`, namespace, backend, conf.SubscriptionID, conf.TenantID, conf.ClientID, conf.ClientSecret, role, conf.AppObjectID, conf.Scope)
}
