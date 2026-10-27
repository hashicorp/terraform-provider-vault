// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package azure_test

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
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
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccAzureStaticRole_basic(t *testing.T) {
	conf := testutil.GetTestAzureConfExistingSP(t)

	if conf.AppObjectID == "" {
		t.Skip("AZURE_APP_OBJECT_ID must be set to run Azure static role tests")
	}

	backend := acctest.RandomWithPrefix("tf-test-azure")
	roleName := acctest.RandomWithPrefix("tf-role")
	resourceType := "vault_azure_secret_backend_static_role"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion121)
		},
		Steps: []resource.TestStep{
			{
				Config: testAzureStaticRole_initialConfig(t, conf, backend, roleName, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRole, roleName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldApplicationObjectID, conf.AppObjectID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "31536000"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSeamlessRotation, "false"),
					resource.TestCheckResourceAttr(resourceName, "metadata.%", "1"),
					resource.TestCheckResourceAttr(resourceName, "metadata.hello", "world"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
			{
				Config: testAzureStaticRole_updateConfig(t, conf, backend, roleName, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRole, roleName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldApplicationObjectID, conf.AppObjectID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "63072000"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSeamlessRotation, "false"),
					resource.TestCheckResourceAttr(resourceName, "metadata.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "metadata.hello", "world"),
					resource.TestCheckResourceAttr(resourceName, "metadata.team", "eco"),
				),
			},
		},
	})
}

func testAzureStaticRole_initialConfig(t *testing.T, conf *testutil.AzureTestConf, backend, roleName string, seamless bool) string {
	return fmt.Sprintf(`
resource "vault_azure_secret_backend" "azure" {
  path            = "%[1]s"
  subscription_id = "%[2]s"
  tenant_id       = "%[3]s"
  client_id       = "%[4]s"
  client_secret   = "%[5]s"
  %[8]s
}

resource "vault_azure_secret_backend_static_role" "test" {
  backend               = vault_azure_secret_backend.azure.path
  role                  = "%[6]s"
  application_object_id = "%[7]s"

  ttl = 31536000
  %[9]s

  metadata = {
    hello = "world"
  }
}
`, backend, conf.SubscriptionID, conf.TenantID, conf.ClientID, conf.ClientSecret, roleName, conf.AppObjectID, renderSeamlessRotationConfig(t, seamless), renderSeamlessRotationRoleConfig(t, 31536000, seamless))
}

func testAzureStaticRole_updateConfig(t *testing.T, conf *testutil.AzureTestConf, backend, roleName string, seamless bool) string {
	return fmt.Sprintf(`
resource "vault_azure_secret_backend" "azure" {
  path            = "%[1]s"
  subscription_id = "%[2]s"
  tenant_id       = "%[3]s"
  client_id       = "%[4]s"
  client_secret   = "%[5]s"
  %[8]s
}

resource "vault_azure_secret_backend_static_role" "test" {
  backend               = vault_azure_secret_backend.azure.path
  role                  = "%[6]s"
  application_object_id = "%[7]s"

  ttl = 63072000
  %[9]s

  metadata = {
    hello = "world"
    team  = "eco"
  }
}
`, backend, conf.SubscriptionID, conf.TenantID, conf.ClientID, conf.ClientSecret, roleName, conf.AppObjectID, renderSeamlessRotationConfig(t, seamless), renderSeamlessRotationRoleConfig(t, 63072000, seamless))
}

func TestAccAzureStaticRole_import(t *testing.T) {
	conf := testutil.GetTestAzureConfExistingSP(t)

	secretID := os.Getenv("AZURE_IMPORT_SECRET_ID")
	clientSecret := os.Getenv("AZURE_IMPORT_CLIENT_SECRET")

	if secretID == "" {
		t.Skip("AZURE_IMPORT_SECRET_ID must be set to run import workflow test")
	}

	backend := acctest.RandomWithPrefix("tf-test-azure")
	roleName := acctest.RandomWithPrefix("tf-role")
	resName := "vault_azure_secret_backend_static_role.imported"
	echoName := "echo.azure_creds_import"
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
				Config: testAzureStaticRole_importConfig(t, backend, roleName, conf, secretID, clientSecret, false),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resName, tfjsonpath.New(consts.FieldBackend), knownvalue.StringExact(backend)),
					statecheck.ExpectKnownValue(resName, tfjsonpath.New(consts.FieldRole), knownvalue.StringExact(roleName)),
					statecheck.ExpectKnownValue(resName, tfjsonpath.New(consts.FieldApplicationObjectID), knownvalue.StringExact(conf.AppObjectID)),
					statecheck.ExpectKnownValue(echoName, tfjsonpath.New("data").AtMapKey(consts.FieldSecretID), knownvalue.StringRegexp(nonEmpty)),
					statecheck.ExpectKnownValue(echoName, tfjsonpath.New("data").AtMapKey(consts.FieldClientID), knownvalue.StringRegexp(nonEmpty)),
					statecheck.ExpectKnownValue(echoName, tfjsonpath.New("data").AtMapKey(consts.FieldClientSecret), knownvalue.StringRegexp(nonEmpty)),
				},
			},
		},
	})
}

func testAzureStaticRole_importConfig(t *testing.T, backend, roleName string, conf *testutil.AzureTestConf, secretID, clientSecret string, seamless bool) string {
	return fmt.Sprintf(`
resource "vault_azure_secret_backend" "azure" {
  path            = "%[1]s"
  subscription_id = "%[2]s"
  tenant_id       = "%[3]s"
  client_id       = "%[4]s"
  client_secret   = "%[5]s"
  %[10]s
}

resource "vault_azure_secret_backend_static_role" "imported" {
  backend               = vault_azure_secret_backend.azure.path
  role                  = "%[6]s"
  application_object_id = "%[7]s"

  ttl           = 63072000
  %[11]s
  secret_id     = "%[8]s"
  client_secret = "%[9]s"
}

ephemeral "vault_azure_static_credentials" "imported" {
  mount_id = vault_azure_secret_backend_static_role.imported.id
  backend  = vault_azure_secret_backend.azure.path
  role     = vault_azure_secret_backend_static_role.imported.role
}

provider "echo" {
  data = ephemeral.vault_azure_static_credentials.imported
}

resource "echo" "azure_creds_import" {}
`, backend, conf.SubscriptionID, conf.TenantID, conf.ClientID, conf.ClientSecret, roleName, conf.AppObjectID, secretID, clientSecret, renderSeamlessRotationConfig(t, seamless), renderSeamlessRotationRoleConfig(t, 63072000, false))
}

func TestAccAzureStaticRole_Seamless(t *testing.T) {
	conf := testutil.GetTestAzureConfExistingSP(t)

	if conf.AppObjectID == "" {
		t.Skip("AZURE_APP_OBJECT_ID must be set to run Azure static role tests")
	}

	backend := acctest.RandomWithPrefix("tf-test-azure")
	roleName := acctest.RandomWithPrefix("tf-role")
	resourceType := "vault_azure_secret_backend_static_role"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		Steps: []resource.TestStep{
			{
				Config: testAzureStaticRole_initialConfig(t, conf, backend, roleName, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRole, roleName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldApplicationObjectID, conf.AppObjectID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "31536000"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSeamlessRotation, "false"),
					resource.TestCheckResourceAttr(resourceName, "metadata.%", "1"),
					resource.TestCheckResourceAttr(resourceName, "metadata.hello", "world"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
			{
				Config: testAzureStaticRole_updateConfig(t, conf, backend, roleName, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRole, roleName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldApplicationObjectID, conf.AppObjectID),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "63072000"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSeamlessRotation, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "63072000"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationGracePeriod, "300"),
					resource.TestCheckResourceAttr(resourceName, "metadata.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "metadata.hello", "world"),
					resource.TestCheckResourceAttr(resourceName, "metadata.team", "eco"),
				),
			},
		},
	})
}

func supportsVaultVersion220Ent(t *testing.T) bool {
	t.Helper()
	acctestutil.PreCheck(t)
	return provider.IsAPISupported(acctestutil.TestProvider.Meta(), provider.VaultVersion220) &&
		provider.IsEnterpriseSupported(acctestutil.TestProvider.Meta())
}

func renderSeamlessRotationConfig(t *testing.T, seamless bool) (s string) {
	var b strings.Builder
	if t.Helper(); supportsVaultVersion220Ent(t) {
		b.WriteString("  seamless_rotation = ")
		b.WriteString(strconv.FormatBool(seamless))
		b.WriteByte('\n')
		s = b.String()
	}

	return s
}

func renderSeamlessRotationRoleConfig(t *testing.T, ttl int64, seamless bool) (s string) {
	var b strings.Builder
	if t.Helper(); supportsVaultVersion220Ent(t) {
		b.WriteString("  seamless_rotation = ")
		b.WriteString(strconv.FormatBool(seamless))
		b.WriteByte('\n')

		if seamless {
			b.WriteString("  rotation_period = ")
			b.WriteString(strconv.FormatInt(ttl, 10))
			b.WriteByte('\n')
			b.WriteString("  rotation_grace_period = 300\n")
		}

		s = b.String()
	}

	return s
}
