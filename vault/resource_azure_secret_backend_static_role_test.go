// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAzureStaticRole_basic(t *testing.T) {
	conf := testutil.GetTestAzureConfExistingSP(t)

	backend := acctest.RandomWithPrefix("tf-test-azure")
	roleName := acctest.RandomWithPrefix("tf-role")
	resourceType := "vault_azure_secret_backend_static_role"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion121)
		},
		CheckDestroy: testAccAzureSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAzureStaticRole_initialConfig(conf, backend, roleName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "role", roleName),
					resource.TestCheckResourceAttr(resourceName, "application_object_id", conf.AppObjectID),
					resource.TestCheckResourceAttr(resourceName, "ttl", "31536000"),
					resource.TestCheckResourceAttr(resourceName, "metadata.%", "1"),
					resource.TestCheckResourceAttr(resourceName, "metadata.hello", "world"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
			{
				Config: testAzureStaticRole_updateConfig(conf, backend, roleName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "role", roleName),
					resource.TestCheckResourceAttr(resourceName, "application_object_id", conf.AppObjectID),
					resource.TestCheckResourceAttr(resourceName, "ttl", "63072000"),
					resource.TestCheckResourceAttr(resourceName, "metadata.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "metadata.hello", "world"),
					resource.TestCheckResourceAttr(resourceName, "metadata.team", "eco"),
				),
			},
		},
	})
}

func testAzureStaticRole_initialConfig(conf *testutil.AzureTestConf, backend, roleName string) string {
	return fmt.Sprintf(`
resource "vault_azure_secret_backend" "azure" {
  path          = "%[1]s"
  subscription_id = "%[2]s"
  tenant_id       = "%[3]s"
  client_id       = "%[4]s"
  client_secret   = "%[5]s"
}

resource "vault_azure_secret_backend_static_role" "test" {
  backend               = vault_azure_secret_backend.azure.path
  role                  = "%[6]s"
  application_object_id = "%[7]s"
  ttl                   = "31536000"
  metadata = {
    hello = "world"
  }
}
`, backend, conf.SubscriptionID, conf.TenantID, conf.ClientID, conf.ClientSecret, roleName, conf.AppObjectID)
}

func testAzureStaticRole_updateConfig(conf *testutil.AzureTestConf, backend, roleName string) string {
	return fmt.Sprintf(`
resource "vault_azure_secret_backend" "azure" {
  path            = "%[1]s"
  subscription_id = "%[2]s"
  tenant_id       = "%[3]s"
  client_id       = "%[4]s"
  client_secret   = "%[5]s"
}

resource "vault_azure_secret_backend_static_role" "test" {
  backend               = vault_azure_secret_backend.azure.path
  role                  = "%[6]s"
  application_object_id = "%[7]s"
  ttl                   = "63072000"
  metadata = {
	hello = "world"
    team  = "eco"
  }
}
`, backend, conf.SubscriptionID, conf.TenantID, conf.ClientID, conf.ClientSecret, roleName, conf.AppObjectID)
}

func TestAzureStaticRole_import(t *testing.T) {
	conf := testutil.GetTestAzureConfExistingSP(t)

	secretID := os.Getenv("AZURE_IMPORT_SECRET_ID")
	clientSecret := os.Getenv("AZURE_IMPORT_CLIENT_SECRET")
	expiration := os.Getenv("AZURE_IMPORT_EXPIRATION") // optional

	if secretID == "" || clientSecret == "" {
		t.Skip("AZURE_IMPORT_SECRET_ID and AZURE_IMPORT_CLIENT_SECRET must be set to run import workflow test")
	}

	backend := acctest.RandomWithPrefix("tf-test-azure")
	roleName := acctest.RandomWithPrefix("tf-role")

	resType := "vault_azure_secret_backend_static_role"
	resName := resType + ".imported"
	dsName := "data.vault_azure_static_access_credentials.read"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion121)
		},
		Steps: []resource.TestStep{
			{
				Config: testAzureStaticRole_importConfig(backend, roleName, conf, secretID, clientSecret, expiration),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resName, consts.FieldRole, roleName),
					resource.TestCheckResourceAttr(resName, consts.FieldApplicationObjectID, conf.AppObjectID),

					resource.TestCheckResourceAttr(dsName, consts.FieldSecretID, secretID),
					resource.TestCheckResourceAttrSet(dsName, consts.FieldClientID),
					resource.TestCheckResourceAttrSet(dsName, consts.FieldClientSecret),
				),
			},
		},
	})
}

func testAzureStaticRole_importConfig(
	backend, roleName string,
	conf *testutil.AzureTestConf,
	secretID, clientSecret, expiration string,
) string {
	// expiration is optional so we include it only when present
	exp := ""
	if expiration != "" {
		exp = fmt.Sprintf(`expiration = "%s"`, expiration)
	}

	return fmt.Sprintf(`
resource "vault_azure_secret_backend" "azure" {
  path            = "%[1]s"
  subscription_id = "%[2]s"
  tenant_id       = "%[3]s"
  client_id       = "%[4]s"
  client_secret   = "%[5]s"
}

resource "vault_azure_secret_backend_static_role" "imported" {
  backend               = vault_azure_secret_backend.azure.path
  role                  = "%[6]s"
  application_object_id = "%[7]s"

  ttl  		     = "63072000"
  secret_id      = "%[8]s"
  client_secret  = "%[9]s"
%[10]s
}

data "vault_azure_static_access_credentials" "read" {
  backend = vault_azure_secret_backend.azure.path
  role    = vault_azure_secret_backend_static_role.imported.role
}
`, backend, conf.SubscriptionID, conf.TenantID, conf.ClientID, conf.ClientSecret, roleName, conf.AppObjectID, secretID,
		clientSecret, exp)
}
