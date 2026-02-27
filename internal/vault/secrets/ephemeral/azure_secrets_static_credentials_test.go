// Copyright IBM Corp. 2016, 2025
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
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccAzureStaticCredentials_basic(t *testing.T) {
	conf := testutil.GetTestAzureConfExistingSP(t)

	if conf.AppObjectID == "" {
		t.Skip("AZURE_APP_OBJECT_ID must be set to run Azure static role tests")
	}

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
				Config: testAccAzureStaticCredentialsConfig(backend, role, conf),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.azure_creds", tfjsonpath.New("data").AtMapKey(consts.FieldClientID), knownvalue.StringRegexp(nonEmpty)),
					statecheck.ExpectKnownValue("echo.azure_creds", tfjsonpath.New("data").AtMapKey(consts.FieldClientSecret), knownvalue.StringRegexp(nonEmpty)),
					statecheck.ExpectKnownValue("echo.azure_creds", tfjsonpath.New("data").AtMapKey(consts.FieldSecretID), knownvalue.StringRegexp(nonEmpty)),
					statecheck.ExpectKnownValue("echo.azure_creds", tfjsonpath.New("data").AtMapKey(consts.FieldExpiration), knownvalue.StringRegexp(nonEmpty)),
					statecheck.ExpectKnownValue("echo.azure_creds", tfjsonpath.New("data").AtMapKey(consts.FieldMetadata).AtMapKey("hello"), knownvalue.StringExact("world")),
					statecheck.ExpectKnownValue("echo.azure_creds", tfjsonpath.New("data").AtMapKey(consts.FieldMetadata).AtMapKey("team"), knownvalue.StringExact("eco")),
					statecheck.ExpectKnownValue("echo.azure_creds", tfjsonpath.New("data").AtMapKey(consts.FieldMetadata).AtMapKey("foo"), knownvalue.StringExact("bar")),
				},
			},
		},
	})
}

func testAccAzureStaticCredentialsConfig(backend, role string, conf *testutil.AzureTestConf) string {
	return fmt.Sprintf(`
resource "vault_azure_secret_backend" "azure" {
  path            = "%[1]s"
  subscription_id = "%[2]s"
  tenant_id       = "%[3]s"
  client_id       = "%[4]s"
  client_secret   = "%[5]s"
}

resource "vault_azure_secret_backend_static_role" "role" {
  backend               = vault_azure_secret_backend.azure.path
  role                  = "%[6]s"
  application_object_id = "%[7]s"
  ttl                   = 31536000

  metadata = {
    hello = "world"
    team  = "eco"
  }
}

ephemeral "vault_azure_static_credentials" "role" {
  mount_id = vault_azure_secret_backend_static_role.role.id
  backend  = vault_azure_secret_backend.azure.path
  role     = vault_azure_secret_backend_static_role.role.role

  request_metadata = {
	foo = "bar"
  }
}

provider "echo" {
  data = ephemeral.vault_azure_static_credentials.role
}

resource "echo" "azure_creds" {}
`, backend, conf.SubscriptionID, conf.TenantID, conf.ClientID, conf.ClientSecret, role, conf.AppObjectID)
}
