// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccAzureAccessCredentialsEphemeralResource_basic tests the creation of dynamic
// Azure service principal credentials using ephemeral resource.
// Note: This test may occasionally fail during cleanup due to Azure API rate limiting,
// which is a known Azure infrastructure limitation and not a code issue.
func TestAccAzureAccessCredentialsEphemeralResource_basic(t *testing.T) {

	testutil.SkipTestAcc(t)
	backend := acctest.RandomWithPrefix("tf-test-azure")
	role := "test-role"
	conf := testutil.GetTestAzureConfExistingSP(t)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
		},
		// Include the provider we want to test (v5)
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		// Include `echo` as a v6 provider from `terraform-plugin-testing`
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccAzureAccessCredentialsEphemeralResourceConfig_basic(backend, role, conf),
				ConfigStateChecks: []statecheck.StateCheck{
					// Verify the ephemeral resource produces client credentials
					statecheck.ExpectKnownValue("echo.test_azure",
						tfjsonpath.New("client_id"),
						knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test_azure",
						tfjsonpath.New("client_secret"),
						knownvalue.NotNull()),
				},
			},
		},
	})
}

func testAccAzureAccessCredentialsEphemeralResourceConfig_basic(backend, role string, conf *testutil.AzureTestConf) string {
	return fmt.Sprintf(`
resource "vault_azure_secret_backend" "test" {
  subscription_id = "%s"
  tenant_id      = "%s" 
  client_id      = "%s"
  client_secret  = "%s"
  path           = "%s"
}

resource "vault_azure_secret_backend_role" "test" {
  backend                = vault_azure_secret_backend.test.path
  role                   = "%s"
  ttl                    = 3600
  max_ttl                = 7200

  application_object_id = "%s"
}

ephemeral "vault_azure_access_credentials" "test" {
  backend  = vault_azure_secret_backend.test.path
  role     = vault_azure_secret_backend_role.test.role
  mount_id = vault_azure_secret_backend.test.id
}

provider "echo" {
  data = {
    client_id     = ephemeral.vault_azure_access_credentials.test.client_id
    client_secret = ephemeral.vault_azure_access_credentials.test.client_secret
  }
}

resource "echo" "test_azure" {}
`,
		conf.SubscriptionID,
		conf.TenantID,
		conf.ClientID,
		conf.ClientSecret,
		backend,
		role,
		conf.AppObjectID,
	)
}
