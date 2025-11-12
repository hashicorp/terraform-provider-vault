// Copyright (c) HashiCorp, Inc.
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
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccAzureAccessCredentialsEphemeralResource_basic tests the creation of dynamic
// Azure service principal credentials using ephemeral resource.
func TestAccAzureAccessCredentialsEphemeralResource_basic(t *testing.T) {

	conf := testutil.GetTestAzureConfExistingSP(t)
	backend := acctest.RandomWithPrefix("tf-test-azure")
	role := acctest.RandomWithPrefix("tf-role")
	nonEmpty := regexp.MustCompile(`^.+$`)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccAzureAccessCredentialsEphemeralResourceConfig_basic(backend, role, conf),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test_azure",
						tfjsonpath.New("data").AtMapKey("client_id"),
						knownvalue.StringExact(conf.ClientID)),
					statecheck.ExpectKnownValue("echo.test_azure",
						tfjsonpath.New("data").AtMapKey("client_secret"),
						knownvalue.StringRegexp(nonEmpty)),
					statecheck.ExpectKnownValue("echo.test_azure",
						tfjsonpath.New("data").AtMapKey("lease_id"),
						knownvalue.StringRegexp(nonEmpty)),
					statecheck.ExpectKnownValue("echo.test_azure",
						tfjsonpath.New("data").AtMapKey("lease_duration"),
						knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test_azure",
						tfjsonpath.New("data").AtMapKey("lease_start_time"),
						knownvalue.StringRegexp(nonEmpty)),
					statecheck.ExpectKnownValue("echo.test_azure",
						tfjsonpath.New("data").AtMapKey("lease_renewable"),
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
  data = ephemeral.vault_azure_access_credentials.test
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
