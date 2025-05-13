// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets_test

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
	"regexp"
	"testing"
)

// TestAccDBSecret confirms that a dynamic DB Secret
// can be read from Vault for a created DB Role
//
// Uses the Echo Provider to test values set in ephemeral resources
// see documentation here for more details:
// https://developer.hashicorp.com/terraform/plugin/testing/acceptance-tests/ephemeral-resources#using-echo-provider-in-acceptance-tests
func TestAccDBSecret(t *testing.T) {
	testutil.SkipTestAcc(t)
	mount := acctest.RandomWithPrefix("postgres")
	dbName := acctest.RandomWithPrefix("db")
	roleName := acctest.RandomWithPrefix("role")

	values := testutil.SkipTestEnvUnset(t, "POSTGRES_URL")
	connURL := values[0]

	// catch-all regex to ensure all usernames and passwords are set to some value
	expectedOutputRegex, err := regexp.Compile("^(.+)$")
	if err != nil {
		t.Fatal(err)
	}
	resource.UnitTest(t, resource.TestCase{
		// Ephemeral resources are only available in 1.10 and later
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		PreCheck: func() { testutil.TestAccPreCheck(t) },
		// Include the provider we want to test
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		// Include `echo` as a v6 provider from `terraform-plugin-testing`
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testDBSecretConfig(mount, dbName, roleName, connURL),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test_db", tfjsonpath.New("data").AtMapKey("username"), knownvalue.StringRegexp(expectedOutputRegex)),
				},
			},
		},
	})
}

func testDBSecretConfig(mount, dbName, roleName, connUrl string) string {
	return fmt.Sprintf(`
resource "vault_database_secrets_mount" "test" {
  path = "%s"

  postgresql {
    name              = "%s"
    connection_url    = "%s"
    allowed_roles = ["*"]
  }
}

resource "vault_database_secret_backend_role" "role" {
  backend             = vault_database_secrets_mount.test.path
  name                = "%s"
  db_name             = vault_database_secrets_mount.test.postgresql.0.name
  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
    "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
  ]
}

ephemeral "vault_db_secret" "db_secret" {
	mount    = vault_database_secrets_mount.test.path
	mount_id = vault_database_secrets_mount.test.id
	name     = vault_database_secret_backend_role.role.name
}

provider "echo" {
	data = ephemeral.vault_db_secret.db_secret
}

resource "echo" "test_db" {}
`, mount, dbName, connUrl, roleName)
}
