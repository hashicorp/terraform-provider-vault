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
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccTFToken confirms that a dynamic terraform token
// can be read from Vault for a created terraform role
//
// Uses the Echo Provider to test values set in ephemeral resources
// see documentation here for more details:
// https://developer.hashicorp.com/terraform/plugin/testing/acceptance-tests/ephemeral-resources#using-echo-provider-in-acceptance-tests
func TestAccTFToken_basic(t *testing.T) {
	testutil.SkipTestAcc(t)
	tfName := acctest.RandomWithPrefix("tf")

	values := testutil.SkipTestEnvUnset(t, "TEST_TF_TOKEN", "TEST_TF_TEAM_ID")
	configToken := values[0]
	tfTeamID := values[1]

	expectedTokenRegex, err := regexp.Compile("atlasv1")
	if err != nil {
		t.Fatal(err)
	}
	resource.UnitTest(t, resource.TestCase{
		PreCheck: func() { testutil.TestAccPreCheck(t) },
		// Include the provider we want to test
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		// Include `echo` as a v6 provider from `terraform-plugin-testing`
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testTFTokenConfig(configToken, tfName, tfTeamID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.tf_token", tfjsonpath.New("data").AtMapKey("token"), knownvalue.StringRegexp(expectedTokenRegex)),
				},
			},
		},
	})
}

func testTFTokenConfig(configToken, tfName, tfTeamId string) string {
	return fmt.Sprintf(`
resource "vault_terraform_cloud_secret_backend" "test" {
  token       = "%[1]s"
  backend     = "%[2]s"
}

resource "vault_terraform_cloud_secret_role" "test_team" {
  backend         = vault_terraform_cloud_secret_backend.test.backend
  name            = "%[2]s_team_id"
  team_id         = "%[3]s"
  credential_type = "team"
  ttl             = 120
  max_ttl		  = 240
  description     = "%[2]s team role"
}

ephemeral "vault_terraform_token" "tf_token" {
  mount           = vault_terraform_cloud_secret_backend.test.backend
  role_name       = vault_terraform_cloud_secret_role.test_team.name
  mount_id        = vault_terraform_cloud_secret_backend.test.id
}

provider "echo" {
  data = ephemeral.vault_terraform_token.tf_token
}

resource "echo" "tf_token" {}
`, configToken, tfName, tfTeamId)
}
