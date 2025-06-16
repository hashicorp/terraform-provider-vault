// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets_test

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccTFTeamToken confirms that a dynamic terraform team token
// can be read from Vault for a created terraform role
//
// Uses the Echo Provider to test values set in ephemeral resources
// see documentation here for more details:
// https://developer.hashicorp.com/terraform/plugin/testing/acceptance-tests/ephemeral-resources#using-echo-provider-in-acceptance-tests
func TestAccTFTeamToken(t *testing.T) {
	testutil.SkipTestAcc(t)
	// mount := acctest.RandomWithPrefix("postgres")
	// tfName := acctest.RandomWithPrefix("tf")
	// roleName := acctest.RandomWithPrefix("role")

	// values := testutil.SkipTestEnvUnset(t, "POSTGRES_URL")
	// connURL := values[0]

	// // catch-all regex to ensure all usernames and passwords are set to some value
	expectedTokenRegex, err := regexp.Compile("atlasv1")
	// expectedPasswordRegex, err := regexp.Compile("^\\S+$")
	if err != nil {
		t.Fatal(err)
	}
	// templ := `{{ printf \"vault-%s-%s\" (.DisplayName) (random 20) }}`

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
				Config: testTFTeamTokenConfig(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.tf_token", tfjsonpath.New("data").AtMapKey("token"), knownvalue.StringRegexp(expectedTokenRegex)),
					// statecheck.ExpectKnownValue("echo.test_tf", tfjsonpath.New("data").AtMapKey("password"), knownvalue.StringRegexp(expectedPasswordRegex)),
				},
			},
		},
	})
}

func testTFTeamTokenConfig() string {
	return `
ephemeral "vault_terraform_team_token" "tf_token" {
	mount     = "terraform"
	role_name = "tfc-mgmt"
	revoke_on_close = true
}

provider "echo" {
	data = ephemeral.vault_terraform_team_token.tf_token
}

resource "echo" "tf_token" {}
`
}
