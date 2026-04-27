// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralauth_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

// TestAccTokenEphemeral_basic confirms that a token can be created via the
// ephemeral resource with minimal configuration.
func TestAccTokenEphemeral_basic(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	// Regex to ensure client_token is set to some value (hvs. for newer Vault, s./h. for older)
	expectedTokenRegex, err := regexp.Compile("^(hvs|hs|s|h)\\..+$")
	if err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccTokenEphemeralConfig_basic(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test_token", tfjsonpath.New("data").AtMapKey(consts.FieldClientToken), knownvalue.StringRegexp(expectedTokenRegex)),
					statecheck.ExpectKnownValue("echo.test_token", tfjsonpath.New("data").AtMapKey(consts.FieldLeaseDuration), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test_token", tfjsonpath.New("data").AtMapKey(consts.FieldLeaseStarted), knownvalue.NotNull()),
				},
			},
		},
	})
}

func testAccTokenEphemeralConfig_basic() string {
	return `
resource "vault_policy" "test" {
  name   = "test-ephemeral-token"
  policy = <<EOT
path "secret/*" { capabilities = [ "list" ] }
EOT
}

ephemeral "vault_token" "test" {
  policies = [vault_policy.test.name]
  ttl      = "60s"
}

provider "echo" {
  data = ephemeral.vault_token.test
}

resource "echo" "test_token" {}
`
}

// TestAccTokenEphemeral_full confirms that a token can be created with all
// supported input fields.
func TestAccTokenEphemeral_full(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	expectedTokenRegex, err := regexp.Compile("^(hvs|hs|s|h)\\..+$")
	if err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccTokenEphemeralConfig_full(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test_token", tfjsonpath.New("data").AtMapKey(consts.FieldClientToken), knownvalue.StringRegexp(expectedTokenRegex)),
					statecheck.ExpectKnownValue("echo.test_token", tfjsonpath.New("data").AtMapKey(consts.FieldLeaseDuration), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test_token", tfjsonpath.New("data").AtMapKey(consts.FieldLeaseStarted), knownvalue.NotNull()),
				},
			},
		},
	})
}

func testAccTokenEphemeralConfig_full() string {
	return `
resource "vault_policy" "test" {
  name   = "test-ephemeral-token-full"
  policy = <<EOT
path "secret/*" { capabilities = [ "list" ] }
EOT
}

ephemeral "vault_token" "test" {
  policies          = [vault_policy.test.name]
  no_parent         = true
  no_default_policy = true
  renewable         = true
  ttl               = "60s"
  explicit_max_ttl  = "1h"
  display_name      = "test-ephemeral"
  num_uses          = 0
  metadata = {
    fizz = "buzz"
  }
}

provider "echo" {
  data = ephemeral.vault_token.test
}

resource "echo" "test_token" {}
`
}

// TestAccTokenEphemeral_withRole confirms that a token can be created using a
// token role, which exercises the CreateWithRole code path.
func TestAccTokenEphemeral_withRole(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	expectedTokenRegex, err := regexp.Compile("^(hvs|hs|s|h)\\..+$")
	if err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccTokenEphemeralConfig_withRole_step1(),
			},
			{
				Config: testAccTokenEphemeralConfig_withRole(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test_token", tfjsonpath.New("data").AtMapKey(consts.FieldClientToken), knownvalue.StringRegexp(expectedTokenRegex)),
				},
			},
		},
	})
}

func testAccTokenEphemeralConfig_withRole_step1() string {
	return `
resource "vault_token_auth_backend_role" "test" {
  role_name        = "test-ephemeral-token-role"
  allowed_policies = ["default"]
  orphan           = true
  token_period     = 86400
}
`
}

func testAccTokenEphemeralConfig_withRole() string {
	return `
resource "vault_token_auth_backend_role" "test" {
  role_name        = "test-ephemeral-token-role"
  allowed_policies = ["default"]
  orphan           = true
  token_period     = 86400
}

ephemeral "vault_token" "test" {
  role_name = vault_token_auth_backend_role.test.role_name
}

provider "echo" {
  data = ephemeral.vault_token.test
}

resource "echo" "test_token" {}
`
}

// TestAccTokenEphemeral_wrapped confirms that a wrapped token can be created,
// exercising the wrapping code path.
func TestAccTokenEphemeral_wrapped(t *testing.T) {
	acctestutil.SkipTestAcc(t)

	expectedWrappedTokenRegex, err := regexp.Compile("^(hvs|hs|s|h)\\..+$")
	if err != nil {
		t.Fatal(err)
	}
	expectedAccessorRegex, err := regexp.Compile("^.+$")
	if err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccTokenEphemeralConfig_wrapped(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test_token", tfjsonpath.New("data").AtMapKey(consts.FieldWrappedToken), knownvalue.StringRegexp(expectedWrappedTokenRegex)),
					statecheck.ExpectKnownValue("echo.test_token", tfjsonpath.New("data").AtMapKey(consts.FieldWrappingAccessor), knownvalue.StringRegexp(expectedAccessorRegex)),
				},
			},
		},
	})
}

func testAccTokenEphemeralConfig_wrapped() string {
	return fmt.Sprintf(`
resource "vault_policy" "test" {
  name   = "test-ephemeral-token-wrapped"
  policy = <<EOT
path "secret/*" { capabilities = [ "list" ] }
EOT
}

ephemeral "vault_token" "test" {
  policies     = [vault_policy.test.name]
  ttl          = "60s"
  wrapping_ttl = "60s"
}

provider "echo" {
  data = ephemeral.vault_token.test
}

resource "echo" "test_token" {}
`)
}
