// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralauth_test

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
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

// TestAccApproleAuthBackendRoleSecretID confirms that a dynamic AppRole SecretID
// can be generated from Vault for a created AppRole role
//
// Uses the Echo Provider to test values set in ephemeral resources
// see documentation here for more details:
// https://developer.hashicorp.com/terraform/plugin/testing/acceptance-tests/ephemeral-resources#using-echo-provider-in-acceptance-tests
func TestAccApproleAuthBackendRoleSecretID(t *testing.T) {
	acctestutil.SkipTestAcc(t)
	backend := acctest.RandomWithPrefix("approle")
	roleName := acctest.RandomWithPrefix("role")

	// Regex to ensure secret_id and accessor are set to some value (UUIDs with hyphens)
	expectedSecretIDRegex, err := regexp.Compile("^[a-f0-9-]+$")
	if err != nil {
		t.Fatal(err)
	}
	expectedAccessorRegex, err := regexp.Compile("^[a-f0-9-]+$")
	if err != nil {
		t.Fatal(err)
	}

	resource.Test(t, resource.TestCase{
		PreCheck: func() { acctestutil.TestAccPreCheck(t) },
		// Include the provider we want to test (v5)
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		// Include `echo` as a v6 provider from `terraform-plugin-testing`
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testApproleAuthBackendRoleSecretIDConfig(backend, roleName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test_approle", tfjsonpath.New("data").AtMapKey(consts.FieldSecretID), knownvalue.StringRegexp(expectedSecretIDRegex)),
					statecheck.ExpectKnownValue("echo.test_approle", tfjsonpath.New("data").AtMapKey(consts.FieldAccessor), knownvalue.StringRegexp(expectedAccessorRegex)),
				},
			},
		},
	})
}

func testApproleAuthBackendRoleSecretIDConfig(backend, roleName string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "%s"
}

resource "vault_approle_auth_backend_role" "role" {
  backend   = vault_auth_backend.approle.path
  role_name = "%s"
}

ephemeral "vault_approle_auth_backend_role_secret_id" "secret" {
  backend   = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.role.role_name
  mount_id  = vault_approle_auth_backend_role.role.id
}

provider "echo" {
  data = ephemeral.vault_approle_auth_backend_role_secret_id.secret
}

resource "echo" "test_approle" {}
`, backend, roleName)
}
