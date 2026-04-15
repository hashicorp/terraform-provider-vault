// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package userpass_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

var testAccUserpassAuthLoginProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"echo": echoprovider.NewProviderServer(),
}

var testAccUserpassAuthLoginNonEmptyRegex = regexp.MustCompile(`.+`)

func testAccUserpassAuthLoginStateChecks() []statecheck.StateCheck {
	return []statecheck.StateCheck{
		statecheck.ExpectKnownValue(
			"echo.test_userpass",
			tfjsonpath.New("data").AtMapKey(consts.FieldClientToken),
			knownvalue.StringRegexp(testAccUserpassAuthLoginNonEmptyRegex),
		),
	}
}

func testAccUserpassAuthLoginPlanChecks() resource.ConfigPlanChecks {
	return resource.ConfigPlanChecks{
		PostApplyPostRefresh: []plancheck.PlanCheck{
			plancheck.ExpectEmptyPlan(),
		},
	}
}

func TestAccUserpassAuthLogin(t *testing.T) {
	mount := acctest.RandomWithPrefix("userpass-mount")
	username := acctest.RandomWithPrefix("userpass-user")
	password := acctest.RandomWithPrefix("userpass-pass")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: testAccUserpassAuthLoginProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:            testAccUserpassAuthLoginConfig(mount, username, password),
				ConfigStateChecks: testAccUserpassAuthLoginStateChecks(),
				ConfigPlanChecks:  testAccUserpassAuthLoginPlanChecks(),
			},
		},
	})
}

func TestAccUserpassAuthLogin_namespace(t *testing.T) {
	mount := acctest.RandomWithPrefix("userpass-mount")
	username := acctest.RandomWithPrefix("userpass-user")
	password := acctest.RandomWithPrefix("userpass-pass")
	namespace := acctest.RandomWithPrefix("ns")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: testAccUserpassAuthLoginProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:            testAccUserpassAuthLoginConfigNamespace(namespace, mount, username, password),
				ConfigStateChecks: testAccUserpassAuthLoginStateChecks(),
				ConfigPlanChecks:  testAccUserpassAuthLoginPlanChecks(),
			},
		},
	})
}

func testAccUserpassAuthLoginConfig(mount, username, password string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = %q
}

resource "vault_userpass_auth_backend_user" "test" {
	mount          = vault_auth_backend.userpass.path
	username       = %q
	password_wo    = %q
	token_policies = ["default"]
}

ephemeral "vault_userpass_auth_login" "login" {
  mount    = vault_auth_backend.userpass.path
  mount_id = vault_auth_backend.userpass.id
  username = vault_userpass_auth_backend_user.test.username
  password = %q
}

provider "echo" {
	data = {
		client_token   = ephemeral.vault_userpass_auth_login.login.client_token
		accessor       = ephemeral.vault_userpass_auth_login.login.accessor
		lease_duration = ephemeral.vault_userpass_auth_login.login.lease_duration
		renewable      = ephemeral.vault_userpass_auth_login.login.renewable
		policies       = ephemeral.vault_userpass_auth_login.login.policies
	}
}

resource "echo" "test_userpass" {}
`, mount, username, password, password)
}

func testAccUserpassAuthLoginConfigNamespace(namespace, mount, username, password string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
	path = %q
}

resource "vault_auth_backend" "userpass" {
	type      = "userpass"
	path      = %q
	namespace = vault_namespace.test.path
}

resource "vault_userpass_auth_backend_user" "test" {
	namespace      = vault_namespace.test.path
	mount          = vault_auth_backend.userpass.path
	username       = %q
	password_wo    = %q
	token_policies = ["default"]
}

ephemeral "vault_userpass_auth_login" "login" {
	namespace = vault_namespace.test.path
	mount     = vault_auth_backend.userpass.path
	mount_id  = vault_auth_backend.userpass.id
	username  = vault_userpass_auth_backend_user.test.username
	password  = %q
}

provider "echo" {
	data = {
		client_token   = ephemeral.vault_userpass_auth_login.login.client_token
		accessor       = ephemeral.vault_userpass_auth_login.login.accessor
		lease_duration = ephemeral.vault_userpass_auth_login.login.lease_duration
		renewable      = ephemeral.vault_userpass_auth_login.login.renewable
		policies       = ephemeral.vault_userpass_auth_login.login.policies
	}
}

resource "echo" "test_userpass" {}
`, namespace, mount, username, password, password)
}
