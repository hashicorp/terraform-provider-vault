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

// TestAccKVV2Secret confirms that a secret written to
// a KV-V2 store in Vault is correctly read into the ephemeral resource
//
// Uses the Echo Provider to test values set in ephemeral resources
// see documentation here for more details:
// https://developer.hashicorp.com/terraform/plugin/testing/acceptance-tests/ephemeral-resources#using-echo-provider-in-acceptance-tests
func TestAccKVV2Secret(t *testing.T) {
	testutil.SkipTestAcc(t)

	mount := acctest.RandomWithPrefix("kvv2-mount")
	name := acctest.RandomWithPrefix("secret")
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
				Config: testKVV2SecretConfig(mount, name),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test_krb", tfjsonpath.New("data").AtMapKey("password"), knownvalue.StringExact("password1")),
				},
			},
			{
				Config: testKVV2SecretConfigJson(mount, name),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test_krb", tfjsonpath.New("data").AtMapKey("password"), knownvalue.StringExact("password1")),
				},
			},
		},
	})
}

func testKVV2SecretConfigJson(mount, name string) string {
	return fmt.Sprintf(`
resource "vault_mount" "kvv2" {
  path        = "%s"
  type        = "kv"
  options     = { version = "2" }
}

resource "vault_kv_secret_v2" "secret" {
  mount                      = vault_mount.kvv2.path
  name                       = "%s"
  data_json_wo                  = jsonencode(
    {
      password       = "password1"
    }
  )
  data_json_wo_version = 0
}

ephemeral "vault_kv_secret_v2" "db_secret" {
	mount    = vault_mount.kvv2.path
	mount_id = vault_mount.kvv2.id
	name     = vault_kv_secret_v2.secret.name
}

provider "echo" {
	data = jsondecode(ephemeral.vault_kv_secret_v2.db_secret.data_json)
}

resource "echo" "test_krb" {}


`, mount, name)
}

func testKVV2SecretConfig(mount, name string) string {
	return fmt.Sprintf(`
resource "vault_mount" "kvv2" {
  path        = "%s"
  type        = "kv"
  options     = { version = "2" }
}

resource "vault_kv_secret_v2" "secret" {
  mount                      = vault_mount.kvv2.path
  name                       = "%s"
  data_json_wo                  = jsonencode(
    {
      password       = "password1"
    }
  )
  data_json_wo_version = 0
}

ephemeral "vault_kv_secret_v2" "db_secret" {
	mount    = vault_mount.kvv2.path
	mount_id = vault_mount.kvv2.id
	name     = vault_kv_secret_v2.secret.name
}

provider "echo" {
	data = ephemeral.vault_kv_secret_v2.db_secret.data
}

resource "echo" "test_krb" {}


`, mount, name)
}
