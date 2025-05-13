// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package secrets_test

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
	"testing"
)

func TestAccKVV2Secret(t *testing.T) {
	// TODO run in CI after fixing
	t.Skip()
	mount := acctest.RandomWithPrefix("kvv2-mount")
	name := acctest.RandomWithPrefix("secret")
	resource.UnitTest(t, resource.TestCase{
		// Ephemeral resources are only available in 1.10 and later
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		// Include the provider we want to test
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		// Include `echo` as a v6 provider from `terraform-plugin-testing`
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testKVV2Setup(mount, name),
			},
			{
				Config: testKVV2SecretConfig(mount, name),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test_krb", tfjsonpath.New("data").AtMapKey("password"), knownvalue.StringExact("password1")),
				},
			},
		},
	})
}

func testKVV2Setup(mount, name string) string {
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
`, mount, name)
}

func testKVV2SecretConfig(mount, name string) string {
	return fmt.Sprintf(`
ephemeral "vault_kvv2_secret" "db_secret" {
	mount = "%s"
	name = "%s"
}

provider "echo" {
	data = ephemeral.vault_kvv2_secret.db_secret.data
}

resource "echo" "test_krb" {}
`, mount, name)
}
