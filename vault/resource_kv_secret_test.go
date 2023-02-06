// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKVSecret(t *testing.T) {
	resourceName := "vault_kv_secret.test"
	mount := acctest.RandomWithPrefix("tf-kvv2")
	name := acctest.RandomWithPrefix("tf-secret")

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKVSecretConfig_basic(mount, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/%s", mount, name)),
					resource.TestCheckResourceAttr(resourceName, "data.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "data.zip", "zap"),
					resource.TestCheckResourceAttr(resourceName, "data.foo", "bar"),
					assertKVV1Data(resourceName),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldDataJSON},
			},
			{
				Config: testKVSecretConfig_updated(mount, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/%s", mount, name)),
					resource.TestCheckResourceAttr(resourceName, "data.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "data.bar", "baz"),
					resource.TestCheckResourceAttr(resourceName, "data.foo", "bar"),
					assertKVV1Data(resourceName),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldDataJSON},
			},
		},
	})
}

func kvV1MountConfig(path string) string {
	ret := fmt.Sprintf(`
resource "vault_mount" "kvv1" {
	path        = "%s"
	type        = "kv"
    options     = { version = "1" }
    description = "KV Version 1 secret engine mount"
}`, path)

	return ret
}

func testKVSecretConfig_basic(mount, name string) string {
	ret := fmt.Sprintf(`
%s

`, kvV1MountConfig(mount))

	ret += fmt.Sprintf(`
resource "vault_kv_secret" "test" {
  path = "${vault_mount.kvv1.path}/%s"
  data_json = jsonencode(
    {
      zip = "zap",
      foo = "bar"
    }
  )
}`, name)

	return ret
}

func testKVSecretConfig_updated(mount, name string) string {
	ret := fmt.Sprintf(`
%s

`, kvV1MountConfig(mount))

	ret += fmt.Sprintf(`
resource "vault_kv_secret" "test" {
  path = "${vault_mount.kvv1.path}/%s"
  data_json = jsonencode(
    {
      bar = "baz",
      foo = "bar"
    }
  )
}`, name)

	return ret
}

func assertKVV1Data(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		path := rs.Primary.Attributes[consts.FieldPath]

		client, err := provider.GetClient(rs.Primary, testProvider.Meta())
		if err != nil {
			return err
		}

		tAttrs := []*testutil.VaultStateTest{
			{
				ResourceName: resourceName,
				StateAttr:    "data",
				VaultAttr:    "",
			},
		}

		return testutil.AssertVaultState(client, s, path, tAttrs...)
	}
}
