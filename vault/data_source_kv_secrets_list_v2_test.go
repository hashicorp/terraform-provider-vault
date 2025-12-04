// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceKVSecretListV2(t *testing.T) {
	t.Parallel()
	mount := acctest.RandomWithPrefix("tf-kv")
	s1 := acctest.RandomWithPrefix("foo")
	s2 := acctest.RandomWithPrefix("bar")

	datasource1 := "data.vault_kv_secrets_list_v2.test"
	datasource2 := "data.vault_kv_secrets_list_v2.test_internal"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceKVV2SecretListConfig(mount, s1, s2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(datasource1, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(datasource1, consts.FieldPath, fmt.Sprintf("%s/metadata/", mount)),
					resource.TestCheckResourceAttr(datasource1, "names.#", "3"),
					resource.TestCheckResourceAttr(datasource1, "names.0", s2),
					resource.TestCheckResourceAttr(datasource1, "names.1", fmt.Sprintf("%s/", s2)),
					resource.TestCheckResourceAttr(datasource1, "names.2", s1),
				),
			},
			{
				Config: testDataSourceKVV2SecretListConfig(mount, s1, s2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(datasource2, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(datasource2, consts.FieldName, s2),
					resource.TestCheckResourceAttr(datasource2, consts.FieldPath, fmt.Sprintf("%s/metadata/%s", mount, s2)),
					resource.TestCheckResourceAttr(datasource2, "names.#", "1"),
					resource.TestCheckResourceAttr(datasource2, "names.0", "biz"),
				),
			},
		},
	})
}

func testDataSourceKVV2SecretListConfig(mount, secretPath1, secretPath2 string) string {
	return fmt.Sprintf(`
%s

resource "vault_kv_secret_v2" "test_1" {
  mount = vault_mount.kvv2.path
  name  = "%s"
  data_json = jsonencode(
    {
      zip = "zap",
      foo = "bar"
    }
  )
}

resource "vault_kv_secret_v2" "test_2" {
  mount = vault_mount.kvv2.path
  name  = "%s"
  data_json = jsonencode(
    {
      zip = "zap",
      foo = "bar"
    }
  )
}

resource "vault_kv_secret_v2" "test_nested" {
  mount = vault_mount.kvv2.path
  name  = "${vault_kv_secret_v2.test_2.name}/biz"
  data_json = jsonencode(
    {
      zip = "zap",
      foo = "bar"
    }
  )
}

data "vault_kv_secrets_list_v2" "test" {
  mount      = vault_mount.kvv2.path
  depends_on = [vault_kv_secret_v2.test_nested, vault_kv_secret_v2.test_1]
}

data "vault_kv_secrets_list_v2" "test_internal" {
  mount      = vault_mount.kvv2.path
  name       = vault_kv_secret_v2.test_2.name
  depends_on = [vault_kv_secret_v2.test_nested]
}
`, kvV2MountConfig(mount), secretPath1, secretPath2)
}
