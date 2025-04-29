// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceKVSecretList(t *testing.T) {
	var p *schema.Provider
	t.Parallel()
	mount := acctest.RandomWithPrefix("tf-kv")
	s1 := acctest.RandomWithPrefix("foo")
	s2 := acctest.RandomWithPrefix("bar")

	datasourceName := "data.vault_kv_secrets_list.test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceKVSecretListConfig(mount, s1, s2, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(datasourceName, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(datasourceName, "names.#", "3"),
					resource.TestCheckResourceAttr(datasourceName, "names.0", s2),
					resource.TestCheckResourceAttr(datasourceName, "names.1", fmt.Sprintf("%s/", s2)),
					resource.TestCheckResourceAttr(datasourceName, "names.2", s1),
				),
			},
			{
				Config: testDataSourceKVSecretListConfig(mount, s1, s2, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(datasourceName, consts.FieldPath, mount),
					resource.TestCheckResourceAttr(datasourceName, "names.#", "4"),
					resource.TestCheckResourceAttr(datasourceName, "names.0", s2),
					resource.TestCheckResourceAttr(datasourceName, "names.1", fmt.Sprintf("%s/", s2)),
					resource.TestCheckResourceAttr(datasourceName, "names.2", s1),
					resource.TestCheckResourceAttr(datasourceName, "names.3", fmt.Sprintf("%s/", s1)),
				),
			},
		},
	})
}

func testDataSourceKVSecretListConfig(mount, secretPath1, secretPath2 string, isUpdate bool) string {
	config := fmt.Sprintf(`
%s

resource "vault_kv_secret" "test_1" {
  path = "${vault_mount.kvv1.path}/%s"
  data_json = jsonencode(
    {
      zip = "zap",
      foo = "bar"
    }
  )
}

resource "vault_kv_secret" "test_2" {
  path = "${vault_mount.kvv1.path}/%s"
  data_json = jsonencode(
    {
      zip = "zap",
      foo = "bar"
    }
  )
}

resource "vault_kv_secret" "test_nested" {
  path = "${vault_kv_secret.test_2.path}/biz"
  data_json = jsonencode(
    {
      zip = "zap",
      foo = "bar"
    }
  )
}

`, kvV1MountConfig(mount), secretPath1, secretPath2)

	if isUpdate {
		config += fmt.Sprintf(`
resource "vault_kv_secret" "test_nested_2" {
  path = "${vault_kv_secret.test_1.path}/baz"
  data_json = jsonencode(
    {
      zip = "zap",
      foo = "bar"
    }
  )
}

data "vault_kv_secrets_list" "test" {
  path       = vault_mount.kvv1.path
  depends_on = [vault_kv_secret.test_nested, vault_kv_secret.test_nested_2]
}
`)
	} else {
		config += fmt.Sprintf(`
data "vault_kv_secrets_list" "test" {
  path       = vault_mount.kvv1.path
  depends_on = [vault_kv_secret.test_nested, vault_kv_secret.test_1]
}
`)
	}

	return config
}
