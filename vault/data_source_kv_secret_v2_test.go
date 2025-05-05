// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceKVV2Secret(t *testing.T) {
	t.Parallel()
	mount := acctest.RandomWithPrefix("tf-kv")
	name := acctest.RandomWithPrefix("foo")

	expectedSubkeys := `{"baz":{"riff":"raff"},"foo":"bar","zip":"zap","test":false}`

	resourceName := "data.vault_kv_secret_v2.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceKVV2SecretConfig(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/data/%s", mount, name)),
					resource.TestCheckResourceAttr(resourceName, "destroyed", "false"),
					resource.TestCheckResourceAttr(resourceName, "data.%", "4"),
					resource.TestCheckResourceAttr(resourceName, "data.zip", "zap"),
					resource.TestCheckResourceAttr(resourceName, "data.foo", "bar"),
					resource.TestCheckResourceAttr(resourceName, "data.test", "false"),
					resource.TestCheckResourceAttr(resourceName, "data.baz", "{\"riff\":\"raff\"}"),
					testutil.CheckJSONData(resourceName, consts.FieldDataJSON, expectedSubkeys),
				),
			},
			{
				Config: testDataSourceKVV2SecretWithVersionConfig(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/data/%s", mount, name)),
					resource.TestCheckResourceAttr(resourceName, "destroyed", "false"),
					resource.TestCheckResourceAttr(resourceName, "data.%", "4"),
					resource.TestCheckResourceAttr(resourceName, "data.zip", "zap"),
					resource.TestCheckResourceAttr(resourceName, "data.foo", "bar"),
					resource.TestCheckResourceAttr(resourceName, "data.test", "false"),
					resource.TestCheckResourceAttr(resourceName, "data.baz", "{\"riff\":\"raff\"}"),
					testutil.CheckJSONData(resourceName, consts.FieldDataJSON, expectedSubkeys),
				),
			},
		},
	})
}

func TestDataSourceKVV2Secret_deletedSecret(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-kv")
	name := acctest.RandomWithPrefix("foo")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				PreConfig: func() {
					client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

					err := client.Sys().Mount(mount, &api.MountInput{
						Type:        "kv-v2",
						Description: "Mount for testing KV datasource",
					})
					if err != nil {
						t.Fatalf(fmt.Sprintf("error mounting kvv2 engine; err=%s", err))
					}

					m := map[string]interface{}{
						"foo": "bar",
						"baz": "qux",
					}

					data := map[string]interface{}{
						consts.FieldData: m,
					}

					// Write data at path
					path := fmt.Sprintf("%s/data/%s", mount, name)
					resp, err := client.Logical().Write(path, data)
					if err != nil {
						t.Fatalf(fmt.Sprintf("error writing to Vault; err=%s", err))
					}

					if resp == nil {
						t.Fatalf("empty response")
					}

					// Soft Delete KV V2 secret at path
					// Secret data returned from Vault is nil
					// confirm that plan does not result in panic
					_, err = client.Logical().Delete(path)
					if err != nil {
					}
				},
				Config:   kvV2DatasourceConfig(mount, name),
				PlanOnly: true,
			},
		},
	})
}

func testDataSourceKVV2SecretConfig(mount, name string) string {
	return fmt.Sprintf(`
%s

resource "vault_kv_secret_v2" "test" {
  mount                      = vault_mount.kvv2.path
  name                       = "%s"
  cas                        = 1
  delete_all_versions        = true
  data_json                  = jsonencode(
  {
      zip  = "zap",
      foo  = "bar",
      test = false
      baz = {
          riff = "raff"
        }
  }
  )
}

data "vault_kv_secret_v2" "test" {
  mount = vault_mount.kvv2.path
  name  = vault_kv_secret_v2.test.name
}`, kvV2MountConfig(mount), name)
}

func testDataSourceKVV2SecretWithVersionConfig(mount, name string) string {
	return fmt.Sprintf(`
%s

resource "vault_kv_secret_v2" "test" {
  mount                      = vault_mount.kvv2.path
  name                       = "%s"
  cas                        = 1
  delete_all_versions        = true
  data_json                  = jsonencode(
  {
      zip  = "zap",
      foo  = "bar",
      test = false
      baz = {
          riff = "raff"
        }
  }
  )
}

data "vault_kv_secret_v2" "test" {
  mount = vault_mount.kvv2.path
  name  = vault_kv_secret_v2.test.name
  version = 1
}`, kvV2MountConfig(mount), name)
}

func kvV2DatasourceConfig(mount, name string) string {
	return fmt.Sprintf(`
data "vault_kv_secret_v2" "test" {
  mount = "%s"
  name  = "%s"
}
`, mount, name)
}
