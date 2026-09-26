// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceKVV2SecretMetadata(t *testing.T) {
	t.Parallel()
	mount := acctest.RandomWithPrefix("tf-kv")
	name := acctest.RandomWithPrefix("foo")

	resourceName := "data.vault_kv_secret_v2_metadata.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceKVV2SecretMetadataConfig(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/data/%s", mount, name)),
					resource.TestCheckResourceAttr(resourceName, "destroyed", "false"),
				),
			},
			{
				Config: testDataSourceKVV2SecretMetadataWithVersionConfig(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/data/%s", mount, name)),
					resource.TestCheckResourceAttr(resourceName, "destroyed", "false"),
				),
			},
		},
	})
}

func TestDataSourceKVV2SecretMetadata_deletedSecret(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-kv")
	name := acctest.RandomWithPrefix("foo")

	config := fmt.Sprintf(`
data "vault_kv_secret_v2_metadata" "test" {
  mount = "%s"
  name  = "%s"
}
`, mount, name)

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
						t.Fatalf("error mounting kvv2 engine; err=%s", err)
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
						t.Fatalf("error writing to Vault; err=%s", err)
					}

					if resp == nil {
						t.Fatalf("empty response")
					}

					// Soft Delete KV V2 secret at path
					// Secret data returned from Vault is nil
					// confirm that plan does not result in panic
					_, err = client.Logical().Delete(path)
					if err != nil {
						t.Fatal(err)
					}
				},
				Config:   config,
				PlanOnly: true,
			},
		},
	})
}

func testDataSourceKVV2SecretMetadataConfig(mount, name string) string {
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

data "vault_kv_secret_v2_metadata" "test" {
  mount = vault_mount.kvv2.path
  name  = vault_kv_secret_v2.test.name
}`, kvV2MountConfig(mount), name)
}

func testDataSourceKVV2SecretMetadataWithVersionConfig(mount, name string) string {
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

data "vault_kv_secret_v2_metadata" "test" {
  mount = vault_mount.kvv2.path
  name  = vault_kv_secret_v2.test.name
  version = 1
}`, kvV2MountConfig(mount), name)
}
