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

func TestAccKVSecretV2(t *testing.T) {
	t.Parallel()
	resourceName := "vault_kv_secret_v2.test"
	mount := acctest.RandomWithPrefix("tf-kvv2")
	name := acctest.RandomWithPrefix("tf-secret")

	updatedMount := acctest.RandomWithPrefix("random-prefix/tf-cloud-metadata")
	updatedName := acctest.RandomWithPrefix("tf-database-creds")

	customMetadata := `{"extra":"cheese","pizza":"please"}`

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKVSecretV2Config_initial(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/data/%s", mount, name)),
					resource.TestCheckResourceAttr(resourceName, "delete_all_versions", "true"),
					resource.TestCheckResourceAttr(resourceName, "data.zip", "zap"),
					resource.TestCheckResourceAttr(resourceName, "data.foo", "bar"),
					resource.TestCheckResourceAttr(resourceName, "data.flag", "false"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.cas_required", "false"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.data.%", "0"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.delete_version_after", "0"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.max_versions", "0"),
					resource.TestCheckResourceAttr(resourceName, "metadata.%", "5"),
					resource.TestCheckResourceAttr(resourceName, "metadata.version", "1"),
					resource.TestCheckResourceAttr(resourceName, "metadata.destroyed", "false"),
					resource.TestCheckResourceAttr(resourceName, "metadata.deletion_time", ""),
					resource.TestCheckResourceAttr(resourceName, "metadata.custom_metadata", "null"),
				),
			},
			{
				Config: testKVSecretV2Config_updated(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/data/%s", mount, name)),
					resource.TestCheckResourceAttr(resourceName, "delete_all_versions", "true"),
					resource.TestCheckResourceAttr(resourceName, "data.zip", "zoop"),
					resource.TestCheckResourceAttr(resourceName, "data.foo", "baz"),
					resource.TestCheckResourceAttr(resourceName, "data.flag", "false"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.cas_required", "false"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.data.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.data.extra", "cheese"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.data.pizza", "please"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.delete_version_after", "0"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.max_versions", "5"),
					resource.TestCheckResourceAttr(resourceName, "metadata.%", "5"),
					resource.TestCheckResourceAttr(resourceName, "metadata.version", "2"),
					resource.TestCheckResourceAttr(resourceName, "metadata.destroyed", "false"),
					resource.TestCheckResourceAttr(resourceName, "metadata.deletion_time", ""),
					resource.TestCheckResourceAttr(resourceName, "metadata.custom_metadata", customMetadata),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"data_json", "disable_read",
					"delete_all_versions",
				},
			},
			{
				Config: testKVSecretV2Config_initial(updatedMount, updatedName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, updatedMount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, updatedName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/data/%s", updatedMount, updatedName)),
					resource.TestCheckResourceAttr(resourceName, "delete_all_versions", "true"),
					resource.TestCheckResourceAttr(resourceName, "data.zip", "zap"),
					resource.TestCheckResourceAttr(resourceName, "data.foo", "bar"),
					resource.TestCheckResourceAttr(resourceName, "data.flag", "false"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.cas_required", "false"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.data.%", "0"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.delete_version_after", "0"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.max_versions", "0"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"data_json", "disable_read",
					"delete_all_versions",
				},
			},
		},
	})
}

func testKVSecretV2Config_initial(mount, name string) string {
	ret := fmt.Sprintf(`
%s

`, kvV2MountConfig(mount))

	ret += fmt.Sprintf(`
resource "vault_kv_secret_v2" "test" {
  mount               = vault_mount.kvv2.path
  name                = "%s"
  delete_all_versions = true
  data_json = jsonencode(
    {
      zip  = "zap",
      foo  = "bar",
      flag = false
    }
  )
}`, name)

	return ret
}

func testKVSecretV2Config_updated(mount, name string) string {
	ret := fmt.Sprintf(`
%s

`, kvV2MountConfig(mount))

	ret += fmt.Sprintf(`
resource "vault_kv_secret_v2" "test" {
  mount               = vault_mount.kvv2.path
  name                = "%s"
  delete_all_versions = true
  data_json = jsonencode(
    {
      zip  = "zoop",
      foo  = "baz",
      flag = false
    }
  )
  custom_metadata {
    max_versions = 5
    data = {
      extra = "cheese",
      pizza = "please"
    }
  }
}`, name)

	return ret
}
