package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceKVV2Secret(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-kv")
	name := acctest.RandomWithPrefix("foo")

	expectedSubkeys := `{"baz":{"riff":"raff"},"foo":"bar","zip":"zap","test":false}`

	resourceName := "data.vault_kv_secret_v2.test"
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
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
