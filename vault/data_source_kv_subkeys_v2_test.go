package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceKVSubkeys_basic(t *testing.T) {
	resourceName := "data.vault_kv_secret_subkeys_v2.test"
	mount := acctest.RandomWithPrefix("tf-kvv2")
	secretPath := acctest.RandomWithPrefix("foo")

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceKVSubkeysConfig(mount, secretPath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", fmt.Sprintf("%s/subkeys/%s", mount, secretPath)),
					resource.TestCheckResourceAttr(resourceName, "subkeys.zip", "null"),
					resource.TestCheckResourceAttr(resourceName, "subkeys.foo", "null"),
				),
			},
		},
	})
}

func testDataSourceKVSubkeysConfig(mount, secretPath string) string {
	ret := fmt.Sprintf(`
%s

resource "vault_kv_secret_v2" "test" {
  mount = vault_mount.kvv2.path
  name  = "%s"
  data_json = jsonencode(
    {
      zip = "zap",
      foo = "bar"
      baz = jsonencode(
        {
          riff = "raff"
        }
      )
    }
  )
}

data "vault_kv_secret_subkeys_v2" "test" {
  mount = vault_mount.kvv2.path
  name  = vault_kv_secret_v2.test.name
}`, kvV2MountConfig(mount), secretPath)

	return ret
}
