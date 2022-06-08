package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceKVV2Secret(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-kv")
	name := acctest.RandomWithPrefix("foo")

	resourceName := "data.vault_kv_secret_v2.test"
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceKVV2SecretConfig(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mount", mount),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "path", fmt.Sprintf("%s/data/%s", mount, name)),
					resource.TestCheckResourceAttr(resourceName, "destroyed", "false"),
					resource.TestCheckResourceAttr(resourceName, "data.zip", "zap"),
					resource.TestCheckResourceAttr(resourceName, "data.foo", "bar"),
					resource.TestCheckResourceAttr(resourceName, "data.test", "false"),
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
    zip       = "zap",
    foo       = "bar",
    test      = false
  }
  )
}

data "vault_kv_secret_v2" "test" {
  mount = vault_mount.kvv2.path
  name  = vault_kv_secret_v2.test.name
}`, kvV2MountConfig(mount), name)
}
