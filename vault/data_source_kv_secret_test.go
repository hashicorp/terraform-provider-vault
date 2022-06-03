package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceKVSecret(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-kv")
	name := acctest.RandomWithPrefix("foo")

	resourceName := "data.vault_kv_secret.test"
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceKVSecretConfig(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", fmt.Sprintf("%s/%s", mount, name)),
					resource.TestCheckResourceAttr(resourceName, "lease_renewable", "false"),
					resource.TestCheckResourceAttr(resourceName, "data.zip", "zap"),
					resource.TestCheckResourceAttr(resourceName, "data.foo", "bar"),
				),
			},
		},
	})
}

func testDataSourceKVSecretConfig(mount, name string) string {
	return fmt.Sprintf(`
%s

resource "vault_kv_secret" "test" {
  path = "${vault_mount.kvv1.path}/%s"
  data_json = jsonencode(
    {
      zip = "zap",
      foo = "bar"
    }
  )
}

data "vault_kv_secret" "test" {
  path = vault_kv_secret.test.path
}`, kvV1MountConfig(mount), name)
}
