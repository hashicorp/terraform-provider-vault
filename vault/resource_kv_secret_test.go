package vault

import (
	"fmt"
	"testing"

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
				Config: testKVSecretConfig(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/%s", mount, name)),
					resource.TestCheckResourceAttr(resourceName, "data.zip", "zap"),
					resource.TestCheckResourceAttr(resourceName, "data.foo", "bar"),
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

func testKVSecretConfig(mount, name string) string {
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
