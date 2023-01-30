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
	resourceName := "vault_kv_secret_v2.test"
	mount := acctest.RandomWithPrefix("tf-kvv2")
	name := acctest.RandomWithPrefix("tf-secret")

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
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.cas_required", "false"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.data.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.data.extra", "cheese"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.data.pizza", "please"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.delete_version_after", "0"),
					resource.TestCheckResourceAttr(resourceName, "custom_metadata.0.max_versions", "5"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"data_json", "disable_read",
					"delete_all_versions", "mount",
					"name", "cas",
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
