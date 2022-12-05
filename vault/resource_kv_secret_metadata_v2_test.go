package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKVSecretMetadataV2(t *testing.T) {
	resourceName := "vault_kv_secret_metadata_v2.test"
	mount := acctest.RandomWithPrefix("tf-kvv2")
	name := acctest.RandomWithPrefix("kv-metadata")
	path := fmt.Sprintf("%s/metadata/%s", mount, name)

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKVSecretMetadataV2Config(mount, name, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxVersions, "5"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeleteVersionAfter, "3700"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCASRequired, "false"),
				),
			},
			{
				Config: testKVSecretMetadataV2Config(mount, name, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, mount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxVersions, "7"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDeleteVersionAfter, "87550"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldCASRequired, "false"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					consts.FieldMount,
					consts.FieldName,
					consts.FieldCustomMetadataJSON,
				},
			},
		},
	})
}

func testKVSecretMetadataV2Config(path, name string, isUpdate bool) string {
	ret := fmt.Sprintf(`
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
   flag      = false
 }
 )
}

`, kvV2MountConfig(path), name)

	if !isUpdate {
		ret += fmt.Sprintf(`
resource "vault_kv_secret_metadata_v2" "test" {
  mount                = vault_mount.kvv2.path
  name                 = "%s"
  max_versions         = 5
  delete_version_after = 3700
  cas_required         = false
  custom_metadata_json = jsonencode(
    {
      fizz = "buzz",
    }
  )
}`, name)
	} else {
		ret += fmt.Sprintf(`

resource "vault_kv_secret_metadata_v2" "test" {
  mount                = vault_mount.kvv2.path
  name                 = "%s"
  max_versions         = 7
  delete_version_after = 87550
  cas_required         = false
  custom_metadata_json = jsonencode(
  {
      fizz = "buzz",
  }
  )
}`, name)
	}
	return ret
}
