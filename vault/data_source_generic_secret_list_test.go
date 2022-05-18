package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceGenericSecretList_v1(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-kv")
	s1 := acctest.RandomWithPrefix("foo")
	s2 := acctest.RandomWithPrefix("bar")

	resourceName := "data.vault_generic_secret_list.test"
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceGenericSecretListConfig(mount, s1, s2, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", mount),
					resource.TestCheckResourceAttr(resourceName, "names.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "names.0", s2),
					resource.TestCheckResourceAttr(resourceName, "names.1", s1),
				),
			},
		},
	})
}

func TestDataSourceGenericSecretList_v2(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-kv")
	s1 := acctest.RandomWithPrefix("foo")
	s2 := acctest.RandomWithPrefix("bar")

	resourceName := "data.vault_generic_secret_list.test"
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceGenericSecretListConfig(mount, s1, s2, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", mount),
					resource.TestCheckResourceAttr(resourceName, "names.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "names.0", s2),
					resource.TestCheckResourceAttr(resourceName, "names.1", s1),
				),
			},
		},
	})
}

func testDataSourceGenericSecretListMountConfig(mount string, isV2 bool) string {
	ret := fmt.Sprintf(`
resource "vault_mount" "test" {
	  path = "%s"
	  type = "kv"
	  description = "Example KV Mount."
`, mount)
	if isV2 {
		ret += fmt.Sprintf(`
	  options = {
		  version = "2"
	  }
}`)
	} else {
		ret += fmt.Sprintf(`
	  options = {
		  version = "1"
	  }
}`)
	}

	return ret
}

func testDataSourceGenericSecretListConfig(mount, secretPath1, secretPath2 string, isV2 bool) string {
	return fmt.Sprintf(`
%s

resource "vault_generic_secret" "test_1" {
    path      = "${vault_mount.test.path}/%s"
    data_json = <<EOT
{
    "zip": "zap"
}
EOT
}

resource "vault_generic_secret" "test_2" {
  path      = "${vault_mount.test.path}/%s"

  data_json = <<EOT
{
  "foo":   "bar",
  "pizza": "cheese"
}
EOT
}

resource "vault_generic_secret" "test_nested" {
  path = "${vault_generic_secret.test_2.path}/biz"

  data_json = <<EOT
{
  "foo":   "bar",
  "pizza": "cheese"
}
EOT
}

data "vault_generic_secret_list" "test" {
    depends_on = [vault_generic_secret.test_1, vault_generic_secret.test_2]
    path       = vault_mount.test.path
}

`, testDataSourceGenericSecretListMountConfig(mount, isV2), secretPath1, secretPath2)
}
