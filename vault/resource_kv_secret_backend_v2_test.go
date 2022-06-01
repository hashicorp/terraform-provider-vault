package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKVSecretBackendV2_basic(t *testing.T) {
	resourceName := "vault_kv_secret_backend_v2.test"
	mount := acctest.RandomWithPrefix("tf-kvv2")

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKVSecretBackendV2Config(mount, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mount", mount),
					resource.TestCheckResourceAttr(resourceName, "max_versions", "5"),
					resource.TestCheckResourceAttr(resourceName, "delete_version_after_input", "3.5h"),
					resource.TestCheckResourceAttr(resourceName, "delete_version_after", "3h30m0s"),
					resource.TestCheckResourceAttr(resourceName, "cas_required", "true"),
				),
			},
			{
				Config: testKVSecretBackendV2Config(mount, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "mount", mount),
					resource.TestCheckResourceAttr(resourceName, "max_versions", "7"),
					resource.TestCheckResourceAttr(resourceName, "delete_version_after_input", "12h"),
					resource.TestCheckResourceAttr(resourceName, "delete_version_after", "12h0m0s"),
					resource.TestCheckResourceAttr(resourceName, "cas_required", "true"),
				),
			},
		},
	})
}

func testKVSecretBackendV2Config(path string, isUpdate bool) string {
	ret := fmt.Sprintf(`
%s

`, kvV2MountConfig(path))

	if !isUpdate {
		ret += fmt.Sprintf(`
resource "vault_kv_secret_backend_v2" "test" {
  mount                      = vault_mount.kvv2.path
  max_versions               = 5
  delete_version_after_input = "3.5h"
  cas_required               = true
}`)
	} else {
		ret += fmt.Sprintf(`
resource "vault_kv_secret_backend_v2" "test" {
  mount                      = vault_mount.kvv2.path
  max_versions               = 7
  delete_version_after_input = "12h"
  cas_required               = true
}`)
	}
	return ret
}

func kvV2MountConfig(path string) string {
	ret := fmt.Sprintf(`
resource "vault_mount" "kvv2" {
	path        = "%s"
	type        = "kv"
    options     = { version = "2" }
    description = "KV Version 2 secret engine mount"
}`, path)

	return ret
}
