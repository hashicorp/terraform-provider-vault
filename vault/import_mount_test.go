package vault

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccMount_importBasic(t *testing.T) {
	path := "test-" + acctest.RandString(10)
	cfg := mountConfig{
		path:      path,
		mountType: "kv",
		version:   "1",
	}
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: testResourceMount_initialConfig(cfg),
				Check:  testResourceMount_initialCheck(cfg),
			},
			{
				ResourceName:      "vault_mount.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}
