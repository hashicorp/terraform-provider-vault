package vault

import (
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
)

func TestAccMount_importBasic(t *testing.T) {
	path := "test-" + acctest.RandString(10)
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: testResourceMount_initialConfig(path),
				Check:  testResourceMount_initialCheck(path),
			},
			{
				ResourceName:      "vault_mount.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}
