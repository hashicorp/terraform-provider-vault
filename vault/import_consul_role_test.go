package vault

import (
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
)

func TestAccConsulRole_importBasic(t *testing.T) {
	path := acctest.RandomWithPrefix("consul-")
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: testResourceConsulRole_initialConfig(path),
				Check:  testResourceConsulRole_initialCheck(path),
			},
			{
				ResourceName:      "vault_consul_role.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}
