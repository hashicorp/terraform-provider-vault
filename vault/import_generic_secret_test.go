package vault

import (
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
)

func TestAccGenericSecret_importBasic(t *testing.T) {
	path := acctest.RandomWithPrefix("secret/test-")
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericSecret_initialConfig(path),
				Check:  testResourceGenericSecret_initialCheck(path),
			},
			{
				ResourceName:      "vault_generic_secret.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}
