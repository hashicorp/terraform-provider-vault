package vault

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccPolicy_importBasic(t *testing.T) {
	name := "test-" + acctest.RandString(10)
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: testResourcePolicy_initialConfig(name),
				Check:  testResourcePolicy_initialCheck(name),
			},
			{
				ResourceName:      "vault_policy.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}
