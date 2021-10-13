package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAlicloudAuthBackendRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-alicloud-backend")
	name := acctest.RandomWithPrefix("tf-test-alicloud-role")
	arn := acctest.RandomWithPrefix("acs:ram:123456:tf:role/")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAlicloudAuthBackedRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAlicloudAuthBackedRoleConfig_basic(backend, name, arn),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_alicloud_auth_backend_role.test",
						"arn", arn),
					resource.TestCheckResourceAttr("vault_alicloud_auth_backend_role.test",
						"role", name),
				),
			},
			{
				Config: testAlicloudAuthBackedRoleConfig_basic(backend, name+"updated", arn+"updated"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_alicloud_auth_backend_role.test",
						"arn", arn+"updated"),
					resource.TestCheckResourceAttr("vault_alicloud_auth_backend_role.test",
						"role", name+"updated"),
				),
			},
			{
				ResourceName:      "vault_alicloud_auth_backend_role.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAlicloudAuthBackedRoleDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_alicloud_auth_backend_role" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Error checking for AliCloud Auth Backend role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("AliCloud Auth Backend role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAlicloudAuthBackedRoleConfig_basic(backend, name, arn string) string {

	return fmt.Sprintf(`

resource "vault_auth_backend" "alicloud" {
    path = "%s"
    type = "alicloud"
}

resource "vault_alicloud_auth_backend_role" "test" {
    backend = vault_auth_backend.alicloud.path
    role = "%s"
    arn = "%s"

}
`, backend, name, arn)
}
