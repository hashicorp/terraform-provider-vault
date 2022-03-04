package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccIdentityOIDCAssignment(t *testing.T) {
	name := acctest.RandomWithPrefix("test-scope")
	resourceName := "vault_identity_oidc_assignment.test"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckOIDCAssignmentDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityOIDCAssignmentConfig_basic(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "group_ids.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "group_ids.0", "gid-1"),
					resource.TestCheckResourceAttr(resourceName, "group_ids.1", "gid-2"),
					resource.TestCheckResourceAttr(resourceName, "entity_ids.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "entity_ids.0", "eid-1"),
					resource.TestCheckResourceAttr(resourceName, "entity_ids.1", "eid-2"),
				),
			},
			{
				Config: testAccIdentityOIDCAssignmentConfig_update(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "group_ids.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "group_ids.0", "gid-1"),
					resource.TestCheckResourceAttr(resourceName, "group_ids.1", "gid-2"),
					resource.TestCheckResourceAttr(resourceName, "group_ids.2", "gid-3"),
					resource.TestCheckResourceAttr(resourceName, "entity_ids.#", "4"),
					resource.TestCheckResourceAttr(resourceName, "entity_ids.0", "eid-1"),
					resource.TestCheckResourceAttr(resourceName, "entity_ids.1", "eid-2"),
					resource.TestCheckResourceAttr(resourceName, "entity_ids.2", "eid-3"),
					resource.TestCheckResourceAttr(resourceName, "entity_ids.3", "eid-4"),
				),
			},
		},
	})
}

func testAccIdentityOIDCAssignmentConfig_basic(name string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_assignment" "test" {
  name       = "%s"
  group_ids  = ["gid-1", "gid-2"]
  entity_ids = ["eid-1", "eid-2"]
}`, name)
}

func testAccIdentityOIDCAssignmentConfig_update(name string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_assignment" "test" {
  name       = "%s"
  group_ids  = ["gid-1", "gid-2", "gid-3"]
  entity_ids = ["eid-1", "eid-2", "eid-3", "eid-4"]
}`, name)
}

func testAccCheckOIDCAssignmentDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_identity_oidc_assignment" {
			continue
		}
		resp, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for OIDC assignment at %s, err=%w", rs.Primary.ID, err)
		}
		if resp != nil {
			return fmt.Errorf("OIDC assignment still exists at %s", rs.Primary.ID)
		}
	}
	return nil
}
