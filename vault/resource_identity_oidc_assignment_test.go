// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccIdentityOIDCAssignment(t *testing.T) {
	var p *schema.Provider
	name := acctest.RandomWithPrefix("test-scope")
	resourceName := "vault_identity_oidc_assignment.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		CheckDestroy:             testAccCheckOIDCAssignmentDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityOIDCAssignmentConfig_empty(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "group_ids.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "entity_ids.#", "0"),
				),
			},
			{
				Config: testAccIdentityOIDCAssignmentConfig_basic(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
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
					resource.TestCheckResourceAttr(resourceName, "name", name),
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

func testAccIdentityOIDCAssignmentConfig_empty(name string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_assignment" "test" {
  name       = "%s"
  group_ids  = []
  entity_ids = []
}`, name)
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
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_identity_oidc_assignment" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
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
