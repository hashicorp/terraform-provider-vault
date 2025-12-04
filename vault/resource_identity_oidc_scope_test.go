// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const (
	basicScope   = `{"groups":"{{identity.entity.groups.names}}"}`
	updatedScope = `{"groups":"{{identity.entity.groups.names}}","username":"{{identity.entity.groups.names}}"}`
)

func TestAccIdentityOIDCScope(t *testing.T) {
	name := acctest.RandomWithPrefix("test-scope")
	resourceName := "vault_identity_oidc_scope.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckOIDCScopeDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityOIDCScopeConfig_basic(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "description", "test scope"),
					resource.TestCheckResourceAttr(resourceName, "template", basicScope),
				),
			},
			{
				Config: testAccIdentityOIDCScopeConfig_update(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "description", "test scope updated description"),
					resource.TestCheckResourceAttr(resourceName, "template", updatedScope),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccIdentityOIDCScopeConfig_basic(scope string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_scope" "test" {
  name        = "%s"
  template    = jsonencode(
    {
      groups   = "{{identity.entity.groups.names}}"
    }
  )
  description = "test scope"
}`, scope)
}

func testAccIdentityOIDCScopeConfig_update(scope string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_scope" "test" {
  name        = "%s"
  template    = jsonencode(
    {
      groups   = "{{identity.entity.groups.names}}",
      username = "{{identity.entity.groups.names}}"
    }
  )
  description = "test scope updated description"
}`, scope)
}

func testAccCheckOIDCScopeDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_identity_oidc_scope" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		resp, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for OIDC scope at %s, err=%w", rs.Primary.ID, err)
		}
		if resp != nil {
			return fmt.Errorf("OIDC scope still exists at %s", rs.Primary.ID)
		}
	}
	return nil
}
