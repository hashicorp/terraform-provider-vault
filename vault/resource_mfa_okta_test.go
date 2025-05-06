// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestMFAOktaBasic(t *testing.T) {
	path := acctest.RandomWithPrefix("mfa-okta")
	resourceName := "vault_mfa_okta.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config: testMFAOktaConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", path),
					resource.TestCheckResourceAttr(resourceName, "username_format", "user@example.com"),
					resource.TestCheckResourceAttr(resourceName, "org_name", "hashicorp"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"api_token"},
			},
		},
	})
}

func testMFAOktaConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = %q
}

resource "vault_mfa_okta" "test" {
  name                  = %q
  mount_accessor        = vault_auth_backend.userpass.accessor
  username_format       = "user@example.com"
  org_name				= "hashicorp"
  api_token				= "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
}
`, acctest.RandomWithPrefix("userpass"), path)
}
