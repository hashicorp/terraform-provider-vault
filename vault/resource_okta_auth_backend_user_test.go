// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// This is light on testing as most of the code is covered by `resource_okta_auth_backend_test.go`
func TestAccOktaAuthBackendUser(t *testing.T) {
	t.Parallel()
	path := "okta-" + strconv.Itoa(acctest.RandInt())
	organization := "dummy"
	resourceName := "vault_okta_auth_backend_user.test"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccOktaAuthBackendUser_Destroyed(path, "user_test"),
		Steps: []resource.TestStep{
			{
				Config: testAccOktaAuthUserConfig(path, organization),
				Check: resource.ComposeTestCheckFunc(
					testAccOktaAuthBackendUser_InitialCheck,
					resource.TestCheckResourceAttr(resourceName, "username", "user_test"),
					resource.TestCheckResourceAttr(resourceName, "groups.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "groups.0", "one"),
					resource.TestCheckResourceAttr(resourceName, "groups.1", "two"),
					resource.TestCheckResourceAttr(resourceName, "policies.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "policies.0", "three"),
				),
			},
		},
	})
}

func testAccOktaAuthUserConfig(path string, organization string) string {
	return fmt.Sprintf(`
resource "vault_okta_auth_backend" "test" {
    path = "%s"
    organization = "%s"
}

resource "vault_okta_auth_backend_user" "test" {
    path = vault_okta_auth_backend.test.path
    username = "user_test"
    groups = ["one", "two"]
    policies = ["three"]
}
`, path, organization)
}

func testAccOktaAuthBackendUser_InitialCheck(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["vault_okta_auth_backend_user.test"]
	if resourceState == nil {
		return fmt.Errorf("resource not found in state")
	}

	instanceState := resourceState.Primary
	if instanceState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	return nil
}

func testAccOktaAuthBackendUser_Destroyed(path, userName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

		group, err := client.Logical().Read(fmt.Sprintf("/auth/%s/users/%s", path, userName))
		if err != nil {
			return fmt.Errorf("error reading back configuration: %s", err)
		}
		if group != nil {
			return fmt.Errorf("okta user still exists")
		}

		return nil
	}
}
