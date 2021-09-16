package vault

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
	"strconv"
	"testing"
)

// This is light on testing as most of the code is covered by `resource_okta_auth_backend_test.go`
func TestAccOktaAuthBackendUser(t *testing.T) {
	path := "okta-" + strconv.Itoa(acctest.RandInt())
	organization := "dummy"

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccOktaAuthBackendUser_Destroyed(path, "user_test"),
		Steps: []resource.TestStep{
			{
				Config: testAccOktaAuthUserConfig(path, organization),
				Check: resource.ComposeTestCheckFunc(
					testAccOktaAuthBackendUser_InitialCheck,
					testAccOktaAuthBackend_UsersCheck(path, "user_test", []string{"one", "two"}, []string{"three"}),
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
		client := testProvider.Meta().(*api.Client)

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
