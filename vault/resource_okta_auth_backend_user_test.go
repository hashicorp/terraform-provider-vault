package vault

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
	"strconv"
	"testing"
)

// This is light on testing as most of the code is covered by `resource_okta_auth_backend_test.go`
func TestOktaAuthBackendUser(t *testing.T) {
	path := "okta-" + strconv.Itoa(acctest.RandInt())

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testOktaAuthBackendUser_Destroyed(path, "user_test"),
		Steps: []resource.TestStep{
			{
				Config: initialOktaAuthUserConfig(path),
				Check: resource.ComposeTestCheckFunc(
					testOktaAuthBackendUser_InitialCheck,
					testOktaAuthBackend_UsersCheck(path, "user_test", []string{"one", "two"}, []string{"three"}),
				),
			},
		},
	})
}

func initialOktaAuthUserConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_okta_auth_backend" "test" {
    path = "%s"
    organization = "dummy"
}

resource "vault_okta_auth_backend_user" "test" {
    path = "${vault_okta_auth_backend.test.path}"
    username = "user_test"
    groups = ["one", "two"]
    policies = ["three"]
}
`, path)
}

func testOktaAuthBackendUser_InitialCheck(s *terraform.State) error {
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

func testOktaAuthBackendUser_Destroyed(path, userName string) resource.TestCheckFunc {
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
