package vault

import (
	"fmt"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
	"testing"
)

// This is light on testing as most of the code is covered by `resource_okta_auth_backend_test.go`
func TestOktaAuthBackendUser(t *testing.T) {
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testOktaAuthBackendUser_Destroyed,
		Steps: []resource.TestStep{
			{
				Config: initialOktaAuthUserConfig,
				Check:  testOktaAuthBackendUser_InitialCheck,
			},
		},
	})
}

var initialOktaAuthUserConfig = `
resource "vault_okta_auth_backend" "test" {
    path = "user_okta"
    organization = "dummy"
}

resource "vault_okta_auth_backend_user" "test" {
    path = "${vault_okta_auth_backend.test.path}"
    username = "user_test"
    groups = ["one", "two"]
    policies = ["three"]
}
`

func testOktaAuthBackendUser_InitialCheck(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["vault_okta_auth_backend_user.test"]
	if resourceState == nil {
		return fmt.Errorf("resource not found in state")
	}

	instanceState := resourceState.Primary
	if instanceState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	client := testProvider.Meta().(*api.Client)

	user, err := client.Logical().Read("/auth/user_okta/users/user_test")
	if err != nil {
		return fmt.Errorf("error reading back configuration: %s", err)
	}

	err = assertArrayContains([]string{"one", "two"}, toStringArray(user.Data["groups"].([]interface{})))
	if err != nil {
		return err
	}

	err = assertArrayContains([]string{"three"}, toStringArray(user.Data["policies"].([]interface{})))
	if err != nil {
		return err
	}

	return nil
}

func testOktaAuthBackendUser_Destroyed(state *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	group, err := client.Logical().Read("/auth/user_okta/users/user_test")
	if err != nil {
		return fmt.Errorf("error reading back configuration: %s", err)
	}
	if group != nil {
		return fmt.Errorf("okta user still exists")
	}

	return nil
}
