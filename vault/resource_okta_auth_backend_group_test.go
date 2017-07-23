package vault

import (
	"fmt"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
	"testing"
)

// This is light on testing as most of the code is covered by `resource_okta_auth_backend_test.go`
func TestOktaAuthBackendGroup(t *testing.T) {
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testOktaAuthBackendGroup_Destroyed,
		Steps: []resource.TestStep{
			{
				Config: initialOktaAuthGroupConfig,
				Check:  testOktaAuthBackendGroup_InitialCheck,
			},
		},
	})
}

const initialOktaAuthGroupConfig = `
resource "vault_okta_auth_backend" "test" {
    path = "group_okta"
    organization = "dummy"
}

resource "vault_okta_auth_backend_group" "test" {
    path = "${vault_okta_auth_backend.test.path}"
    group_name = "foo"
    policies = ["one", "two"]
}
`

func testOktaAuthBackendGroup_InitialCheck(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["vault_okta_auth_backend_group.test"]
	if resourceState == nil {
		return fmt.Errorf("resource not found in state")
	}

	instanceState := resourceState.Primary
	if instanceState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	client := testProvider.Meta().(*api.Client)

	group, err := client.Logical().Read("/auth/group_okta/groups/foo")
	if err != nil {
		return fmt.Errorf("error reading back configuration: %s", err)
	}
	err = assertArrayContains([]string{"one", "two", "default"}, toStringArray(group.Data["policies"].([]interface{})))
	if err != nil {
		return err
	}

	return nil
}

func testOktaAuthBackendGroup_Destroyed(state *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	group, err := client.Logical().Read("/auth/group_okta/groups/foo")
	if err != nil {
		return fmt.Errorf("error reading back configuration: %s", err)
	}
	if group != nil {
		return fmt.Errorf("okta group still exists")
	}

	return nil
}
