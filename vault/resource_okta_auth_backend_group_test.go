package vault

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

// This is light on testing as most of the code is covered by `resource_okta_auth_backend_test.go`
func TestAccOktaAuthBackendGroup_basic(t *testing.T) {
	path := "okta-" + strconv.Itoa(acctest.RandInt())
	organization := "dummy"

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccOktaAuthBackendGroup_Destroyed(path, "foo"),
		Steps: []resource.TestStep{
			{
				Config: testAccOktaAuthGroupConfig_basic(path, organization),
				Check: resource.ComposeTestCheckFunc(
					testAccOktaAuthBackendGroup_InitialCheck,
					testAccOktaAuthBackend_GroupsCheck(path, "foo", []string{"one", "two", "default"}),
				),
			},
			{
				ResourceName:      "vault_okta_auth_backend_group.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

/* Test config which contains a special character "/" in the group name */
func TestAccOktaAuthBackendGroup_specialChar(t *testing.T) {
	path := "okta-" + strconv.Itoa(acctest.RandInt())
	organization := "dummy"

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccOktaAuthBackendGroup_Destroyed(path, "foo/bar"),
		Steps: []resource.TestStep{
			{
				Config: testAccOktaAuthGroupConfig_specialChar(path, organization),
				Check: resource.ComposeTestCheckFunc(
					testAccOktaAuthBackendGroup_InitialCheck,
					testAccOktaAuthBackend_GroupsCheck(path, "foo/bar", []string{"one", "two", "default"}),
				),
			},
			{
				ResourceName:      "vault_okta_auth_backend_group.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccOktaAuthGroupConfig_basic(path string, organization string) string {
	return fmt.Sprintf(`
resource "vault_okta_auth_backend" "test" {
    path = "%s"
    organization = "%s"
}

resource "vault_okta_auth_backend_group" "test" {
    path = vault_okta_auth_backend.test.path
    group_name = "foo"
    policies = ["one", "two", "default"]
}
`, path, organization)
}

func testAccOktaAuthGroupConfig_specialChar(path string, organization string) string {
	return fmt.Sprintf(`
resource "vault_okta_auth_backend" "test" {
    path = "%s"
    organization = "%s"
}

resource "vault_okta_auth_backend_group" "test" {
    path = vault_okta_auth_backend.test.path
    group_name = "foo/bar"
    policies = ["one", "two", "default"]
}
`, path, organization)
}

func testAccOktaAuthBackendGroup_InitialCheck(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["vault_okta_auth_backend_group.test"]
	if resourceState == nil {
		return fmt.Errorf("resource not found in state")
	}

	instanceState := resourceState.Primary
	if instanceState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	return nil
}

func testAccOktaAuthBackendGroup_Destroyed(path, groupName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testProvider.Meta().(*api.Client)

		group, err := client.Logical().Read(fmt.Sprintf("/auth/%s/groups/%s", path, groupName))
		if err != nil {
			return fmt.Errorf("error reading back configuration: %s", err)
		}
		if group != nil {
			return fmt.Errorf("okta group still exists")
		}

		return nil
	}
}
