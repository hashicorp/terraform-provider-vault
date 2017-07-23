package vault

import (
	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
	"testing"
	"time"
)

func TestOktaAuthBackend(t *testing.T) {
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testOktaAuthBackend_Destroyed,
		Steps: []resource.TestStep{
			{
				Config: initialOktaAuthConfig,
				Check:  testOktaAuthBackend_InitialCheck,
			},
			{
				Config: updatedOktaAuthConfig,
				Check:  testOktaAuthBackend_UpdatedCheck,
			},
		},
	})
}

var initialOktaAuthConfig = `
resource "vault_okta_auth_backend" "test" {
    description = "Testing the Terraform okta auth backend"
    organization = "example"
    token = "this must be kept secret"
    ttl = "1h"
    group {
        group_name = "dummy"
        policies = ["one", "two"]
    }
    user {
        username = "foo"
        groups = ["dummy"]
    }
}
`

func testOktaAuthBackend_InitialCheck(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["vault_okta_auth_backend.test"]
	if resourceState == nil {
		return fmt.Errorf("resource not found in state")
	}

	instanceState := resourceState.Primary
	if instanceState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	path := instanceState.ID

	if path != instanceState.Attributes["path"] {
		return fmt.Errorf("id doesn't match path")
	}

	client := testProvider.Meta().(*api.Client)

	authMounts, err := client.Sys().ListAuth()
	if err != nil {
		return err
	}

	authMount := authMounts[path+"/"]

	if authMount == nil {
		return fmt.Errorf("Auth mount %s not present", path)
	}

	err = assertEquals("okta", authMount.Type)
	if err != nil {
		return err
	}

	err = assertEquals("Testing the Terraform okta auth backend", authMount.Description)
	if err != nil {
		return err
	}

	config, err := client.Logical().Read("/auth/okta/config")
	if err != nil {
		return fmt.Errorf("error reading back configuration: %s", err)
	}

	err = assertEquals("example", config.Data["organization"])
	if err != nil {
		return err
	}

	ttl, err := config.Data["ttl"].(json.Number).Int64()
	if err != nil {
		return err
	}
	err = assertEquals((time.Hour * 1).Nanoseconds(), ttl)
	if err != nil {
		return err
	}

	groupList, err := client.Logical().List("/auth/okta/groups")
	if err != nil {
		return fmt.Errorf("error reading back configuration: %s", err)
	}

	if len(groupList.Data["keys"].([]interface{})) != 1 {
		return fmt.Errorf("Unexpected groups present: %v", groupList.Data)
	}

	dummyGroup, err := client.Logical().Read("/auth/okta/groups/dummy")
	if err != nil {
		return fmt.Errorf("error reading back configuration: %s", err)
	}
	err = assertArrayContains([]string{"one", "two", "default"}, toStringArray(dummyGroup.Data["policies"].([]interface{})))
	if err != nil {
		return err
	}

	userList, err := client.Logical().List("/auth/okta/users")
	if err != nil {
		return fmt.Errorf("error reading back configuration: %s", err)
	}

	if len(userList.Data["keys"].([]interface{})) != 1 {
		return fmt.Errorf("Unexpected users present: %v", userList.Data)
	}

	user, err := client.Logical().Read("/auth/okta/users/foo")
	if err != nil {
		return fmt.Errorf("error reading back configuration: %s", err)
	}
	err = assertArrayContains([]string{"dummy"}, toStringArray(user.Data["groups"].([]interface{})))
	if err != nil {
		return err
	}
	err = assertArrayContains([]string{""}, toStringArray(user.Data["policies"].([]interface{})))
	if err != nil {
		return err
	}

	return nil
}

var updatedOktaAuthConfig = `
resource "vault_okta_auth_backend" "test" {
    description = "Testing the Terraform okta auth backend"
    organization = "example"
    token = "this must be kept secret"
    group {
        group_name = "example"
        policies = ["three", "four"]
    }
    user {
        username = "bar"
        groups = ["example"]
    }
}
`

func testOktaAuthBackend_UpdatedCheck(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	groupList, err := client.Logical().List("/auth/okta/groups")
	if err != nil {
		return fmt.Errorf("error reading back configuration: %s", err)
	}

	if len(groupList.Data["keys"].([]interface{})) != 1 {
		return fmt.Errorf("Unexpected groups present: %v", groupList.Data)
	}

	dummyGroup, err := client.Logical().Read("/auth/okta/groups/example")
	if err != nil {
		return fmt.Errorf("error reading back configuration: %s", err)
	}
	err = assertArrayContains([]string{"three", "four", "default"}, toStringArray(dummyGroup.Data["policies"].([]interface{})))
	if err != nil {
		return err
	}

	userList, err := client.Logical().List("/auth/okta/users")
	if err != nil {
		return fmt.Errorf("error reading back configuration: %s", err)
	}

	if len(userList.Data["keys"].([]interface{})) != 1 {
		return fmt.Errorf("Unexpected users present: %v", userList.Data)
	}

	user, err := client.Logical().Read("/auth/okta/users/bar")
	if err != nil {
		return fmt.Errorf("error reading back configuration: %s", err)
	}
	err = assertArrayContains([]string{"example"}, toStringArray(user.Data["groups"].([]interface{})))
	if err != nil {
		return err
	}

	err = assertArrayContains([]string{""}, toStringArray(user.Data["policies"].([]interface{})))
	if err != nil {
		return err
	}

	return nil
}

func testOktaAuthBackend_Destroyed(state *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	authMounts, err := client.Sys().ListAuth()
	if err != nil {
		return err
	}

	if _, ok := authMounts["okta/"]; ok {
		return fmt.Errorf("Auth mount not destroyed")
	}

	return nil
}

func assertEquals(expected, actual interface{}) error {
	if expected != actual {
		return fmt.Errorf("Value incorrect; expected %[1]v, actual %[2]v (types: %[1]T, %[2]T)", expected, actual)
	}

	return nil
}

func assertArrayContains(expected, actual []string) error {
	var missing []interface{}

EXPECTED:
	for _, i := range expected {
		for _, j := range actual {
			if i == j {
				continue EXPECTED
			}
		}

		missing = append(missing, i)
	}

	if len(missing) != 0 {
		return fmt.Errorf("Value incorrect; expected %[1]v, actual %[2]v (types: %[1]T, %[2]T)", expected, actual)
	}

	return nil
}
