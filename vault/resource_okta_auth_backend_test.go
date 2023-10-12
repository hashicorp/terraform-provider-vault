// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func TestAccOktaAuthBackend_basic(t *testing.T) {
	t.Parallel()
	organization := "example"
	path := resource.PrefixedUniqueId("okta-basic-")

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccOktaAuthBackend_Destroyed(path),
		Steps: []resource.TestStep{
			{
				Config: testAccOktaAuthConfig_basic(path, organization),
				Check: resource.ComposeTestCheckFunc(
					testAccOktaAuthBackend_InitialCheck,
					testAccOktaAuthBackend_GroupsCheck(path, "dummy", []string{"one", "two", "default"}),
					testAccOktaAuthBackend_UsersCheck(path, "foo", []string{"dummy"}, []string{}),
				),
			},
			{
				Config: testAccOktaAuthConfig_updated(path, organization),
				Check: resource.ComposeTestCheckFunc(
					testAccOktaAuthBackend_GroupsCheck(path, "example", []string{"three", "four", "default"}),
					testAccOktaAuthBackend_UsersCheck(path, "bar", []string{"example"}, []string{}),
				),
			},
		},
	})
}

func TestAccOktaAuthBackend_import(t *testing.T) {
	t.Parallel()
	organization := "example"
	path := resource.PrefixedUniqueId("okta-import-")

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccOktaAuthBackend_Destroyed(path),
		Steps: []resource.TestStep{
			{
				Config: testAccOktaAuthConfig_basic(path, organization),
				Check: resource.ComposeTestCheckFunc(
					testAccOktaAuthBackend_InitialCheck,
					testAccOktaAuthBackend_GroupsCheck(path, "dummy", []string{"one", "two", "default"}),
					testAccOktaAuthBackend_UsersCheck(path, "foo", []string{"dummy"}, []string{}),
				),
			},
			{
				ResourceName:      "vault_okta_auth_backend.test",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"token",
					"disable_remount",
				},
			},
			{
				Config: testAccOktaAuthConfig_updated(path, organization),
				Check: resource.ComposeTestCheckFunc(
					testAccOktaAuthBackend_GroupsCheck(path, "example", []string{"three", "four", "default"}),
					testAccOktaAuthBackend_UsersCheck(path, "bar", []string{"example"}, []string{}),
				),
			},
			{
				ResourceName:      "vault_okta_auth_backend.test",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"token",
					"disable_remount",
				},
			},
		},
	})
}

func TestAccOktaAuthBackend_invalid_ttl(t *testing.T) {
	t.Parallel()
	organization := "example"
	path := resource.PrefixedUniqueId("okta-invalid-ttl-")

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccOktaAuthBackend_Destroyed(path),
		Steps: []resource.TestStep{
			{
				Config:      testAccOktaAuthConfig_invalid_ttl(path, organization),
				ExpectError: regexp.MustCompile(`Error: invalid value for "ttl", could not parse "invalid_ttl"`),
			},
		},
	})
}

func TestAccOktaAuthBackend_invalid_max_ttl(t *testing.T) {
	t.Parallel()
	organization := "example"
	path := resource.PrefixedUniqueId("okta-invalid_max_ttl-")

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccOktaAuthBackend_Destroyed(path),
		Steps: []resource.TestStep{
			{
				Config:      testAccOktaAuthConfig_invalid_max_ttl(path, organization),
				ExpectError: regexp.MustCompile(`Error: invalid value for "max_ttl", could not parse "invalid_max_ttl"`),
			},
		},
	})
}

func TestAccOktaAuthBackend_groups_optional(t *testing.T) {
	t.Parallel()
	organization := "example"
	path := resource.PrefixedUniqueId("okta-group-optional")

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		ProviderFactories: providerFactories,
		CheckDestroy:      testAccOktaAuthBackend_Destroyed(path),
		Steps: []resource.TestStep{
			{
				Config: testAccOktaAuthConfig_groups_optional(path, organization),
				Check: resource.ComposeTestCheckFunc(
					testAccOktaAuthBackend_UsersCheck(path, "bar", []string{}, []string{"eng", "default"}),
				),
			},
		},
	})
}

func TestAccOktaAuthBackend_remount(t *testing.T) {
	t.Parallel()
	path := acctest.RandomWithPrefix("tf-test-auth-okta")
	updatedPath := acctest.RandomWithPrefix("tf-test-auth-okta-updated")

	organization := "example"
	resourceName := "vault_okta_auth_backend.test"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccOktaAuthConfig_basic(path, organization),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					testAccOktaAuthBackend_InitialCheck,
				),
			},
			{
				Config: testAccOktaAuthConfig_basic(updatedPath, organization),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", updatedPath),
					testAccOktaAuthBackend_InitialCheck,
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "token", "disable_remount"),
		},
	})
}

func testAccOktaAuthConfig_basic(path string, organization string) string {
	return fmt.Sprintf(`
resource "vault_okta_auth_backend" "test" {
    description = "Testing the Terraform okta auth backend"
    path = "%s"
    organization = "%s"
    token = "this must be kept secret"
    ttl = "1h"
    group {
        group_name = "dummy"
        policies = ["one", "two", "default"]
    }
    user {
        username = "foo"
        groups = ["dummy"]
    }
}
`, path, organization)
}

func testAccOktaAuthConfig_updated(path string, organization string) string {
	return fmt.Sprintf(`
resource "vault_okta_auth_backend" "test" {
    description = "Testing the Terraform okta auth backend"
    path = "%s"
    organization = "%s"
    token = "this must be kept secret"
    group {
        group_name = "example"
        policies = ["three", "four", "default"]
    }
    user {
        username = "bar"
        groups = ["example"]
    }
}
`, path, organization)
}

func testAccOktaAuthConfig_invalid_ttl(path string, organization string) string {
	return fmt.Sprintf(`
resource "vault_okta_auth_backend" "test" {
    description = "Testing the Terraform okta auth backend"
    path = "%s"
    organization = "%s"
    token = "this must be kept secret"
    ttl = "invalid_ttl"
    max_ttl = "1h"
}
`, path, organization)
}

func testAccOktaAuthConfig_invalid_max_ttl(path string, organization string) string {
	return fmt.Sprintf(`
resource "vault_okta_auth_backend" "test" {
    description = "Testing the Terraform okta auth backend"
    path = "%s"
    organization = "%s"
    token = "this must be kept secret"
    ttl = "1h"
    max_ttl = "invalid_max_ttl"
}
`, path, organization)
}

func testAccOktaAuthConfig_groups_optional(path string, organization string) string {
	return fmt.Sprintf(`
resource "vault_okta_auth_backend" "test" {
    description = "Testing the Terraform okta auth backend"
    path = "%s"
    organization = "%s"
    token = "this must be kept secret"
    user {
        username = "bar"
        policies   = ["eng", "default"]
    }
}
`, path, organization)
}

func testAccOktaAuthBackend_InitialCheck(s *terraform.State) error {
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

	client, e := provider.GetClient(instanceState, testProvider.Meta())
	if e != nil {
		return e
	}

	authMounts, err := client.Sys().ListAuth()
	if err != nil {
		return err
	}

	authMount := authMounts[path+"/"]

	if authMount == nil {
		return fmt.Errorf("auth mount %s not present", path)
	}

	if "okta" != authMount.Type {
		return fmt.Errorf("incorrect mount type: %s", authMount.Type)
	}

	if "Testing the Terraform okta auth backend" != authMount.Description {
		return fmt.Errorf("incorrect description: %s", authMount.Description)
	}

	config, err := client.Logical().Read(fmt.Sprintf("/auth/%s/config", path))
	if err != nil {
		return fmt.Errorf("error reading back configuration: %s", err)
	}

	if "example" != config.Data["organization"] {
		return fmt.Errorf("incorrect organization: %s", config.Data["organization"])
	}

	ttl, err := config.Data["ttl"].(json.Number).Int64()
	if err != nil {
		return err
	}

	if int64((time.Hour * 1).Seconds()) != ttl {
		return fmt.Errorf("incorrect ttl: %s", config.Data["ttl"])
	}

	if instanceState.Attributes["accessor"] != authMount.Accessor {
		return fmt.Errorf("incorrect accessor: %s", instanceState.Attributes["accessor"])
	}

	return nil
}

func testAccOktaAuthBackend_GroupsCheck(path, groupName string, expectedPolicies []string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testProvider.Meta().(*provider.ProviderMeta).GetClient()

		groupList, err := client.Logical().List(fmt.Sprintf("/auth/%s/groups", path))
		if err != nil {
			return fmt.Errorf("error reading back group configuration: %s", err)
		}

		if len(groupList.Data["keys"].([]interface{})) != 1 {
			return fmt.Errorf("unexpected groups present: %v", groupList.Data)
		}

		dummyGroup, err := client.Logical().Read(fmt.Sprintf("/auth/%s/groups/%s", path, groupName))
		if err != nil {
			return fmt.Errorf("error reading back configuration: %s", err)
		}

		var missing []interface{}

		actual := util.ToStringArray(dummyGroup.Data["policies"].([]interface{}))
	EXPECTED:
		for _, i := range expectedPolicies {
			for _, j := range actual {
				if i == j {
					continue EXPECTED
				}
			}

			missing = append(missing, i)
		}

		if len(missing) != 0 {
			return fmt.Errorf("group policies incorrect; expected %[1]v, actual %[2]v (types: %[1]T, %[2]T)", expectedPolicies, actual)
		}

		return nil
	}
}

func testAccOktaAuthBackend_UsersCheck(path, userName string, expectedGroups, expectedPolicies []string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testProvider.Meta().(*provider.ProviderMeta).GetClient()

		userList, err := client.Logical().List(fmt.Sprintf("/auth/%s/users", path))
		if err != nil {
			return fmt.Errorf("error reading back configuration: %s", err)
		}

		if len(userList.Data["keys"].([]interface{})) != 1 {
			return fmt.Errorf("unexpected users present: %v", userList.Data)
		}

		user, err := client.Logical().Read(fmt.Sprintf("/auth/%s/users/%s", path, userName))
		if err != nil {
			return fmt.Errorf("error reading back configuration: %s", err)
		}

		var missing []interface{}

		actual := util.ToStringArray(user.Data["policies"].([]interface{}))
		if len(expectedPolicies) != len(actual) {
			return fmt.Errorf("expected %d policies, got %d", len(expectedPolicies), len(actual))
		}
	EXPECTED_POLICIES:
		for _, i := range expectedPolicies {
			for _, j := range actual {
				if i == j {
					continue EXPECTED_POLICIES
				}
			}

			missing = append(missing, i)
		}

		if len(missing) != 0 {
			return fmt.Errorf("user policies incorrect; expected %[1]v (len: %[3]d), actual %[2]v (len: %[4]d) (types: %[1]T, %[2]T)", expectedPolicies, actual, len(expectedPolicies), len(actual))
		}

		actual = util.ToStringArray(user.Data["groups"].([]interface{}))

		if len(expectedGroups) != len(actual) {
			return fmt.Errorf("expected %d groups, got %d", len(expectedGroups), len(actual))
		}
	EXPECTED_GROUPS:
		for _, i := range expectedGroups {
			for _, j := range actual {
				if i == j {
					continue EXPECTED_GROUPS
				}
			}

			missing = append(missing, i)
		}

		if len(missing) != 0 {
			return fmt.Errorf("user groups incorrect; expected %[1]v, actual %[2]v (types: %[1]T, %[2]T)", expectedGroups, actual)
		}

		return nil
	}
}

func testAccOktaAuthBackend_Destroyed(path string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testProvider.Meta().(*provider.ProviderMeta).GetClient()

		authMounts, err := client.Sys().ListAuth()
		if err != nil {
			return err
		}

		if _, ok := authMounts[fmt.Sprintf("%s/", path)]; ok {
			return fmt.Errorf("auth mount not destroyed")
		}

		return nil
	}
}
