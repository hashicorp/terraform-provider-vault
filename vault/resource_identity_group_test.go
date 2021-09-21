package vault

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccIdentityGroup(t *testing.T) {
	group := acctest.RandomWithPrefix("test-group")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckIdentityGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityGroupConfig(group),
				Check:  testAccIdentityGroupCheckAttrs(),
			},
		},
	})
}

func TestAccIdentityGroupUpdate(t *testing.T) {
	group := acctest.RandomWithPrefix("test-group")
	entity := acctest.RandomWithPrefix("test-entity")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckIdentityGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityGroupConfig(group),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityGroupCheckAttrs(),
					resource.TestCheckResourceAttr("vault_identity_group.group", "type", "external"),
					resource.TestCheckResourceAttr("vault_identity_group.group", "policies.#", "1"),
					resource.TestCheckResourceAttr("vault_identity_group.group", "policies.0", "test"),
					resource.TestCheckResourceAttr("vault_identity_group.group", "metadata.version", "1"),
				),
			},
			{
				Config: testAccIdentityGroupConfigUpdate(group),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityGroupCheckAttrs(),
					resource.TestCheckResourceAttr("vault_identity_group.group", "name", fmt.Sprintf("%s-2", group)),
					resource.TestCheckResourceAttr("vault_identity_group.group", "type", "internal"),
					resource.TestCheckResourceAttr("vault_identity_group.group", "metadata.version", "2"),
					resource.TestCheckResourceAttr("vault_identity_group.group", "policies.#", "2"),
					resource.TestCheckResourceAttr("vault_identity_group.group", "policies.0", "dev"),
					resource.TestCheckResourceAttr("vault_identity_group.group", "policies.1", "test"),
					resource.TestCheckResourceAttr("vault_identity_group.group", "member_entity_ids.#", "0"),
					resource.TestCheckResourceAttr("vault_identity_group.group", "member_group_ids.#", "0"),
				),
			},
			{
				Config: testAccIdentityGroupConfigUpdateRemovePolicies(group),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityGroupCheckAttrs(),
					resource.TestCheckResourceAttr("vault_identity_group.group", "type", "internal"),
					resource.TestCheckResourceAttr("vault_identity_group.group", "policies.#", "0"),
				),
			},
			{
				Config: testAccIdentityGroupConfigUpdateMembers(group, entity),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityGroupCheckAttrs(),
					resource.TestCheckResourceAttr("vault_identity_group.group", "type", "internal"),
					resource.TestCheckResourceAttr("vault_identity_group.group", "policies.#", "2"),
					resource.TestCheckResourceAttr("vault_identity_group.group", "policies.0", "dev"),
					resource.TestCheckResourceAttr("vault_identity_group.group", "policies.1", "test"),
					resource.TestCheckResourceAttr("vault_identity_group.group", "member_entity_ids.#", "1"),
					resource.TestCheckResourceAttr("vault_identity_group.group", "member_group_ids.#", "1"),
				),
			},
			{
				Config: testAccIdentityGroupConfigExternalMembers(group),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityGroupCheckAttrs(),
					resource.TestCheckResourceAttr("vault_identity_group.group", "type", "external"),
					resource.TestCheckResourceAttr("vault_identity_group.group", "policies.#", "1"),
					resource.TestCheckResourceAttr("vault_identity_group.group", "member_entity_ids.#", "0"),
					resource.TestCheckResourceAttr("vault_identity_group.group", "member_group_ids.#", "0"),
				),
			},
		},
	})
}

func TestAccIdentityGroupExternal(t *testing.T) {
	group := acctest.RandomWithPrefix("test-group")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckIdentityGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityGroupConfig(group),
				Check:  testAccIdentityGroupCheckAttrs(),
			},
		},
	})
}

func testAccCheckIdentityGroupDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_identity_group" {
			continue
		}
		secret, err := client.Logical().Read(identityGroupIDPath(rs.Primary.ID))
		if err != nil {
			return fmt.Errorf("error checking for identity group %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("identity group role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccIdentityGroupCheckAttrs() resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_identity_group.group"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		id := instanceState.ID

		path := identityGroupIDPath(id)
		client := testProvider.Meta().(*api.Client)
		resp, err := client.Logical().Read(path)
		if err != nil {
			return fmt.Errorf("%q doesn't exist", path)
		}

		attrs := map[string]string{
			"name":     "name",
			"policies": "policies",
			"type":     "type",
		}
		for stateAttr, apiAttr := range attrs {
			if resp.Data[apiAttr] == nil && instanceState.Attributes[stateAttr] == "" {
				continue
			}
			var match bool
			switch resp.Data[apiAttr].(type) {
			case json.Number:
				apiData, err := resp.Data[apiAttr].(json.Number).Int64()
				if err != nil {
					return fmt.Errorf("expected API field %s to be an int, was %q", apiAttr, resp.Data[apiAttr])
				}
				stateData, err := strconv.ParseInt(instanceState.Attributes[stateAttr], 10, 64)
				if err != nil {
					return fmt.Errorf("expected state field %s to be an int, was %q", stateAttr, instanceState.Attributes[stateAttr])
				}
				match = apiData == stateData
			case bool:
				if _, ok := resp.Data[apiAttr]; !ok && instanceState.Attributes[stateAttr] == "" {
					match = true
				} else {
					stateData, err := strconv.ParseBool(instanceState.Attributes[stateAttr])
					if err != nil {
						return fmt.Errorf("expected state field %s to be a bool, was %q", stateAttr, instanceState.Attributes[stateAttr])
					}
					match = resp.Data[apiAttr] == stateData
				}
			case []interface{}:
				apiData := resp.Data[apiAttr].([]interface{})
				length := instanceState.Attributes[stateAttr+".#"]
				if length == "" {
					if len(resp.Data[apiAttr].([]interface{})) != 0 {
						return fmt.Errorf("expected state field %s to have %d entries, had 0", stateAttr, len(apiData))
					}
					match = true
				} else {
					count, err := strconv.Atoi(length)
					if err != nil {
						return fmt.Errorf("expected %s.# to be a number, got %q", stateAttr, instanceState.Attributes[stateAttr+".#"])
					}
					if count != len(apiData) {
						return fmt.Errorf("expected %s to have %d entries in state, has %d", stateAttr, len(apiData), count)
					}

					for i := 0; i < count; i++ {
						found := false
						for stateKey, stateValue := range instanceState.Attributes {
							if strings.HasPrefix(stateKey, stateAttr) {
								if apiData[i] == stateValue {
									found = true
								}
							}
						}
						if !found {
							return fmt.Errorf("expected item %d of %s (%s in state) of %q to be in state but wasn't", i, apiAttr, stateAttr, apiData[i])
						}
					}
					match = true
				}
			default:
				match = resp.Data[apiAttr] == instanceState.Attributes[stateAttr]
			}
			if !match {
				return fmt.Errorf("expected %s (%s in state) of %q to be %q, got %q", apiAttr, stateAttr, path, instanceState.Attributes[stateAttr], resp.Data[apiAttr])
			}
		}
		return nil
	}
}

func testAccIdentityGroupConfig(groupName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
  name = "%s"
  type = "external"
  policies = ["test"]
  metadata = {
    version = "1"
  }
}`, groupName)
}

func testAccIdentityGroupConfigUpdate(groupName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
  name = "%s-2"
  type = "internal"
  policies = ["dev", "test"]
  metadata = {
    version = "2"
  }
}`, groupName)
}

func testAccIdentityGroupConfigUpdateRemovePolicies(groupName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
  name = "%s-2"
  type = "internal"
  policies = []
  metadata = {
    version = "2"
  }
}`, groupName)
}

func testAccIdentityGroupConfigUpdateMembers(groupName string, entityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
  name = "%s"
  type = "internal"
  policies = ["dev", "test"]
  metadata = {
    version = "2"
  }

  member_entity_ids = [vault_identity_entity.entity.id]
  member_group_ids = [vault_identity_group.other_group.id]
}

resource "vault_identity_entity" "entity" {
  name = "%s"
  policies = ["dev", "test"]
  metadata = {
    version = "2"
  }
}

resource "vault_identity_group" "other_group" {
  name = "other_%s"
}
`, groupName, entityName, groupName)
}

func testAccIdentityGroupConfigExternalMembers(groupName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
  name = "%s"
  type = "external"
  policies = ["test"]
  metadata = {
    version = "1"
  }

  member_entity_ids = ["member entities can't be set for external groups"]
  member_group_ids = ["member groups can't be set for external groups"]
}`, groupName)
}
