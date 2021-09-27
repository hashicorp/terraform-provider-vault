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

func TestDataSourceIdentityGroupName(t *testing.T) {
	group := acctest.RandomWithPrefix("test-group")

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceIdentityGroup_configName(group),
				Check: resource.ComposeTestCheckFunc(
					testDataSourceIdentityGroup_check("data.vault_identity_group.group_name"),
					resource.TestCheckResourceAttr("data.vault_identity_group.group_name", "group_name", group),
					resource.TestCheckResourceAttr("data.vault_identity_group.group_name", "policies.#", "1"),
					resource.TestCheckResourceAttr("data.vault_identity_group.group_name", "metadata.version", "1"),
				),
			},
		},
	})
}

func TestDataSourceIdentityGroupAlias(t *testing.T) {
	group := acctest.RandomWithPrefix("test-group")

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceIdentityGroup_configAlias(group),
				Check: resource.ComposeTestCheckFunc(
					testDataSourceIdentityGroup_check("data.vault_identity_group.group_alias"),
					resource.TestCheckResourceAttr("data.vault_identity_group.group_alias", "group_name", group),
					resource.TestCheckResourceAttr("data.vault_identity_group.group_alias", "policies.#", "1"),
					resource.TestCheckResourceAttr("data.vault_identity_group.group_alias", "metadata.version", "1"),
					resource.TestCheckResourceAttr("data.vault_identity_group.group_alias", "alias_name", group),
				),
			},
		},
	})
}

func testDataSourceIdentityGroup_check(resource string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources[resource]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		id := instanceState.ID
		client := testProvider.Meta().(*api.Client)

		resp, err := identityGroupLookup(client, map[string]interface{}{"id": id})
		if err != nil {
			return err
		}

		attrs := map[string]string{
			"id":         "id",
			"group_id":   "id",
			"group_name": "name",
		}
		for _, k := range identityGroupFields {
			attrs[k] = k
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
			case map[string]interface{}:
				apiData := resp.Data[apiAttr].(map[string]interface{})
				for k, v := range apiData {
					stateKey := stateAttr + "." + k
					stateData := instanceState.Attributes[stateKey]
					if stateData != v {
						return fmt.Errorf("Expected %s of %s (%s in state) to be %s, but got %s", k, apiAttr, stateKey, v, stateData)
					}
				}
				match = true

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
									break
								}
							}
						}
						if !found {
							return fmt.Errorf("Expected item %d of %s (%s in state) of %q to be in state but wasn't", i, apiAttr, stateAttr, apiData[i])
						}
					}
					match = true
				}
			default:
				match = resp.Data[apiAttr] == instanceState.Attributes[stateAttr]
			}
			if !match {
				return fmt.Errorf("expected %s (%s in state) to be %q, got %q", apiAttr, stateAttr, instanceState.Attributes[stateAttr], resp.Data[apiAttr])
			}
		}
		return nil
	}
}

func testDataSourceIdentityGroup_configName(groupName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
  name = "%s"
  policies = ["test"]
  metadata = {
    version = "1"
  }
}

data "vault_identity_group" "group_name" {
  group_name = vault_identity_group.group.name
}
`, groupName)
}

func testDataSourceIdentityGroup_configAlias(groupName string) string {
	return fmt.Sprintf(`
resource "vault_identity_group" "group" {
  name = "%s"
  type = "external"
  policies = ["test"]
  metadata = {
    version = "1"
  }
}

resource "vault_auth_backend" "github" {
  type = "github"
  path = "github-%s"
}

resource "vault_identity_group_alias" "group_alias" {
  name = "%s"
  mount_accessor = vault_auth_backend.github.accessor
  canonical_id = vault_identity_group.group.id
}

data "vault_identity_group" "group_alias" {
  alias_name = vault_identity_group_alias.group_alias.name
  alias_mount_accessor = vault_identity_group_alias.group_alias.mount_accessor
}
`, groupName, groupName, groupName)
}
