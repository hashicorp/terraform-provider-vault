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

func TestDataSourceIdentityEntityName(t *testing.T) {
	entity := acctest.RandomWithPrefix("test-entity")

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceIdentityEntity_configName(entity),
				Check: resource.ComposeTestCheckFunc(
					testDataSourceIdentityEntity_check(),
					resource.TestCheckResourceAttr("data.vault_identity_entity.entity", "entity_name", entity),
					resource.TestCheckResourceAttr("data.vault_identity_entity.entity", "policies.#", "1"),
					resource.TestCheckResourceAttr("data.vault_identity_entity.entity", "metadata.version", "1"),
				),
			},
		},
	})
}

func TestDataSourceIdentityEntityAlias(t *testing.T) {
	entity := acctest.RandomWithPrefix("test-entity")

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceIdentityEntity_configAlias(entity),
				Check: resource.ComposeTestCheckFunc(
					testDataSourceIdentityEntity_check(),
					resource.TestCheckResourceAttr("data.vault_identity_entity.entity", "entity_name", entity),
					resource.TestCheckResourceAttr("data.vault_identity_entity.entity", "policies.#", "1"),
					resource.TestCheckResourceAttr("data.vault_identity_entity.entity", "metadata.version", "1"),
					resource.TestCheckResourceAttr("data.vault_identity_entity.entity", "aliases.#", "1"),
				),
			},
		},
	})
}

func testDataSourceIdentityEntity_check() resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["data.vault_identity_entity.entity"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		id := instanceState.ID
		client := testProvider.Meta().(*api.Client)

		resp, err := identityEntityLookup(client, map[string]interface{}{"id": id})
		if err != nil {
			return err
		}

		attrs := map[string]string{
			"id":          "id",
			"entity_id":   "id",
			"entity_name": "name",
		}
		for _, k := range identityEntityFields {
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

func testDataSourceIdentityEntity_configName(entityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "entity" {
  name = "%s"
  policies = ["test"]
  metadata = {
    version = "1"
  }
}

data "vault_identity_entity" "entity" {
  entity_name = vault_identity_entity.entity.name
}
`, entityName)
}

func testDataSourceIdentityEntity_configAlias(entityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_entity" "entity" {
  name = "%s"
  policies = ["test"]
  metadata = {
    version = "1"
  }
}

resource "vault_auth_backend" "github" {
  type = "github"
  path = "github-%s"
}

resource "vault_identity_entity_alias" "entity_alias" {
  name = "%s"
  mount_accessor = vault_auth_backend.github.accessor
  canonical_id = vault_identity_entity.entity.id
}

data "vault_identity_entity" "entity" {
  alias_name = vault_identity_entity_alias.entity_alias.name
  alias_mount_accessor = vault_identity_entity_alias.entity_alias.mount_accessor
}
`, entityName, entityName, entityName)
}
