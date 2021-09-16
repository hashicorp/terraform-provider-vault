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
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

func TestLDAPAuthBackendGroup_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-ldap-backend")
	groupname := acctest.RandomWithPrefix("tf-test-ldap-group")

	policies := []string{
		acctest.RandomWithPrefix("policy"),
		acctest.RandomWithPrefix("policy"),
	}

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testLDAPAuthBackendGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: testLDAPAuthBackendGroupConfig_basic(backend, groupname, policies),
				Check:  testLDAPAuthBackendGroupCheck_attrs(backend, groupname),
			},
			{
				ResourceName:      "vault_ldap_auth_backend_group.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestLDAPAuthBackendGroup_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-ldap-backend")
	groupname := acctest.RandomWithPrefix("tf-test-ldap-group")

	policies := []string{
		acctest.RandomWithPrefix("policy"),
		acctest.RandomWithPrefix("policy"),
	}

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testLDAPAuthBackendGroupDestroy,
		Steps: []resource.TestStep{
			{
				Config: testLDAPAuthBackendGroupConfig_basic(backend, groupname, policies),
				Check:  testLDAPAuthBackendGroupCheck_attrs(backend, groupname),
			},
		},
	})
}

func testLDAPAuthBackendGroupDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_ldap_auth_backend_group" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for ldap auth backend group %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("ldap auth backend group %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testLDAPAuthBackendGroupCheck_attrs(backend, groupname string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_ldap_auth_backend_group.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		endpoint := "auth/" + strings.Trim(backend, "/") + "/groups/" + groupname
		if endpoint != instanceState.ID {
			return fmt.Errorf("expected id to be %q, got %q instead", endpoint, instanceState.ID)
		}

		client := testProvider.Meta().(*api.Client)
		authMounts, err := client.Sys().ListAuth()
		if err != nil {
			return err
		}
		authMount := authMounts[strings.Trim(backend, "/")+"/"]

		if authMount == nil {
			return fmt.Errorf("auth mount %s not present", backend)
		}

		if "ldap" != authMount.Type {
			return fmt.Errorf("incorrect mount type: %s", authMount.Type)
		}

		resp, err := client.Logical().Read(instanceState.ID)
		if err != nil {
			return err
		}

		attrs := map[string]string{
			"policies": "policies",
		}

		//return fmt.Errorf("%q", resp.Data)

		for stateAttr, apiAttr := range attrs {
			if resp.Data[apiAttr] == nil && instanceState.Attributes[stateAttr] == "" {
				continue
			}
			var match bool
			switch resp.Data[apiAttr].(type) {
			case json.Number:
				apiData, err := resp.Data[apiAttr].(json.Number).Int64()
				if err != nil {
					return fmt.Errorf("expected api field %s to be an int, was %q", apiAttr, resp.Data[apiAttr])
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
									break
								}
							}
						}
						if !found {
							return fmt.Errorf("expected item %d of %s (%s in state) of %q to be in state but wasn't", i, apiAttr, stateAttr, endpoint)
						}
					}
					match = true
				}
			default:
				match = resp.Data[apiAttr] == instanceState.Attributes[stateAttr]

			}
			if !match {
				return fmt.Errorf("expected %s (%s in state) of %q to be %q, got %q", apiAttr, stateAttr, endpoint, instanceState.Attributes[stateAttr], resp.Data[apiAttr])
			}

		}

		return nil
	}
}

func testLDAPAuthBackendGroupConfig_basic(backend, groupname string, policies []string) string {

	return fmt.Sprintf(`

resource "vault_auth_backend" "ldap" {
    path = "%s"
    type = "ldap"
}

resource "vault_ldap_auth_backend_group" "test" {
    backend   = vault_auth_backend.ldap.path
    groupname = "%s"
    policies  = %s
}
`, backend, groupname, util.ArrayToTerraformList(policies))

}
