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

func TestAzureAuthBackendRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-azure-backend")
	name := acctest.RandomWithPrefix("tf-test-azure-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAzureAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAzureAuthBackendRoleConfig_basic(backend, name),
				Check:  testAzureAuthBackendRoleCheck_attrs(backend, name),
			},
		},
	})
}

func TestAzureAuthBackendRole(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-azure-backend")
	name := acctest.RandomWithPrefix("tf-test-azure-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAzureAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAzureAuthBackendRoleConfig(backend, name),
				Check: resource.ComposeTestCheckFunc(
					testAzureAuthBackendRoleCheck_attrs(backend, name),
					resource.TestCheckResourceAttr("vault_azure_auth_backend_role.test",
						"token_ttl", "300"),
					resource.TestCheckResourceAttr("vault_azure_auth_backend_role.test",
						"token_max_ttl", "600"),
					resource.TestCheckResourceAttr("vault_azure_auth_backend_role.test",
						"token_policies.#", "2"),
				),
			},
			{
				Config: testAzureAuthBackendRoleUnset(backend, name),
				Check: resource.ComposeTestCheckFunc(
					testAzureAuthBackendRoleCheck_attrs(backend, name),
					resource.TestCheckResourceAttr("vault_azure_auth_backend_role.test",
						"token_ttl", "0"),
					resource.TestCheckResourceAttr("vault_azure_auth_backend_role.test",
						"token_max_ttl", "0"),
					resource.TestCheckResourceAttr("vault_azure_auth_backend_role.test",
						"token_policies.#", "0"),
				),
			},
		},
	})
}

func testAzureAuthBackendRoleDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_azure_auth_backend_role" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Error checking for Azure auth backend role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("Azure auth backend role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAzureAuthBackendRoleCheck_attrs(backend, name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_azure_auth_backend_role.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		endpoint := "auth/" + strings.Trim(backend, "/") + "/role/" + name
		if endpoint != instanceState.ID {
			return fmt.Errorf("expected ID to be %q, got %q instead", endpoint, instanceState.ID)
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

		if "azure" != authMount.Type {
			return fmt.Errorf("incorrect mount type: %s", authMount.Type)
		}

		resp, err := client.Logical().Read(instanceState.ID)
		if err != nil {
			return err
		}

		attrs := map[string]string{
			"type":                        "role_type",
			"token_ttl":                   "token_ttl",
			"token_max_ttl":               "token_max_ttl",
			"token_period":                "token_period",
			"token_policies":              "token_policies",
			"bound_service_principal_ids": "bound_service_principal_ids",
			"bound_group_ids":             "bound_group_ids",
			"bound_locations":             "bound_locations",
			"bound_subscription_ids":      "bound_subscription_ids",
			"bound_resource_groups":       "bound_resource_groups",
			"bound_scale_sets":            "bound_scale_sets",
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
					return fmt.Errorf("Expected API field %s to be an int, was %q", apiAttr, resp.Data[apiAttr])
				}
				stateData, err := strconv.ParseInt(instanceState.Attributes[stateAttr], 10, 64)
				if err != nil {
					return fmt.Errorf("Expected state field %s to be an int, was %q", stateAttr, instanceState.Attributes[stateAttr])
				}
				match = apiData == stateData
			case bool:
				if _, ok := resp.Data[apiAttr]; !ok && instanceState.Attributes[stateAttr] == "" {
					match = true
				} else {
					stateData, err := strconv.ParseBool(instanceState.Attributes[stateAttr])
					if err != nil {
						return fmt.Errorf("Expected state field %s to be a bool, was %q", stateAttr, instanceState.Attributes[stateAttr])
					}
					match = resp.Data[apiAttr] == stateData
				}

			case []interface{}:
				apiData := resp.Data[apiAttr].([]interface{})
				length := instanceState.Attributes[stateAttr+".#"]
				if length == "" {
					if len(resp.Data[apiAttr].([]interface{})) != 0 {
						return fmt.Errorf("Expected state field %s to have %d entries, had 0", stateAttr, len(apiData))
					}
					match = true
				} else {
					count, err := strconv.Atoi(length)
					if err != nil {
						return fmt.Errorf("Expected %s.# to be a number, got %q", stateAttr, instanceState.Attributes[stateAttr+".#"])
					}
					if count != len(apiData) {
						return fmt.Errorf("Expected %s to have %d entries in state, has %d", stateAttr, len(apiData), count)
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
							return fmt.Errorf("Expected item %d of %s (%s in state) of %q to be in state but wasn't", i, apiAttr, stateAttr, endpoint)
						}
					}
					match = true
				}
			default:
				match = resp.Data[apiAttr] == instanceState.Attributes[stateAttr]

			}
			if !match {
				return fmt.Errorf("Expected %s (%s in state) of %q to be %q, got %q", apiAttr, stateAttr, endpoint, instanceState.Attributes[stateAttr], resp.Data[apiAttr])
			}

		}

		return nil
	}
}

func testAzureAuthBackendRoleConfig_basic(backend, name string) string {

	return fmt.Sprintf(`

resource "vault_auth_backend" "azure" {
    path = "%s"
    type = "azure"
}

resource "vault_azure_auth_backend_role" "test" {
    backend                     = vault_auth_backend.azure.path
    role                        = "%s"
    bound_service_principal_ids = ["foo"]
    bound_resource_groups       = ["bar"]
    token_ttl                   = 300
    token_max_ttl               = 600
    token_policies              = ["policy_a", "policy_b"]
}
`, backend, name)

}

func testAzureAuthBackendRoleConfig(backend, name string) string {

	return fmt.Sprintf(`

resource "vault_auth_backend" "azure" {
    path = "%s"
    type = "azure"
}

resource "vault_azure_auth_backend_role" "test" {
    backend                    = vault_auth_backend.azure.path
    role                       = "%s"
    token_ttl                  = 300
    token_max_ttl              = 600
    token_policies             = ["policy_a", "policy_b"]
    bound_locations	           = ["west us"]
    bound_resource_groups      = ["test"]
}
`, backend, name)
}

func testAzureAuthBackendRoleUnset(backend, name string) string {

	return fmt.Sprintf(`

resource "vault_auth_backend" "azure" {
    path = "%s"
    type = "azure"
}

resource "vault_azure_auth_backend_role" "test" {
    backend                    = vault_auth_backend.azure.path
    role                       = "%s"
    bound_locations	           = ["west us"]
    bound_resource_groups      = ["test"]
}
`, backend, name)
}
