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

func TestAccTokenAuthBackendRoleImport(t *testing.T) {
	role := acctest.RandomWithPrefix("test-role")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckTokenAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccTokenAuthBackendRoleConfig(role),
				Check:  testAccTokenAuthBackendRoleCheck_attrs(role),
			},
			{
				ResourceName:      "vault_token_auth_backend_role.role",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccTokenAuthBackendRole(t *testing.T) {
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckTokenAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccTokenAuthBackendRoleConfig(role),
				Check:  testAccTokenAuthBackendRoleCheck_attrs(role),
			},
		},
	})
}

func TestAccTokenAuthBackendRoleUpdate(t *testing.T) {
	role := acctest.RandomWithPrefix("test-role")
	roleUpdated := acctest.RandomWithPrefix("test-role-updated")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckTokenAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccTokenAuthBackendRoleConfig(role),
				Check:  testAccTokenAuthBackendRoleCheck_attrs(role),
			},
			{
				Config: testAccTokenAuthBackendRoleConfigUpdate(role),
				Check: resource.ComposeTestCheckFunc(
					testAccTokenAuthBackendRoleCheck_attrs(role),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "role_name", role),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "allowed_policies.#", "2"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "allowed_policies.0", "dev"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "allowed_policies.1", "test"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "disallowed_policies.#", "1"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "disallowed_policies.0", "default"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "orphan", "true"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "token_period", "86400"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "renewable", "false"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "token_explicit_max_ttl", "115200"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "path_suffix", "parth-suffix"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "token_bound_cidrs.#", "1"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "token_bound_cidrs.0", "0.0.0.0/0"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "token_type", "default-batch"),
				),
			},
			{
				Config: testAccTokenAuthBackendRoleConfigUpdate(roleUpdated),
				Check: resource.ComposeTestCheckFunc(
					testAccTokenAuthBackendRoleCheck_attrs(roleUpdated),
					testAccTokenAuthBackendRoleCheck_deleted(role),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "role_name", roleUpdated),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "allowed_policies.#", "2"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "allowed_policies.0", "dev"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "allowed_policies.1", "test"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "disallowed_policies.#", "1"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "disallowed_policies.0", "default"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "orphan", "true"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "token_period", "86400"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "renewable", "false"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "token_explicit_max_ttl", "115200"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "path_suffix", "parth-suffix"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "token_bound_cidrs.#", "1"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "token_bound_cidrs.0", "0.0.0.0/0"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "token_type", "default-batch"),
				),
			},
			{
				Config: testAccTokenAuthBackendRoleConfig(roleUpdated),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccTokenAuthBackendRoleCheck_attrs(roleUpdated),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "role_name", roleUpdated),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "allowed_policies.#", "0"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "disallowed_policies.#", "0"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "orphan", "false"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "token_period", "0"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "renewable", "true"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "token_explicit_max_ttl", "0"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "path_suffix", ""),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "token_bound_cidrs.#", "0"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "token_type", "default-service"),
				),
			},
		},
	})
}

func testAccCheckTokenAuthBackendRoleDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_token_auth_backend_role" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for Token auth backend role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("token auth backend role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccTokenAuthBackendRoleCheck_deleted(role string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		endpoint := "auth/token/roles"
		client := testProvider.Meta().(*api.Client)

		resp, err := client.Logical().List(endpoint)

		if err != nil {
			return fmt.Errorf("%q returned unexpectedly", endpoint)
		}

		apiData := resp.Data["keys"].([]interface{})
		for _, r := range apiData {
			if r == role {
				return fmt.Errorf("%q still exists, extected to be deleted", role)
			}
		}
		return nil
	}
}

func testAccTokenAuthBackendRoleCheck_attrs(role string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_token_auth_backend_role.role"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		endpoint := instanceState.ID

		if endpoint != "auth/token/roles/"+role {
			return fmt.Errorf("expected ID to be %q, got %q instead", "auth/token/roles/"+role, endpoint)
		}

		client := testProvider.Meta().(*api.Client)
		resp, err := client.Logical().Read(endpoint)
		if err != nil {
			return fmt.Errorf("%q doesn't exist", endpoint)
		}

		attrs := map[string]string{
			"role_name":              "name",
			"allowed_policies":       "allowed_policies",
			"disallowed_policies":    "disallowed_policies",
			"orphan":                 "orphan",
			"token_period":           "token_period",
			"token_explicit_max_ttl": "token_explicit_max_ttl",
			"path_suffix":            "path_suffix",
			"renewable":              "renewable",
			"token_bound_cidrs":      "token_bound_cidrs",
			"token_type":             "token_type",
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
							return fmt.Errorf("Expected item %d of %s (%s in state) of %q to be in state but wasn't", i, apiAttr, stateAttr, apiData[i])
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

func testAccTokenAuthBackendRoleConfig(roleName string) string {
	return fmt.Sprintf(`
resource "vault_token_auth_backend_role" "role" {
  role_name = "%s"
}`, roleName)
}

func testAccTokenAuthBackendRoleConfigUpdate(role string) string {
	return fmt.Sprintf(`
resource "vault_token_auth_backend_role" "role" {
  role_name = "%s"
  allowed_policies = ["dev", "test"]
  disallowed_policies = ["default"]
  orphan = true
  token_period = "86400"
  renewable = false
  token_explicit_max_ttl = "115200"
  path_suffix = "parth-suffix"
  token_bound_cidrs = ["0.0.0.0/0"]
	token_type = "default-batch"
}`, role)
}
