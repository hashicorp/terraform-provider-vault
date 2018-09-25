package vault

import (
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
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
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "allowed_policies.0", "dev"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "allowed_policies.1", "test"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "disallowed_policies.0", "default"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "orphan", "true"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "period", "86400"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "renewable", "true"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "explicit_max_ttl", "115200"),
					resource.TestCheckResourceAttr("vault_token_auth_backend_role.role", "path_suffix", "parth-suffix"),
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
			"role_name":           "name",
			"allowed_policies":    "allowed_policies",
			"disallowed_policies": "disallowed_policies",
			"orphan":              "orphan",
			"period":              "period",
			"renewable":           "renewable",
			"explicit_max_ttl":    "explicit_max_ttl",
			"path_suffix":         "path_suffix",
			"ttl":                 "ttl",
			"max_ttl":             "max_ttl",
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
						stateData := instanceState.Attributes[stateAttr+"."+strconv.Itoa(i)]
						if stateData != apiData[i] {
							return fmt.Errorf("expected item %d of %s (%s in state) of %q to be %q, got %q", i, apiAttr, stateAttr, endpoint, stateData, apiData[i])
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
  period = "86400"
  renewable = true
  explicit_max_ttl = "115200"
  path_suffix = "parth-suffix"
}`, role)
}
