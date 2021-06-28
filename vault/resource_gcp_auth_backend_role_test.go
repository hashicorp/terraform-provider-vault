package vault

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func TestGCPAuthBackend_pathRegex(t *testing.T) {
	tests := map[string]struct {
		path      string
		wantMount string
		wantRole  string
	}{
		"no nesting": {
			path:      "auth/gcp/role/carrot",
			wantMount: "gcp",
			wantRole:  "carrot",
		},
		"nested": {
			path:      "auth/test/usc1/gpc/role/usc1-test-master",
			wantMount: "test/usc1/gpc",
			wantRole:  "usc1-test-master",
		},
		"nested with double 'role'": {
			path:      "auth/gcp/role/role/foo",
			wantMount: "gcp/role",
			wantRole:  "foo",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			mount, err := gcpAuthResourceBackendFromPath(tc.path)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if mount != tc.wantMount {
				t.Fatalf("expected mount %q, got %q", tc.wantMount, mount)
			}

			role, err := gcpAuthResourceRoleFromPath(tc.path)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if role != tc.wantRole {
				t.Fatalf("expected role %q, got %q", tc.wantRole, role)
			}
		})
	}
}

func TestGCPAuthBackendRole_basic(t *testing.T) {
	t.Run("simple backend path", func(t *testing.T) {
		backend := acctest.RandomWithPrefix("tf-test-gcp-backend")
		testGCPAuthBackendRole_basic(t, backend)
	})
	t.Run("nested backend path", func(t *testing.T) {
		backend := acctest.RandomWithPrefix("tf-test-gcp-backend") + "/nested"
		testGCPAuthBackendRole_basic(t, backend)
	})
}

func testGCPAuthBackendRole_basic(t *testing.T, backend string) {
	name := acctest.RandomWithPrefix("tf-test-gcp-role")
	serviceAccount := acctest.RandomWithPrefix("tf-test-gcp-service-account")
	projectId := acctest.RandomWithPrefix("tf-test-gcp-project-id")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testGCPAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testGCPAuthBackendRoleConfig_basic(backend, name, serviceAccount, projectId),
				Check: resource.ComposeTestCheckFunc(
					testGCPAuthBackendRoleCheck_attrs(backend, name),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend_role.test",
						"token_ttl", "300"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend_role.test",
						"token_max_ttl", "600"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend_role.test",
						"token_policies.#", "2"),
				),
			},
			{
				Config: testGCPAuthBackendRoleConfig_unset(backend, name, serviceAccount, projectId),
				Check: resource.ComposeTestCheckFunc(
					testGCPAuthBackendRoleCheck_attrs(backend, name),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend_role.test",
						"token_ttl", "0"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend_role.test",
						"token_max_ttl", "0"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend_role.test",
						"token_policies.#", "0"),
				),
			},
			{
				ResourceName:      "vault_gcp_auth_backend_role.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestGCPAuthBackendRole_gce(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-gcp-backend")
	name := acctest.RandomWithPrefix("tf-test-gcp-role")
	projectId := acctest.RandomWithPrefix("tf-test-gcp-project-id")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testGCPAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testGCPAuthBackendRoleConfig_gce(backend, name, projectId),
				Check: resource.ComposeTestCheckFunc(
					testGCPAuthBackendRoleCheck_attrs(backend, name),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend_role.test",
						"bound_labels.#", "2"),
				),
			},
		},
	})
}

func TestGCPAuthBackendRole_deprecated(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-gcp-backend")
	name := acctest.RandomWithPrefix("tf-test-gcp-role")
	serviceAccount := acctest.RandomWithPrefix("tf-test-gcp-service-account")
	projectId := acctest.RandomWithPrefix("tf-test-gcp-project-id")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testGCPAuthBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testGCPAuthBackendRoleConfig_deprecated(backend, name, serviceAccount, projectId),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("vault_gcp_auth_backend_role.test",
						"policies.#", "2"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend_role.test",
						"ttl", "300"),
					resource.TestCheckResourceAttr("vault_gcp_auth_backend_role.test",
						"max_ttl", "600"),
				),
			},
		},
	})
}

func testGCPAuthBackendRoleDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_gcp_auth_backend_role" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Error checking for GCP auth backend role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("GCP auth backend role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testGCPAuthBackendRoleCheck_attrs(backend, name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_gcp_auth_backend_role.test"]
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

		if "gcp" != authMount.Type {
			return fmt.Errorf("incorrect mount type: %s", authMount.Type)
		}

		resp, err := client.Logical().Read(instanceState.ID)
		if err != nil {
			return err
		}

		attrs := map[string]string{
			"type":                   "type",
			"bound_projects":         "bound_projects",
			"token_ttl":              "token_ttl",
			"token_max_ttl":          "token_max_ttl",
			"token_period":           "token_period",
			"token_policies":         "token_policies",
			"bound_service_accounts": "bound_service_accounts",
			"bound_regions":          "bound_regions",
			"bound_zones":            "bound_zones",
			"bound_labels":           "bound_labels",
			"add_group_aliases":      "add_group_aliases",
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
			case map[string]interface{}:
				apiData := resp.Data[apiAttr].(map[string]interface{})
				length := instanceState.Attributes[stateAttr+".#"]
				if length == "" {
					if len(resp.Data[apiAttr].(map[string]interface{})) != 0 {
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

					for respKey, respValue := range apiData {
						found := false
						for stateKey, stateValue := range instanceState.Attributes {
							if strings.HasPrefix(stateKey, stateAttr) {
								val := respValue

								// We send a list to Vault and it returns a map. To ensure
								// the response from Vault and the state file are equal,
								// we need to prepare a string "key:value" for comparison.
								if apiAttr == "bound_labels" {
									val = fmt.Sprintf("%s:%s", respKey, respValue)
								}

								if val == stateValue {
									found = true
								}
							}
						}
						if !found {
							return fmt.Errorf("Expected item %s of %s (%s in state) of %q to be in state but wasn't", respKey, apiAttr, stateAttr, endpoint)
						}
					}
					match = true
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

func testGCPAuthBackendRoleConfig_basic(backend, name, serviceAccount, projectId string) string {

	return fmt.Sprintf(`

resource "vault_auth_backend" "gcp" {
    path = "%s"
    type = "gcp"
}

resource "vault_gcp_auth_backend_role" "test" {
    backend                = "${vault_auth_backend.gcp.path}"
    role                   = "%s"
    type                   = "iam"
    bound_service_accounts = ["%s"]
    bound_projects         = ["%s"]
    token_ttl              = 300
    token_max_ttl          = 600
    token_policies         = ["policy_a", "policy_b"]
    add_group_aliases      = true
}
`, backend, name, serviceAccount, projectId)

}

func testGCPAuthBackendRoleConfig_unset(backend, name, serviceAccount, projectId string) string {

	return fmt.Sprintf(`

resource "vault_auth_backend" "gcp" {
    path = "%s"
    type = "gcp"
}

resource "vault_gcp_auth_backend_role" "test" {
    backend                = "${vault_auth_backend.gcp.path}"
    role                   = "%s"
    type                   = "iam"
    bound_service_accounts = ["%s"]
    bound_projects         = ["%s"]
    add_group_aliases      = true
}
`, backend, name, serviceAccount, projectId)

}

func testGCPAuthBackendRoleConfig_gce(backend, name, projectId string) string {

	return fmt.Sprintf(`

resource "vault_auth_backend" "gcp" {
    path = "%s"
    type = "gcp"
}

resource "vault_gcp_auth_backend_role" "test" {
    backend                = "${vault_auth_backend.gcp.path}"
    role                   = "%s"
    type                   = "gce"
    bound_projects         = ["%s"]
    token_ttl              = 300
    token_max_ttl          = 600
    token_policies         = ["policy_a", "policy_b"]
    bound_regions          = ["eu-west2"]
    bound_zones            = ["europe-west2-c"]
    bound_labels           = ["foo:bar", "key:value"]
}
`, backend, name, projectId)

}

func testGCPAuthBackendRoleConfig_deprecated(backend, name, serviceAccount, projectId string) string {

	return fmt.Sprintf(`

resource "vault_auth_backend" "gcp" {
    path = "%s"
    type = "gcp"
}

resource "vault_gcp_auth_backend_role" "test" {
    backend                = "${vault_auth_backend.gcp.path}"
    role                   = "%s"
    type                   = "iam"
    bound_service_accounts = ["%s"]
    bound_projects         = ["%s"]
    ttl                    = 300
    max_ttl                = 600
    policies               = ["policy_a", "policy_b"]
    add_group_aliases      = true
}
`, backend, name, serviceAccount, projectId)

}
