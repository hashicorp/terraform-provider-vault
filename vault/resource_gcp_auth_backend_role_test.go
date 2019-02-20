package vault

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
)

func TestGCPAuthBackendRole_basic(t *testing.T) {
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
				Config: testGCPAuthBackendRoleConfig_basic(backend, name, serviceAccount, projectId),
				Check:  testGCPAuthBackendRoleCheck_attrs(backend, name),
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
				Check:  testGCPAuthBackendRoleCheck_attrs(backend, name),
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
			"bound_projects":         "project_id",
			"ttl":                    "ttl",
			"max_ttl":                "max_ttl",
			"period":                 "period",
			"policies":               "policies",
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
    project_id             = "%s"
    ttl                    = 300
    max_ttl                = 600
    policies               = ["policy_a", "policy_b"]
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
    project_id             = "%s"
    ttl                    = 300
    max_ttl                = 600
    policies               = ["policy_a", "policy_b"]
    bound_regions          = ["eu-west2"]
    bound_zones            = ["europe-west2-c"]
    bound_labels           = ["foo"]
}
`, backend, name, projectId)

}
