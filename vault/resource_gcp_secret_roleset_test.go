package vault

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
)

// This test requires that you pass credentials for a user or service account having the IAM rights
// listed at https://www.vaultproject.io/docs/secrets/gcp/index.html for the project you are testing
// on. The credentials must also allow setting IAM permissions on the project being tested.
func TestGCPSecretRoleset(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-gcp")
	roleset := acctest.RandomWithPrefix("tf-test")
	credentials, project := getTestGCPCreds(t)

	initialRole := "roles/viewer"
	initialConfig, initialHash := testGCPSecretRoleset_config(backend, roleset, credentials, project, initialRole)

	updatedRole := "roles/browser"
	updatedConfig, updatedHash := testGCPSecretRoleset_config(backend, roleset, credentials, project, updatedRole)

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testGCPSecretRolesetDestroy,
		Steps: []resource.TestStep{
			{
				Config: initialConfig,
				Check: resource.ComposeTestCheckFunc(
					testGCPSecretRoleset_attrs(backend, roleset),
					resource.TestCheckResourceAttr("vault_gcp_secret_backend.test", "path", backend),
					resource.TestCheckResourceAttr("vault_gcp_secret_roleset.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_gcp_secret_roleset.test", "roleset", roleset),
					resource.TestCheckResourceAttr("vault_gcp_secret_roleset.test", "secret_type", "access_token"),
					resource.TestCheckResourceAttr("vault_gcp_secret_roleset.test", "project", project),
					resource.TestCheckResourceAttr("vault_gcp_secret_roleset.test", "token_scopes.#", "1"),
					resource.TestCheckResourceAttr("vault_gcp_secret_roleset.test", "token_scopes.2400041053", "https://www.googleapis.com/auth/cloud-platform"),
					resource.TestCheckResourceAttr("vault_gcp_secret_roleset.test", "binding.#", "1"),
					resource.TestCheckResourceAttr("vault_gcp_secret_roleset.test", fmt.Sprintf("binding.%d.resource", initialHash), fmt.Sprintf("//cloudresourcemanager.googleapis.com/projects/%s", project)),
					resource.TestCheckResourceAttr("vault_gcp_secret_roleset.test", fmt.Sprintf("binding.%d.roles.#", initialHash), "1"),
					resource.TestCheckResourceAttr("vault_gcp_secret_roleset.test", fmt.Sprintf("binding.%d.roles.3993311253", initialHash), initialRole),
				),
			},
			{
				Config: updatedConfig,
				Check: resource.ComposeTestCheckFunc(
					testGCPSecretRoleset_attrs(backend, roleset),
					resource.TestCheckResourceAttr("vault_gcp_secret_backend.test", "path", backend),
					resource.TestCheckResourceAttr("vault_gcp_secret_roleset.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_gcp_secret_roleset.test", "roleset", roleset),
					resource.TestCheckResourceAttr("vault_gcp_secret_roleset.test", "secret_type", "access_token"),
					resource.TestCheckResourceAttr("vault_gcp_secret_roleset.test", "project", project),
					resource.TestCheckResourceAttr("vault_gcp_secret_roleset.test", "token_scopes.#", "1"),
					resource.TestCheckResourceAttr("vault_gcp_secret_roleset.test", "token_scopes.2400041053", "https://www.googleapis.com/auth/cloud-platform"),
					resource.TestCheckResourceAttr("vault_gcp_secret_roleset.test", "binding.#", "1"),
					resource.TestCheckResourceAttr("vault_gcp_secret_roleset.test", fmt.Sprintf("binding.%d.resource", updatedHash), fmt.Sprintf("//cloudresourcemanager.googleapis.com/projects/%s", project)),
					resource.TestCheckResourceAttr("vault_gcp_secret_roleset.test", fmt.Sprintf("binding.%d.roles.#", updatedHash), "1"),
					resource.TestCheckResourceAttr("vault_gcp_secret_roleset.test", fmt.Sprintf("binding.%d.roles.2133424675", updatedHash), updatedRole),
				),
			},
		},
	})
}

func testGCPSecretRoleset_attrs(backend, roleset string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_gcp_secret_roleset.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		endpoint := instanceState.ID

		if endpoint != backend+"/roleset/"+roleset {
			return fmt.Errorf("expected ID to be %q, got %q instead", backend+"/roleset/"+roleset, endpoint)
		}

		client := testProvider.Meta().(*api.Client)
		resp, err := client.Logical().Read(endpoint)
		if err != nil {
			return fmt.Errorf("%q doesn't exist", endpoint)
		}

		attrs := map[string]string{
			"secret_type":           "secret_type",
			"project":               "service_account_project",
			"token_scopes":          "token_scopes",
			"service_account_email": "service_account_email",
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

func testGCPSecretRolesetDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_gcp_secret_roleset" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for GCP Secrets Roleset %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("GCP Secrets Roleset %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testGCPSecretRoleset_config(backend, roleset, credentials, project, role string) (string, int) {
	resource := fmt.Sprintf("//cloudresourcemanager.googleapis.com/projects/%s", project)

	terraform := fmt.Sprintf(`
resource "vault_gcp_secret_backend" "test" {
  path = "%s"
  credentials = "${file("%s")}"
}

resource "vault_gcp_secret_roleset" "test" {
  backend = "${vault_gcp_secret_backend.test.path}"
  roleset = "%s"
  secret_type = "access_token"
  project = "%s"
  token_scopes = ["https://www.googleapis.com/auth/cloud-platform"]

  binding {
	resource = "%s"

	roles = ["%s"]
  }
}
`, backend, credentials, roleset, project, resource, role)

	// Hash the set of bindings
	binding := make(map[string]interface{})
	roles := []interface{}{role}
	binding["resource"] = resource
	binding["roles"] = schema.NewSet(schema.HashString, roles)

	return terraform, gcpSecretRolesetBindingHash(binding)
}
