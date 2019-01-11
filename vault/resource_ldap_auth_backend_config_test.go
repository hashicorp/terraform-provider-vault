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

func TestLDAPAuthBackendConfig_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("ldap")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testLDAPAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testLDAPAuthBackendConfigConfig_basic(backend),
				Check:  testLDAPAuthBackendConfigCheck_attrs(backend),
			},
		},
	})
}

func testLDAPAuthBackendConfigDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_ldap_auth_backend_config" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for ldap auth backend config %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("ldap auth backend config %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testLDAPAuthBackendConfigCheck_attrs(backend string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_ldap_auth_backend_config.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
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

		endpoint := strings.Trim(backend, "/")

		resp, err := client.Logical().Read(instanceState.ID)
		if err != nil {
			return err
		}

		// Check that `bindpass`, if present in the state, is not returned by the API
		if instanceState.Attributes["bindpass"] != "" && resp.Data["bindpass"] != nil {
			return fmt.Errorf("expected api field bindpass to not be returned, but was %q", resp.Data["bindpass"])
		}

		attrs := map[string]string{
			"url":             "url",
			"starttls":        "starttls",
			"tls_min_version": "tls_min_version",
			"tls_max_version": "tls_max_version",
			"insecure_tls":    "insecure_tls",
			"certificate":     "certificate",
			"binddn":          "binddn",
			"userdn":          "userdn",
			"userattr":        "userattr",
			"discoverdn":      "discoverdn",
			"deny_null_bind":  "deny_null_bind",
			"upndomain":       "upndomain",
			"groupfilter":     "groupfilter",
			"groupdn":         "groupdn",
			"groupattr":       "groupattr",
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
						stateData := instanceState.Attributes[stateAttr+"."+strconv.Itoa(i)]
						if stateData != apiData[i] {
							return fmt.Errorf("Expected item %d of %s (%s in state) of %q to be %q, got %q", i, apiAttr, stateAttr, endpoint, stateData, apiData[i])
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

func testLDAPAuthBackendConfigConfig_basic(backend string) string {
	return fmt.Sprintf(`
	resource "vault_auth_backend" "ldap" {
		type 				= "ldap"
		path 				= "%s"
		description = "example"
	}

	resource "vault_ldap_auth_backend_config" "test" {
    backend                = "${vault_auth_backend.ldap.path}"
    url                    = "ldaps://example.org"
    starttls               = true
    tls_min_version        = "tls11"
    tls_max_version        = "tls12"
    insecure_tls           = false
    binddn                 = "cn=example.com"
    bindpass               = "supersecurepassword"
    discoverdn             = false
    deny_null_bind         = true
}`, backend)
}
