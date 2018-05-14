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

func TestPKIRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki-backend")
	name := acctest.RandomWithPrefix("tf-test-pki-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testPKIRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPKIRoleConfig_basic(backend, name),
				Check:  testPKIRoleCheck_attrs(backend, name),
			},
		},
	})
}

func testPKIRoleDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_pki_role" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Error checking for PKI role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("PKI role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testPKIRoleCheck_attrs(backend, name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_pki_role.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		endpoint := strings.Trim(backend, "/") + "/roles/" + name
		if endpoint != instanceState.ID {
			return fmt.Errorf("expected ID to be %q, got %q instead", endpoint, instanceState.ID)
		}

		client := testProvider.Meta().(*api.Client)
		mounts, err := client.Sys().ListMounts()
		if err != nil {
			return err
		}
		mount := mounts[strings.Trim(backend, "/")+"/"]

		if mount == nil {
			return fmt.Errorf("auth mount %s not present", backend)
		}

		if "pki" != mount.Type {
			return fmt.Errorf("incorrect mount type: %s", mount.Type)
		}

		resp, err := client.Logical().Read(instanceState.ID)
		if err != nil {
			return err
		}

		attrs := map[string]string{
			"ttl":                   "ttl",
			"max_ttl":               "max_ttl",
			"allow_localhost":       "allow_localhost",
			"allowed_domains":       "allowed_domains",
			"allow_bare_domains":    "allow_bare_domains",
			"allow_subdomains":      "allow_subdomains",
			"allow_glob_domains":    "allow_glob_domains",
			"allow_any_name":        "allow_any_name",
			"enforce_hostnames":     "enforce_hostnames",
			"allow_ip_sans":         "allow_ip_sans",
			"server_flag":           "server_flag",
			"client_flag":           "client_flag",
			"code_signing_flag":     "code_signing_flag",
			"email_protection_flag": "email_protection_flag",
			"key_type":              "key_type",
			"key_bits":              "key_bits",
			"key_usage":             "key_usage",
			"use_csr_common_name":   "use_csr_common_name",
			"use_csr_sans":          "use_csr_sans",
			"ou":                    "ou",
			"organization":          "organization",
			"generate_lease":        "generate_lease",
			"no_store":              "no_store",
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
				return fmt.Errorf("Expected %s (%s in state) of %q to be %q, got %q", apiAttr, stateAttr, endpoint, instanceState.Attributes[stateAttr], resp.Data[apiAttr])
			}

		}

		return nil
	}
}

func testPKIRoleConfig_basic(backend, name string) string {

	return fmt.Sprintf(`

resource "vault_mount" "pki" {
    path = "%s"
    type = "pki"
}

resource "vault_pki_role" "test" {
    backend                = "${vault_mount.pki.path}"
    role                   = "%s"
    server_flag            = true
    client_flag            = false
    allow_subdomains       = true
    allowed_domains        = ["example-a.com", "example-b.com"]
    key_bits               = 4096
}
`, backend, name)

}
