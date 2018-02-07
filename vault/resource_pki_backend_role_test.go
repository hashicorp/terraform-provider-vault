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

func TestAccPKIBackendRoleImport(t *testing.T) {
	backend := acctest.RandomWithPrefix("pki")
	role := acctest.RandomWithPrefix("test-role")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckPKIBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPKIBackendRoleConfig(backend, role),
				Check:  testAccPKIBackendRoleCheck_attrs(backend, role),
			},
			{
				ResourceName:      "vault_pki_backend_role.role",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccPKIBackendRole(t *testing.T) {
	backend := acctest.RandomWithPrefix("pki")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckPKIBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPKIBackendRoleConfig(backend, role),
				Check:  testAccPKIBackendRoleCheck_attrs(backend, role),
			},
		},
	})
}

func TestAccPKIBackendRoleUpdate(t *testing.T) {
	backend := acctest.RandomWithPrefix("pki")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckPKIBackendRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPKIBackendRoleConfig(backend, role),
				Check:  testAccPKIBackendRoleCheck_attrs(backend, role),
			},
			{
				Config: testAccPKIBackendRoleConfigUpdate(backend, role),
				Check: resource.ComposeTestCheckFunc(
					testAccPKIBackendRoleCheck_attrs(backend, role),
					resource.TestCheckResourceAttr("vault_pki_backend_role.role",
						"ttl", "48h0m0s"),
					resource.TestCheckResourceAttr("vault_pki_backend_role.role",
						"max_ttl", "72h0m0s"),
					resource.TestCheckResourceAttr("vault_pki_backend_role.role",
						"allow_ip_sans", "false"),
				),
			},
		},
	})
}

func testAccCheckPKIBackendRoleDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_pki_backend_role" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Error checking for PKI backend role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("PKI backend role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccPKIBackendRoleCheck_attrs(backend, role string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_pki_backend_role.role"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		endpoint := instanceState.ID

		if endpoint != backend+"/roles/"+role {
			return fmt.Errorf("expected ID to be %q, got %q instead", backend+"/roles/"+role, endpoint)
		}

		client := testProvider.Meta().(*api.Client)
		resp, err := client.Logical().Read(endpoint)
		if err != nil {
			return fmt.Errorf("%q doesn't exist", endpoint)
		}

		attrs := map[string]string{
			"ttl":     "ttl",
			"max_ttl": "max_ttl",
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

func testAccPKIBackendRoleConfig(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_mount" "pki" {
  type = "pki"
  path = "%s"
}

resource "vault_pki_backend_role" "role" {
  backend = "${vault_mount.pki.path}"
  role = "%s"
}`, backend, role)
}

func testAccPKIBackendRoleConfigUpdate(backend, role string) string {
	return fmt.Sprintf(`
resource "vault_mount" "pki" {
  type = "pki"
  path = "%s"
}

resource "vault_pki_backend_role" "role" {
  backend = "${vault_mount.pki.path}"
  role = "%s"
  ttl = "48h0m0s"
  max_ttl = "72h0m0s"
  allow_localhost = false
  allowed_domains = ["example.com"]
  allow_bare_domains = true
  allow_subdomains = true
  allow_glob_domains = true
  allow_any_name = true
  enforce_hostnames = false
  allow_ip_sans = false
  server_flag = false
  client_flag = false
  code_signing_flag = true
  email_protection_flag = true
  key_type = "ec"
  key_bits = 256
  key_usage = ["DigitalSignature"]
  use_csr_common_name = false
  use_csr_sans = false
  ou = "example ou"
  organization = "example org"
  generate_lease = true
  no_store = true
}`, backend, role)
}
