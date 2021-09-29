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

const testAccIdentityOidcRoleTemplate = `{
  "name": {{identity.entity.name}}
}`

func TestAccIdentityOidcRole(t *testing.T) {
	name := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckIdentityOidcRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityOidcRoleConfig(name),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityOidcRoleCheckAttrs(),
					resource.TestCheckResourceAttr("vault_identity_oidc_role.role", "name", name),
					resource.TestCheckResourceAttr("vault_identity_oidc_role.role", "key", name),
					resource.TestCheckResourceAttr("vault_identity_oidc_role.role", "template", ""),
					resource.TestCheckResourceAttr("vault_identity_oidc_role.role", "ttl", "86400"),
				),
			},
			{
				ResourceName:      "vault_identity_oidc_role.role",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccIdentityOidcRoleWithClientId(t *testing.T) {
	name := acctest.RandomWithPrefix("test-role")
	clientId := acctest.RandomWithPrefix("test-client-id")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckIdentityOidcRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityOidcRoleWithClientIdConfig(name, clientId),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityOidcRoleCheckAttrs(),
					resource.TestCheckResourceAttr("vault_identity_oidc_role.role", "name", name),
					resource.TestCheckResourceAttr("vault_identity_oidc_role.role", "key", name),
					resource.TestCheckResourceAttr("vault_identity_oidc_role.role", "template", ""),
					resource.TestCheckResourceAttr("vault_identity_oidc_role.role", "client_id", clientId),
					resource.TestCheckResourceAttr("vault_identity_oidc_role.role", "ttl", "86400"),
				),
			},
			{
				ResourceName:      "vault_identity_oidc_role.role",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccIdentityOidcRoleUpdate(t *testing.T) {
	name := acctest.RandomWithPrefix("test-role")
	clientId := acctest.RandomWithPrefix("test-client-id")
	updateClientId := acctest.RandomWithPrefix("test-update-client-id")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckIdentityOidcRoleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityOidcRoleWithClientIdConfig(name, clientId),
				Check:  testAccIdentityOidcRoleCheckAttrs(),
			},
			{
				Config: testAccIdentityOidcRoleConfigUpdate(name, updateClientId),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityOidcRoleCheckAttrs(),
					resource.TestCheckResourceAttr("vault_identity_oidc_role.role", "name", name),
					resource.TestCheckResourceAttr("vault_identity_oidc_role.role", "key", name),
					resource.TestCheckResourceAttr("vault_identity_oidc_role.role", "template", fmt.Sprintf("%s\n", testAccIdentityOidcRoleTemplate)),
					resource.TestCheckResourceAttr("vault_identity_oidc_role.role", "client_id", updateClientId),
					resource.TestCheckResourceAttr("vault_identity_oidc_role.role", "ttl", "3600"),
				),
			},
			{
				Config: testAccIdentityOidcRoleWithClientIdConfig(name, clientId),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityOidcRoleCheckAttrs(),
					resource.TestCheckResourceAttr("vault_identity_oidc_role.role", "name", name),
					resource.TestCheckResourceAttr("vault_identity_oidc_role.role", "key", name),
					resource.TestCheckResourceAttr("vault_identity_oidc_role.role", "template", ""),
					resource.TestCheckResourceAttr("vault_identity_oidc_role.role", "client_id", clientId),
					resource.TestCheckResourceAttr("vault_identity_oidc_role.role", "ttl", "86400"),
				),
			},
		},
	})
}

func testAccCheckIdentityOidcRoleDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_identity_oidc_role" {
			continue
		}
		secret, err := client.Logical().Read(identityOidcRolePath(rs.Primary.ID))
		if err != nil {
			return fmt.Errorf("error checking for identity oidc role %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("identity oidc role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccIdentityOidcRoleCheckAttrs() resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_identity_oidc_role.role"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		id := instanceState.ID

		path := identityOidcRolePath(id)
		client := testProvider.Meta().(*api.Client)
		resp, err := client.Logical().Read(path)
		if err != nil {
			return fmt.Errorf("%q doesn't exist", path)
		}

		attrs := map[string]string{
			"key":       "key",
			"template":  "template",
			"ttl":       "ttl",
			"client_id": "client_id",
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
									break
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
				return fmt.Errorf("expected %s (%s in state) of %q to be %q, got %q", apiAttr, stateAttr, path, instanceState.Attributes[stateAttr], resp.Data[apiAttr])
			}
		}
		return nil
	}
}

func testAccIdentityOidcRoleConfig(entityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "key" {
  name = "%s"
  algorithm = "RS256"
}

resource "vault_identity_oidc_role" "role" {
	name = "%s"
	key = vault_identity_oidc_key.key.name
}
`, entityName, entityName)
}

func testAccIdentityOidcRoleWithClientIdConfig(entityName string, clientId string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "key" {
  name = "%s"
  algorithm = "RS256"
}

resource "vault_identity_oidc_role" "role" {
	name = "%s"
	key = vault_identity_oidc_key.key.name
  client_id = "%s"
}
`, entityName, entityName, clientId)
}

func testAccIdentityOidcRoleConfigUpdate(entityName string, clientId string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "key" {
  name = "%s"
  algorithm = "RS256"
}

resource "vault_identity_oidc_role" "role" {
	name = "%s"
	key = vault_identity_oidc_key.key.name
  client_id = "%s"

	template = <<EOF
%s
EOF
	ttl = 3600
}`, entityName, entityName, clientId, testAccIdentityOidcRoleTemplate)
}
