package vault

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccIdentityOidcKey(t *testing.T) {
	key := acctest.RandomWithPrefix("test-key")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckIdentityOidcKeyDestroy,
		Steps: []resource.TestStep{
			{
				// Test a create failure
				Config:      testAccIdentityOidcKeyConfig_bad(key),
				ExpectError: regexp.MustCompile(`unknown signing algorithm "RS123"`),
			},
			{
				Config: testAccIdentityOidcKeyConfig(key),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityOidcKeyCheckAttrs(),
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "name", key),
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "rotation_period", "86400"),
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "verification_ttl", "86400"),
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "algorithm", "RS256"),
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "allowed_client_ids.#", "0"),
				),
			},
			{
				ResourceName:      "vault_identity_oidc_key.key",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccIdentityOidcKeyUpdate(t *testing.T) {
	key := acctest.RandomWithPrefix("test-key")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckIdentityOidcKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityOidcKeyConfig(key),
				Check:  testAccIdentityOidcKeyCheckAttrs(),
			},
			{
				Config: testAccIdentityOidcKeyConfigUpdate(key),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityOidcKeyCheckAttrs(),
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "name", key),
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "rotation_period", "3600"),
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "verification_ttl", "3600"),
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "algorithm", "ES256"),
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "allowed_client_ids.#", "1"),
				),
			},
			{
				Config: testAccIdentityOidcKeyConfig(key),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityOidcKeyCheckAttrs(),
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "name", key),
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "rotation_period", "86400"),
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "verification_ttl", "86400"),
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "algorithm", "RS256"),
					resource.TestCheckResourceAttr("vault_identity_oidc_key.key", "allowed_client_ids.#", "0"),
				),
			},
			{
				// Test an update failure
				Config:      testAccIdentityOidcKeyConfig_bad(key),
				ExpectError: regexp.MustCompile(`unknown signing algorithm "RS123"`),
			},
		},
	})
}

func testAccCheckIdentityOidcKeyDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_identity_oidc_key" {
			continue
		}
		resp, err := identityOidcKeyApiRead(rs.Primary.Attributes["name"], client)

		if err != nil {
			return fmt.Errorf("error checking for identity oidc key %q: %s", rs.Primary.ID, err)
		}
		if resp != nil {
			return fmt.Errorf("identity oidc key %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccIdentityOidcKeyCheckAttrs() resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_identity_oidc_key.key"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		id := instanceState.ID
		path := identityOidcKeyPath(id)
		client := testProvider.Meta().(*api.Client)
		resp, err := identityOidcKeyApiRead(id, client)
		if err != nil {
			return fmt.Errorf("%q doesn't exist", id)
		}

		attrs := map[string]string{
			"rotation_period":    "rotation_period",
			"verification_ttl":   "verification_ttl",
			"algorithm":          "algorithm",
			"allowed_client_ids": "allowed_client_ids",
		}
		for stateAttr, apiAttr := range attrs {
			if resp[apiAttr] == nil && instanceState.Attributes[stateAttr] == "" {
				continue
			}
			var match bool
			switch resp[apiAttr].(type) {
			case json.Number:
				apiData, err := resp[apiAttr].(json.Number).Int64()
				if err != nil {
					return fmt.Errorf("expected API field %s to be an int, was %q", apiAttr, resp[apiAttr])
				}
				stateData, err := strconv.ParseInt(instanceState.Attributes[stateAttr], 10, 64)
				if err != nil {
					return fmt.Errorf("expected state field %s to be an int, was %q", stateAttr, instanceState.Attributes[stateAttr])
				}
				match = apiData == stateData
			case bool:
				if _, ok := resp[apiAttr]; !ok && instanceState.Attributes[stateAttr] == "" {
					match = true
				} else {
					stateData, err := strconv.ParseBool(instanceState.Attributes[stateAttr])
					if err != nil {
						return fmt.Errorf("expected state field %s to be a bool, was %q", stateAttr, instanceState.Attributes[stateAttr])
					}
					match = resp[apiAttr] == stateData
				}
			case []interface{}:
				apiData := resp[apiAttr].([]interface{})
				length := instanceState.Attributes[stateAttr+".#"]
				if length == "" {
					if len(resp[apiAttr].([]interface{})) != 0 {
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
				match = resp[apiAttr] == instanceState.Attributes[stateAttr]
			}
			if !match {
				return fmt.Errorf("expected %s (%s in state) of %q to be %q, got %q", apiAttr, stateAttr, path, instanceState.Attributes[stateAttr], resp[apiAttr])
			}
		}
		return nil
	}
}

func testAccIdentityOidcKeyConfig(entityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "key" {
  name = "%s"
	algorithm = "RS256"

	allowed_client_ids = []
}`, entityName)
}

func testAccIdentityOidcKeyConfig_bad(entityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "key" {
  name = "%s"
	algorithm = "RS123"

	allowed_client_ids = []
}`, entityName)
}

func testAccIdentityOidcKeyConfigUpdate(entityName string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_key" "key" {
  name = "%s"
	algorithm = "ES256"
	rotation_period = 3600
	verification_ttl = 3600

	allowed_client_ids = ["*"]
}`, entityName)
}
