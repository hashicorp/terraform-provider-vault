package vault

import (
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccAWSAuthBackendIdentityWhitelist_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAWSAuthBackendIdentityWhitelistDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendIdentityWhitelistConfig_basic(backend),
				Check:  testAccAWSAuthBackendIdentityWhitelistCheck_attrs(backend),
			},
			{
				ResourceName:      "vault_aws_auth_backend_identity_whitelist.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAWSAuthBackendIdentityWhitelist_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("aws")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAWSAuthBackendIdentityWhitelistDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSAuthBackendIdentityWhitelistConfig_basic(backend),
				Check:  testAccAWSAuthBackendIdentityWhitelistCheck_attrs(backend),
			},
		},
	})
}

func testAccCheckAWSAuthBackendIdentityWhitelistDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_aws_auth_backend_identity_whitelist" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for AWS Auth Backend identity whitelist %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("AWS auth backend identity whitelist %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccAWSAuthBackendIdentityWhitelistConfig_basic(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "aws" {
  path = "%s"
  type = "aws"
}

resource "vault_aws_auth_backend_identity_whitelist" "test" {
  backend = vault_auth_backend.aws.path
  safety_buffer = 8600
  disable_periodic_tidy = true
}`, backend)
}

func testAccAWSAuthBackendIdentityWhitelistCheck_attrs(backend string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_aws_auth_backend_identity_whitelist.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		endpoint := instanceState.ID

		if endpoint != "auth/"+backend+"/config/tidy/identity-whitelist" {
			return fmt.Errorf("expected ID to be %q, got %q", "auth/"+backend+"/config/tidy/identity-whitelist", endpoint)
		}

		client := testProvider.Meta().(*api.Client)
		resp, err := client.Logical().Read(endpoint)
		if err != nil {
			return fmt.Errorf("error reading back AWS auth bavkend identity whitelist config from %q: %s", endpoint, err)
		}
		if resp == nil {
			return fmt.Errorf("AWS auth backend identity whitelist not configured at %q", endpoint)
		}

		var respBuffer int64
		var respDisable bool
		if v, ok := resp.Data["safety_buffer"]; ok {
			vint, err := v.(json.Number).Int64()
			if err != nil {
				return fmt.Errorf("expected safety_buffer to be an int, was %q", v)
			}
			respBuffer = vint
		}

		stateBuffer, err := strconv.ParseInt(instanceState.Attributes["safety_buffer"], 10, 64)
		if err != nil {
			return fmt.Errorf("expected safety_buffer to be an int, was %q in state", instanceState.Attributes["safety_buffer"])
		}

		if v, ok := resp.Data["disable_periodic_tidy"]; ok {
			respDisable = v.(bool)
		}

		stateDisable, err := strconv.ParseBool(instanceState.Attributes["disable_periodic_tidy"])
		if err != nil {
			return fmt.Errorf("expected disable_periodic_tidy to be a bool, was %q in state", instanceState.Attributes["disable_periodic_tidy"])
		}

		if respBuffer != stateBuffer {
			return fmt.Errorf("expected safety_buffer of %q to be %q, got %q", endpoint, stateBuffer, respBuffer)
		}

		if respDisable != stateDisable {
			return fmt.Errorf("expected disable_periodic_tidy of %q to be %q, got %q", endpoint, stateBuffer, respBuffer)
		}
		return nil
	}
}
