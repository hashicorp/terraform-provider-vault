package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func TestResourceGenericEndpoint(t *testing.T) {
	path := acctest.RandomWithPrefix("userpass")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testResourceGenericEndpoint_destroyCheck(path),
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericEndpoint_initialConfig(path),
				Check:  testResourceGenericEndpoint_initialCheck,
			},
		},
	})
}

func testResourceGenericEndpoint_initialConfig(path string) string {
	return fmt.Sprintf(`
variable "up_path" {
  default = "%s"
}

resource "vault_policy" "p1" {
  name = "p1"

  policy = <<EOT
path "secret/data/p1" {
  capabilities = ["read"]
}
EOT
}

# This resource does not have disable_delete and will not get deleted
# automatically because of being inside something else that's getting
# deleted. This is how we verify deletion of resources with
# disable_delete = false.
resource "vault_generic_endpoint" "up1" {
  path         = "sys/auth/${var.up_path}-1"
  disable_read = true

  data_json = <<EOT
{
  "type": "userpass"
}
EOT
}

# This one does not get deleted. We delete it manually. This is to
# test the test logic. If this one sticks around but up1 is gone,
# we know disable_delete is doing what it's supposed to and that
# we are correctly exercising this in the tests.
resource "vault_generic_endpoint" "up2" {
  path           = "sys/auth/${var.up_path}-2"
  disable_read   = true
  disable_delete = true

  data_json = <<EOT
{
  "type": "userpass"
}
EOT
}

resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = var.up_path
}

resource "vault_generic_endpoint" "u1" {
  depends_on           = ["vault_auth_backend.userpass"]
  path                 = "auth/${var.up_path}/users/u1"
  ignore_absent_fields = true

  data_json = <<EOT
{
  "policies": ["p1"],
  "password": "something"
}
EOT
}

resource "vault_generic_endpoint" "u1_token" {
  depends_on     = ["vault_generic_endpoint.u1"]
  path           = "auth/${var.up_path}/login/u1"
  disable_read   = true
  disable_delete = true

  data_json = <<EOT
{
  "password": "something"
}
EOT
}

resource "vault_generic_endpoint" "u1_entity" {
  depends_on           = ["vault_generic_endpoint.u1_token"]
  disable_read         = true
  disable_delete       = true
  path                 = "identity/lookup/entity"
  ignore_absent_fields = true
  write_fields         = ["id"]

  data_json = <<EOT
{
  "alias_name": "u1",
  "alias_mount_accessor": "${vault_auth_backend.userpass.accessor}"
}
EOT
}
`, path)
}

func testResourceGenericEndpoint_initialCheck(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["vault_generic_endpoint.u1_entity"]
	if resourceState == nil {
		return fmt.Errorf("resource vault_generic_endpoint.u1_entity not found in state")
	}

	instanceState := resourceState.Primary
	if instanceState == nil {
		return fmt.Errorf("resource vault_generic_endpoint.u1_entity has no primary instance")
	}

	path := instanceState.ID

	if path != instanceState.Attributes["path"] {
		return fmt.Errorf("id doesn't match path")
	}
	if path != "identity/lookup/entity" {
		return fmt.Errorf("unexpected secret path")
	}

	write_data_count := instanceState.Attributes["write_data.%"]
	if write_data_count != "1" {
		return fmt.Errorf("write_data.%% has value %q, not 1", write_data_count)
	}

	write_data_id := instanceState.Attributes["write_data.id"]
	if write_data_id == "" {
		return fmt.Errorf("write_data.id not found in state (%q)", instanceState.Attributes)
	}

	resourceState = s.Modules[0].Resources["vault_generic_endpoint.u1_token"]
	if resourceState == nil {
		return fmt.Errorf("resource vault_generic_endpoint.u1_token not found in state")
	}

	instanceState = resourceState.Primary
	if instanceState == nil {
		return fmt.Errorf("resource vault_generic_endpoint.u1_token has no primary instance")
	}

	write_data_count = instanceState.Attributes["write_data.%"]
	if write_data_count != "0" {
		return fmt.Errorf("write_data.%% has value %q, not 0", write_data_count)
	}

	return nil
}

func testResourceGenericEndpoint_destroyCheck(path string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testProvider.Meta().(*api.Client)

		for _, rs := range s.RootModule().Resources {
			if rs.Type != "vault_generic_endpoint" {
				continue
			}
			instanceState := rs.Primary
			// Check to make sure resources that we can read are no longer
			// there.
			if instanceState.Attributes["disable_read"] != "true" {
				data, err := client.Logical().Read(rs.Primary.ID)
				if err != nil {
					return fmt.Errorf("error checking for vault generic endpoint %q: %s", rs.Primary.ID, err)
				}
				if data != nil {
					return fmt.Errorf("generic endpoint %q still exists", rs.Primary.ID)
				}
			}
		}

		data, err := client.Logical().Read("sys/auth")
		if err != nil {
			return fmt.Errorf("error reading for sys/auth: %s", err)
		}
		if _, ok := data.Data[path+"-1/"]; ok {
			return fmt.Errorf("auth/user/pass/%s-1 still exists (%q)", path, data.Data)
		}
		if _, ok := data.Data[path+"-2/"]; !ok {
			return fmt.Errorf("auth/user/pass/%s-2 no longer exists (%q)", path, data.Data)
		}
		if _, err := client.Logical().Delete("sys/auth/" + path + "-2/"); err != nil {
			return fmt.Errorf("unable to delete auth/user/pass/%s-2: %s", path, err)
		}

		return nil
	}
}
