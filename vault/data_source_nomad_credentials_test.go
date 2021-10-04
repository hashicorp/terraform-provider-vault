package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func TestAccDataSourceNomadAccessCredentialsClientBasic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-nomad")
	address, token := util.GetTestNomadCreds(t)

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { util.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceNomadAccessCredentialsConfig(backend, address, token, "test"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.vault_nomad_access_token.token", "secret_id"),
					resource.TestCheckResourceAttrSet("data.vault_nomad_access_token.token", "accessor_id"),
				),
			},
		},
	})
}

func TestAccDataSourceNomadAccessCredentialsManagementBasic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-nomad")
	address, token := util.GetTestNomadCreds(t)

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { util.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceNomadAccessCredentialsManagementConfig(backend, address, token, "test"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.vault_nomad_access_token.token", "secret_id"),
					resource.TestCheckResourceAttrSet("data.vault_nomad_access_token.token", "accessor_id"),
				),
			},
		},
	})
}

func testAccDataSourceNomadAccessCredentialsConfig(backend, address, token, role string) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "config" {
	backend = "%s"
	description = "test description"
	default_lease_ttl_seconds = "3600"
	max_lease_ttl_seconds = "7200"
	address = "%s"
	token = "%s"
}

resource "vault_nomad_secret_role" "test" {
    backend = vault_nomad_secret_backend.config.backend
	role = "%s"
	policies = ["reaodnly"]
}

data "vault_nomad_access_token" "token" {
  backend = vault_nomad_secret_backend.config.backend
  role    = vault_nomad_secret_role.test.role
}
`, backend, address, token, role)
}

func testAccDataSourceNomadAccessCredentialsManagementConfig(backend, address, token, role string) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "config" {
	backend = "%s"
	description = "test description"
	default_lease_ttl_seconds = "3600"
	max_lease_ttl_seconds = "7200"
	address = "%s"
	token = "%s"
}

resource "vault_nomad_secret_role" "test" {
    backend = vault_nomad_secret_backend.config.backend
	role = "%s"
	type = "management"
}

data "vault_nomad_access_token" "token" {
  backend = vault_nomad_secret_backend.config.backend
  role    = vault_nomad_secret_role.test.role
}
`, backend, address, token, role)
}
