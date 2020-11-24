package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/terraform-providers/terraform-provider-vault/util"
)

func TestAccDataSourceNomadAccessCredentials_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-nomad")
	address, token := util.GetTestNomadCreds(t)

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { util.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceNomadAccessCredentialsConfig(backend, address, token, "test"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.vault_nomad_access_credentials.creds", "secret_id"),
					resource.TestCheckResourceAttrSet("data.vault_nomad_access_credentials.creds", "accessor_id"),
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
	address = "%s",
	token = "%s"
}

resource "vault_nomad_secret_role" "test" {
    backend = "${vault_nomad_secret_backend.config.backend}"
    role = "%s"
}

data "vault_nomad_access_credentials" "creds" {
  backend = "${vault_nomad_secret_backend.config.backend}"
  role    = "${vault_nomad_secret_backend.test.role}"
}
`, backend, address, token, role)
}
