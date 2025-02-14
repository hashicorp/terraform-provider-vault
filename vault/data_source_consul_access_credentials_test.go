package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDataSourceConsul_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-consul")
	token := "026a0c16-87cd-4c2d-b3f3-fb539f592b7e"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccConsulSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceConsul_initialConfig(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_consul_access_credentials.test", "backend", path),
					resource.TestCheckResourceAttrSet("data.vault_consul_access_credentials.test", "token"),
					resource.TestCheckResourceAttrSet("data.vault_consul_access_credentials.test", "accessor"),
				),
			},
		},
	})
}

func testAccDataSourceConsul_initialConfig(path string, token string) string {
	return fmt.Sprintf(`
resource "vault_consul_secret_backend" "test" {
	path = "%s"
	address = "127.0.0.1:8500"
	token = "%s"
}
resource "vault_consul_secret_backend_role" "this" {
	backend = vault_consul_secret_backend.test.path
	name = "test"
	# FIXME: Docs say policies is optional when token_type == management
	# https://www.vaultproject.io/api/secret/consul#parameters-for-consul-versions-1-4-and-above
	policies = ["foo", "bar"]
	token_type = "client"
	ttl = 120
	max_ttl = 240
	local = true
}
data "vault_consul_access_credentials" "test" {
  backend = vault_consul_secret_backend.test.path
  role = vault_consul_secret_backend_role.this.name
}`, path, token)
}
