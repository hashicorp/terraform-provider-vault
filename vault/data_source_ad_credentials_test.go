package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func TestAccDataSourceADAccessCredentials_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-ad")
	bindDN, bindPass, url := util.GetTestADCreds(t)

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { util.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceADAccessCredentialsConfig(backend, bindDN, bindPass, url, "bob", "Bob", 60),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.vault_ad_access_credentials.creds", "current_password"),
					resource.TestCheckResourceAttr("data.vault_ad_access_credentials.creds", "username", "Bob"),
				),
			},
		},
	})
}

func testAccDataSourceADAccessCredentialsConfig(backend, bindDN, bindPass, url, role, serviceAccountName string, ttl int) string {
	return fmt.Sprintf(`
resource "vault_ad_secret_backend" "config" {
	backend = "%s"
	description = "test description"
	default_lease_ttl_seconds = "3600"
	max_lease_ttl_seconds = "7200"
	binddn = "%s"
	bindpass = "%s"
	url = "%s"
	insecure_tls = "true"
	userdn = "CN=Users,DC=corp,DC=example,DC=net"
}

resource "vault_ad_secret_role" "role" {
    backend = vault_ad_secret_backend.config.backend
    role = "%s"
    service_account_name = "%s"
    ttl = %d
}

data "vault_ad_access_credentials" "creds" {
  backend = vault_ad_secret_backend.config.backend
  role    = vault_ad_secret_role.role.role
}

`, backend, bindDN, bindPass, url, role, serviceAccountName, ttl)
}
