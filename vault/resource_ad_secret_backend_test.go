package vault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

func TestADSecretBackend(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-ad")
	bindDN, bindPass, url := util.GetTestADCreds(t)

	resource.Test(t, resource.TestCase{
		Providers:                 testProviders,
		PreCheck:                  func() { util.TestAccPreCheck(t) },
		PreventPostDestroyRefresh: true,
		CheckDestroy:              testAccADSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testADSecretBackend_initialConfig(backend, bindDN, bindPass, url),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_ad_secret_backend.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_ad_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_ad_secret_backend.test", "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_ad_secret_backend.test", "max_lease_ttl_seconds", "7200"),
					resource.TestCheckResourceAttr("vault_ad_secret_backend.test", "binddn", bindDN),
					resource.TestCheckResourceAttr("vault_ad_secret_backend.test", "bindpass", bindPass),
					resource.TestCheckResourceAttr("vault_ad_secret_backend.test", "url", url),
					resource.TestCheckResourceAttr("vault_ad_secret_backend.test", "insecure_tls", "true"),
					resource.TestCheckResourceAttr("vault_ad_secret_backend.test", "userdn", "CN=Users,DC=corp,DC=example,DC=net"),
				),
			},
			{
				Config: testADSecretBackend_updateConfig(backend, bindDN, bindPass, url),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_ad_secret_backend.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_ad_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_ad_secret_backend.test", "default_lease_ttl_seconds", "7200"),
					resource.TestCheckResourceAttr("vault_ad_secret_backend.test", "max_lease_ttl_seconds", "14400"),
					resource.TestCheckResourceAttr("vault_ad_secret_backend.test", "binddn", bindDN),
					resource.TestCheckResourceAttr("vault_ad_secret_backend.test", "bindpass", bindPass),
					resource.TestCheckResourceAttr("vault_ad_secret_backend.test", "url", url),
					resource.TestCheckResourceAttr("vault_ad_secret_backend.test", "insecure_tls", "false"),
					resource.TestCheckResourceAttr("vault_ad_secret_backend.test", "userdn", "CN=Users,DC=corp,DC=hashicorp,DC=com"),
				),
			},
		},
	})
}

func testAccADSecretBackendCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_ad_secret_backend" {
			continue
		}
		for backend, mount := range mounts {
			backend = strings.Trim(backend, "/")
			rsBackend := strings.Trim(rs.Primary.Attributes["backend"], "/")
			if mount.Type == "ad" && backend == rsBackend {
				return fmt.Errorf("Mount %q still exists", rsBackend)
			}
		}
	}
	return nil
}

func testADSecretBackend_initialConfig(backend, bindDN, bindPass, url string) string {
	return fmt.Sprintf(`
resource "vault_ad_secret_backend" "test" {
	backend = "%s"
	description = "test description"
	default_lease_ttl_seconds = "3600"
	max_lease_ttl_seconds = "7200"
	binddn = "%s"
	bindpass = "%s"
	url = "%s"
	insecure_tls = "true"
	userdn = "CN=Users,DC=corp,DC=example,DC=net"
}`, backend, bindDN, bindPass, url)
}

func testADSecretBackend_updateConfig(backend, bindDN, bindPass, url string) string {
	return fmt.Sprintf(`
resource "vault_ad_secret_backend" "test" {
	backend = "%s"
	description = "test description"
	default_lease_ttl_seconds = "7200"
	max_lease_ttl_seconds = "14400"
	binddn = "%s"
	bindpass = "%s"
	url = "%s"
	insecure_tls = "false"
	userdn = "CN=Users,DC=corp,DC=hashicorp,DC=com"
}`, backend, bindDN, bindPass, url)
}
