package vault

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccConsulSecretBackend_import(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-consul")
	token := "aea34d3f-17e4-4387-801c-5e41be678e46"
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccConsulSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testConsulSecretBackend_initialConfig(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "address", "127.0.0.1:8500"),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "token", token),
					resource.TestCheckResourceAttr("vault_consul_secret_backend.test", "scheme", "http"),
				),
			},
			{
				ResourceName:      "vault_consul_secret_backend.test",
				ImportState:       true,
				ImportStateVerify: true,
				// the API can't serve these fields, so ignore them
				ImportStateVerifyIgnore: []string{"token"},
			},
		},
	})
}
