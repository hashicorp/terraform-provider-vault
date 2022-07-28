package vault

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccConsulSecretBackend_import(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-consul")
	resourcePath := "vault_consul_secret_backend.test"
	token := "aea34d3f-17e4-4387-801c-5e41be678e46"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccConsulSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testConsulSecretBackend_initialConfig(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourcePath, "path", path),
					resource.TestCheckResourceAttr(resourcePath, "description", "test description"),
					resource.TestCheckResourceAttr(resourcePath, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourcePath, "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr(resourcePath, "address", "127.0.0.1:8500"),
					resource.TestCheckResourceAttr(resourcePath, "token", token),
					resource.TestCheckResourceAttr(resourcePath, "scheme", "http"),
				),
			},
			{
				ResourceName:      resourcePath,
				ImportState:       true,
				ImportStateVerify: true,
				// the API can't serve these fields, so ignore them
				ImportStateVerifyIgnore: []string{"token"},
			},
		},
	})
}
