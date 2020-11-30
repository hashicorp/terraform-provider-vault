package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func TestAccNomadSecretLease(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-nomad")
	address, token := util.GetTestNomadCreds(t)

	resource.Test(t, resource.TestCase{
		Providers:                 testProviders,
		PreCheck:                  func() { util.TestAccPreCheck(t) },
		PreventPostDestroyRefresh: true,
		CheckDestroy:              testAccNomadSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testNomadSecretBackendInitialLeaseConfig(backend, address, token, 3600, 1800),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_nomad_secret_lease.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_nomad_secret_lease.test", "max_ttl", "3600"),
					resource.TestCheckResourceAttr("vault_nomad_secret_lease.test", "ttl", "1800"),
				),
			},
			{
				Config: testNomadSecretBackendInitialLeaseConfig(backend, address, token, 7200, 3600),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_nomad_secret_lease.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_nomad_secret_lease.test", "max_ttl", "7200"),
					resource.TestCheckResourceAttr("vault_nomad_secret_lease.test", "ttl", "3600"),
				),
			},
		},
	})
}

func testNomadSecretBackendInitialLeaseConfig(backend, address, token string, maxTTL, ttl int) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "config" {
	backend = "%s"
	description = "test description"
	default_lease_ttl_seconds = "3600"
	max_lease_ttl_seconds = "7200"
	address = "%s"
	token = "%s"
}

resource "vault_nomad_secret_lease" "test" {
    backend = vault_nomad_secret_backend.config.backend
    max_ttl = %d
    ttl = %d
}
`, backend, address, token, maxTTL, ttl)
}
