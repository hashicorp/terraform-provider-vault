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

func TestAccNomadSecretBackend(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-nomad")
	address, token := util.GetTestNomadCreds(t)

	resource.Test(t, resource.TestCase{
		Providers:                 testProviders,
		PreCheck:                  func() { util.TestAccPreCheck(t) },
		PreventPostDestroyRefresh: true,
		CheckDestroy:              testAccNomadSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testNomadSecretBackendConfig(backend, address, token, 60, 30, 3600, 7200),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "max_lease_ttl_seconds", "7200"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "address", address),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "max_ttl", "60"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "ttl", "30"),
				),
			},
			{
				Config: testNomadSecretBackendConfig(backend, "foobar", token, 90, 60, 7200, 14400),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "default_lease_ttl_seconds", "7200"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "max_lease_ttl_seconds", "14400"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "address", "foobar"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "max_ttl", "90"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "ttl", "60"),
				),
			},
			{
				Config: testNomadSecretBackendConfig(backend, "foobar", token, 0, 0, -1, -1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "default_lease_ttl_seconds", "-1"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "max_lease_ttl_seconds", "-1"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "address", "foobar"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "max_ttl", "0"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "ttl", "0"),
				),
			},
		},
	})
}

func testAccNomadSecretBackendCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_nomad_secret_backend" {
			continue
		}
		for backend, mount := range mounts {
			backend = strings.Trim(backend, "/")
			rsBackend := strings.Trim(rs.Primary.Attributes["backend"], "/")
			if mount.Type == "nomad" && backend == rsBackend {
				return fmt.Errorf("Mount %q still exists", rsBackend)
			}
		}
	}
	return nil
}

func testNomadSecretBackendConfig(backend, address, token string, maxTTL, ttl, defaultLease, maxLease int) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "test" {
	backend = "%s"
	description = "test description"
	address = "%s"
	token = "%s"
	max_ttl = "%d"
	ttl = "%d"
	default_lease_ttl_seconds = "%d"
	max_lease_ttl_seconds = "%d"
}
`, backend, address, token, maxTTL, ttl, defaultLease, maxLease)
}
