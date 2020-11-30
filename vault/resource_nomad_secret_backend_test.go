package vault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

func TestNomadSecretBackend(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-nomad")
	address, token := util.GetTestNomadCreds(t)

	resource.Test(t, resource.TestCase{
		Providers:                 testProviders,
		PreCheck:                  func() { util.TestAccPreCheck(t) },
		PreventPostDestroyRefresh: true,
		CheckDestroy:              testAccNomadSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testNomadSecretBackendInitialConfig(backend, address, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "max_lease_ttl_seconds", "7200"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "address", address),
				),
			},
			{
				Config: testNomadSecretBackendUpdateConfig(backend, "foobar", token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "default_lease_ttl_seconds", "7200"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "max_lease_ttl_seconds", "14400"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "address", "foobar"),
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

func testNomadSecretBackendInitialConfig(backend, address, token string) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "config" {
	backend = "%s"
	description = "test description"
	default_lease_ttl_seconds = "3600"
	max_lease_ttl_seconds = "7200"
	address = "%s"
	token = "%s"
}
`, backend, address, token)
}

func testNomadSecretBackendUpdateConfig(backend, address, token string) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "config" {
	backend = "%s"
	description = "test description"
	default_lease_ttl_seconds = "7200"
	max_lease_ttl_seconds = "14000"
	address = "%s"
	token = "%s"
}
`, backend, address, token)
}
