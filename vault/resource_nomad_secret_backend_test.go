package vault

import (
	"testing"

	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func TestNomadSecretBackend(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-nomad")
	token := "026a0c16-87cd-4c2d-b3f3-fb539f592b7e"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccNomadSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testNomadSecretBackend_initialConfig(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "address", "127.0.0.1:4646"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "token", token),
				),
			},
			{
				Config: testNomadSecretBackend_updateConfig(path, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "default_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "max_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "address", "nomad.domain.tld:4646"),
					resource.TestCheckResourceAttr("vault_nomad_secret_backend.test", "token", token),
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
		for path, mount := range mounts {
			path = strings.Trim(path, "/")
			rsPath := strings.Trim(rs.Primary.Attributes["path"], "/")
			if mount.Type == "nomad" && path == rsPath {
				return fmt.Errorf("Mount %q still exists", path)
			}
		}
	}
	return nil
}

func testNomadSecretBackend_initialConfig(path, token string) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "test" {
  path = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  address = "127.0.0.1:4646"
  token = "%s"
}`, path, token)
}

func testNomadSecretBackend_updateConfig(path, token string) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "test" {
  path = "%s"
  description = "test description"
  address = "nomad.domain.tld:4646"
  token = "%s"
}`, path, token)
}
