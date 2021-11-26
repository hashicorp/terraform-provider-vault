package vault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func TestGCPSecretBackend(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-gcp")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccGCPSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testGCPSecretBackend_initialConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_gcp_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_gcp_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_gcp_secret_backend.test", "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_gcp_secret_backend.test", "max_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr("vault_gcp_secret_backend.test", "credentials", "{\"hello\":\"world\"}"),
					resource.TestCheckResourceAttr("vault_gcp_secret_backend.test", "local", "false"),
				),
			},
			{
				Config: testGCPSecretBackend_updateConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_gcp_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_gcp_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_gcp_secret_backend.test", "default_lease_ttl_seconds", "1800"),
					resource.TestCheckResourceAttr("vault_gcp_secret_backend.test", "max_lease_ttl_seconds", "43200"),
					resource.TestCheckResourceAttr("vault_gcp_secret_backend.test", "credentials", "{\"how\":\"goes\"}"),
					resource.TestCheckResourceAttr("vault_gcp_secret_backend.test", "local", "true"),
				),
			},
		},
	})
}

func testAccGCPSecretBackendCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_gcp_secret_backend" {
			continue
		}
		for path, mount := range mounts {
			path = strings.Trim(path, "/")
			rsPath := strings.Trim(rs.Primary.Attributes["path"], "/")
			if mount.Type == "gcp" && path == rsPath {
				return fmt.Errorf("Mount %q still exists", path)
			}
		}
	}
	return nil
}

func testGCPSecretBackend_initialConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_gcp_secret_backend" "test" {
  path = "%s"
  credentials = <<EOF
{
  "hello": "world"
}
EOF
  description = "test description"
  default_lease_ttl_seconds = 3600
}`, path)
}

func testGCPSecretBackend_updateConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_gcp_secret_backend" "test" {
  path = "%s"
  credentials = <<EOF
{
  "how": "goes"
}
EOF
  description = "test description"
  default_lease_ttl_seconds = 1800
  max_lease_ttl_seconds = 43200
  local = true
}`, path)
}
