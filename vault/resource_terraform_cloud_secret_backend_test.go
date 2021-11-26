package vault

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func TestTerraformCloudSecretBackend(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-terraform-cloud")
	token := os.Getenv("TEST_TF_TOKEN")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccTerraformCloudSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testTerraformCloudSecretBackend_initialConfig(backend, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_terraform_cloud_secret_backend.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_terraform_cloud_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_terraform_cloud_secret_backend.test", "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_terraform_cloud_secret_backend.test", "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr("vault_terraform_cloud_secret_backend.test", "address", "https://app.terraform.io"),
					resource.TestCheckResourceAttr("vault_terraform_cloud_secret_backend.test", "token", token),
					resource.TestCheckResourceAttr("vault_terraform_cloud_secret_backend.test", "base_path", "/api/v2/"),
				),
			},
			{
				Config: testTerraformCloudSecretBackend_updateConfig(backend, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_terraform_cloud_secret_backend.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_terraform_cloud_secret_backend.test", "description", "test description"),
					resource.TestCheckResourceAttr("vault_terraform_cloud_secret_backend.test", "default_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr("vault_terraform_cloud_secret_backend.test", "max_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr("vault_terraform_cloud_secret_backend.test", "address", "https://app.terraform.io/not"),
					resource.TestCheckResourceAttr("vault_terraform_cloud_secret_backend.test", "token", token),
					resource.TestCheckResourceAttr("vault_terraform_cloud_secret_backend.test", "base_path", "/not/api/v2/"),
				),
			},
		},
	})
}

func testAccTerraformCloudSecretBackendCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_terraform_cloud_secret_backend" {
			continue
		}
		for path, mount := range mounts {
			path = strings.Trim(path, "/")
			rsPath := strings.Trim(rs.Primary.Attributes["path"], "/")
			if mount.Type == "terraform_cloud" && path == rsPath {
				return fmt.Errorf("Mount %q still exists", path)
			}
		}
	}
	return nil
}

func testTerraformCloudSecretBackend_initialConfig(path, token string) string {
	return fmt.Sprintf(`
resource "vault_terraform_cloud_secret_backend" "test" {
  backend = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  token = "%s"
}`, path, token)
}

func testTerraformCloudSecretBackend_updateConfig(path, token string) string {
	return fmt.Sprintf(`
resource "vault_terraform_cloud_secret_backend" "test" {
  backend = "%s"
  description = "test description"
  address = "https://app.terraform.io/not"
  token = "%s"
  base_path = "/not/api/v2/"
}`, path, token)
}
