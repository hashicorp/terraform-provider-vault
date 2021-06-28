package vault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAzureSecretBackend(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-azure")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccAzureSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAzureSecretBackend_initialConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_azure_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_azure_secret_backend.test", "subscription_id", "11111111-2222-3333-4444-111111111111"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend.test", "tenant_id", "11111111-2222-3333-4444-222222222222"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend.test", "client_id", "11111111-2222-3333-4444-333333333333"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend.test", "client_secret", "12345678901234567890"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend.test", "environment", "AzurePublicCloud"),
				),
			},
			{
				Config: testAzureSecretBackend_updated(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_azure_secret_backend.test", "path", path),
					resource.TestCheckResourceAttr("vault_azure_secret_backend.test", "subscription_id", "11111111-2222-3333-4444-111111111111"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend.test", "tenant_id", "22222222-3333-4444-5555-333333333333"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend.test", "client_id", "22222222-3333-4444-5555-444444444444"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend.test", "client_secret", "098765432109876543214"),
					resource.TestCheckResourceAttr("vault_azure_secret_backend.test", "environment", "AzurePublicCloud"),
				),
			},
		},
	})
}

func testAccAzureSecretBackendCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_azure_secret_backend" {
			continue
		}
		for path, mount := range mounts {
			path = strings.Trim(path, "/")
			rsPath := strings.Trim(rs.Primary.Attributes["path"], "/")
			if mount.Type == "azure" && path == rsPath {
				return fmt.Errorf("Mount %q still exists", path)
			}
		}
	}
	return nil
}

func testAzureSecretBackend_initialConfig(path string) string {
	return fmt.Sprintf(`
	resource "vault_azure_secret_backend" "test" {
	 path = "%s"
	 subscription_id = "11111111-2222-3333-4444-111111111111"
	 tenant_id = "11111111-2222-3333-4444-222222222222"
	 client_id = "11111111-2222-3333-4444-333333333333"
	 client_secret = "12345678901234567890"
	 environment = "AzurePublicCloud"
	}`, path)
}

func testAzureSecretBackend_updated(path string) string {
	return fmt.Sprintf(`
	resource "vault_azure_secret_backend" "test" {
	 path = "%s"
	 subscription_id = "11111111-2222-3333-4444-111111111111"
	 tenant_id = "22222222-3333-4444-5555-333333333333"
	 client_id = "22222222-3333-4444-5555-444444444444"
	 client_secret = "098765432109876543214"
	 environment = "AzurePublicCloud"
	}`, path)
}
