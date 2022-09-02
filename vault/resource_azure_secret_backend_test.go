package vault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAzureSecretBackend(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-azure")
	resourceName := "vault_azure_secret_backend.test"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testAccAzureSecretBackendCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAzureSecretBackend_initialConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "subscription_id", "11111111-2222-3333-4444-111111111111"),
					resource.TestCheckResourceAttr(resourceName, "tenant_id", "11111111-2222-3333-4444-222222222222"),
					resource.TestCheckResourceAttr(resourceName, "client_id", "11111111-2222-3333-4444-333333333333"),
					resource.TestCheckResourceAttr(resourceName, "client_secret", "12345678901234567890"),
					resource.TestCheckResourceAttr(resourceName, "environment", "AzurePublicCloud"),
					resource.TestCheckResourceAttr(resourceName, "use_microsoft_graph_api", "false"),
				),
			},
			{
				Config: testAzureSecretBackend_updated(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "subscription_id", "11111111-2222-3333-4444-111111111111"),
					resource.TestCheckResourceAttr(resourceName, "tenant_id", "22222222-3333-4444-5555-333333333333"),
					resource.TestCheckResourceAttr(resourceName, "client_id", "22222222-3333-4444-5555-444444444444"),
					resource.TestCheckResourceAttr(resourceName, "client_secret", "098765432109876543214"),
					resource.TestCheckResourceAttr(resourceName, "environment", "AzurePublicCloud"),
					resource.TestCheckResourceAttr(resourceName, "use_microsoft_graph_api", "true"),
				),
			},
			{
				Config: testAzureSecretBackend_updateSubscriptionID(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "subscription_id", "11111112-2221-3332-4443-111111111110"),
					resource.TestCheckResourceAttr(resourceName, "tenant_id", "22222222-3333-4444-5555-333333333333"),
					resource.TestCheckResourceAttr(resourceName, "client_id", "22222222-3333-4444-5555-444444444444"),
					resource.TestCheckResourceAttr(resourceName, "client_secret", "098765432109876543214"),
					resource.TestCheckResourceAttr(resourceName, "environment", "AzurePublicCloud"),
					resource.TestCheckResourceAttr(resourceName, "use_microsoft_graph_api", "true"),
				),
			},
		},
	})
}

func TestAzureSecretBackend_remount(t *testing.T) {
	path := acctest.RandomWithPrefix("tf-test-azure")
	updatedPath := acctest.RandomWithPrefix("tf-test-azure-updated")

	resourceName := "vault_azure_secret_backend.test"
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAzureSecretBackend_initialConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, "subscription_id", "11111111-2222-3333-4444-111111111111"),
					resource.TestCheckResourceAttr(resourceName, "tenant_id", "11111111-2222-3333-4444-222222222222"),
					resource.TestCheckResourceAttr(resourceName, "client_id", "11111111-2222-3333-4444-333333333333"),
					resource.TestCheckResourceAttr(resourceName, "client_secret", "12345678901234567890"),
					resource.TestCheckResourceAttr(resourceName, "environment", "AzurePublicCloud"),
					resource.TestCheckResourceAttr(resourceName, "use_microsoft_graph_api", "false"),
				),
			},
			{
				Config: testAzureSecretBackend_initialConfig(updatedPath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, updatedPath),
					resource.TestCheckResourceAttr(resourceName, "subscription_id", "11111111-2222-3333-4444-111111111111"),
					resource.TestCheckResourceAttr(resourceName, "tenant_id", "11111111-2222-3333-4444-222222222222"),
					resource.TestCheckResourceAttr(resourceName, "client_id", "11111111-2222-3333-4444-333333333333"),
					resource.TestCheckResourceAttr(resourceName, "client_secret", "12345678901234567890"),
					resource.TestCheckResourceAttr(resourceName, "environment", "AzurePublicCloud"),
					resource.TestCheckResourceAttr(resourceName, "use_microsoft_graph_api", "false"),
				),
			},
		},
	})
}

func testAccAzureSecretBackendCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_azure_secret_backend" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		mounts, err := client.Sys().ListMounts()
		if err != nil {
			return err
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
	 use_microsoft_graph_api = true
	}`, path)
}

func testAzureSecretBackend_updateSubscriptionID(path string) string {
	return fmt.Sprintf(`
	resource "vault_azure_secret_backend" "test" {
	 path = "%s"
	 subscription_id = "11111112-2221-3332-4443-111111111110"
	 tenant_id = "22222222-3333-4444-5555-333333333333"
	 client_id = "22222222-3333-4444-5555-444444444444"
	 client_secret = "098765432109876543214"
	 environment = "AzurePublicCloud"
	 use_microsoft_graph_api = true
	}`, path)
}
