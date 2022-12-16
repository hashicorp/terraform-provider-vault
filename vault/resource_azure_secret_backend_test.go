package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAzureSecretBackend(t *testing.T) {
	testutil.SkipTestAcc(t)

	path := acctest.RandomWithPrefix("tf-test-azure")
	resourceType := "vault_azure_secret_backend"
	resourceName := resourceType + ".test"
	azureInitialCheckFuncs := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
		resource.TestCheckResourceAttr(resourceName, "subscription_id", "11111111-2222-3333-4444-111111111111"),
		resource.TestCheckResourceAttr(resourceName, "tenant_id", "11111111-2222-3333-4444-222222222222"),
		resource.TestCheckResourceAttr(resourceName, "client_id", "11111111-2222-3333-4444-333333333333"),
		resource.TestCheckResourceAttr(resourceName, "client_secret", "12345678901234567890"),
		resource.TestCheckResourceAttr(resourceName, "environment", "AzurePublicCloud"),
	}

	azureUpdatedCheckFuncs := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
		resource.TestCheckResourceAttr(resourceName, "subscription_id", "11111111-2222-3333-4444-111111111111"),
		resource.TestCheckResourceAttr(resourceName, "tenant_id", "22222222-3333-4444-5555-333333333333"),
		resource.TestCheckResourceAttr(resourceName, "client_id", "22222222-3333-4444-5555-444444444444"),
		resource.TestCheckResourceAttr(resourceName, "client_secret", "098765432109876543214"),
		resource.TestCheckResourceAttr(resourceName, "environment", "AzurePublicCloud"),
	}

	azureUpdatedSubscriptionIDCheckFuncs := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
		resource.TestCheckResourceAttr(resourceName, "subscription_id", "11111112-2221-3332-4443-111111111110"),
		resource.TestCheckResourceAttr(resourceName, "tenant_id", "22222222-3333-4444-5555-333333333333"),
		resource.TestCheckResourceAttr(resourceName, "client_id", "22222222-3333-4444-5555-444444444444"),
		resource.TestCheckResourceAttr(resourceName, "client_secret", "098765432109876543214"),
		resource.TestCheckResourceAttr(resourceName, "environment", "AzurePublicCloud"),
	}

	skipMSGraphCheck := provider.IsAPISupported(testProvider.Meta(), provider.VaultVersion112)
	if !skipMSGraphCheck {
		azureInitialCheckFuncs = append(azureInitialCheckFuncs,
			resource.TestCheckResourceAttr(resourceName, "use_microsoft_graph_api", "false"))
		azureUpdatedCheckFuncs = append(azureUpdatedCheckFuncs,
			resource.TestCheckResourceAttr(resourceName, "use_microsoft_graph_api", "true"))
		azureUpdatedSubscriptionIDCheckFuncs = append(azureUpdatedSubscriptionIDCheckFuncs,
			resource.TestCheckResourceAttr(resourceName, "use_microsoft_graph_api", "true"))
	}

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeAzure, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAzureSecretBackend_initialConfig(path),
				Check:  resource.ComposeTestCheckFunc(azureInitialCheckFuncs...),
			},
			{
				Config: testAzureSecretBackend_updated(path),
				Check:  resource.ComposeTestCheckFunc(azureUpdatedCheckFuncs...),
			},
			{
				Config: testAzureSecretBackend_updateSubscriptionID(path),
				Check:  resource.ComposeTestCheckFunc(azureUpdatedSubscriptionIDCheckFuncs...),
			},
		},
	})
}

func TestAzureSecretBackend_remount(t *testing.T) {
	testutil.SkipTestAcc(t)

	path := acctest.RandomWithPrefix("tf-test-azure")
	updatedPath := acctest.RandomWithPrefix("tf-test-azure-updated")

	resourceType := "vault_azure_secret_backend"
	resourceName := resourceType + ".test"
	azureInitialCheckFuncs := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
		resource.TestCheckResourceAttr(resourceName, "subscription_id", "11111111-2222-3333-4444-111111111111"),
		resource.TestCheckResourceAttr(resourceName, "tenant_id", "11111111-2222-3333-4444-222222222222"),
		resource.TestCheckResourceAttr(resourceName, "client_id", "11111111-2222-3333-4444-333333333333"),
		resource.TestCheckResourceAttr(resourceName, "client_secret", "12345678901234567890"),
		resource.TestCheckResourceAttr(resourceName, "environment", "AzurePublicCloud"),
	}
	azureUpdatedCheckFuncs := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldPath, updatedPath),
		resource.TestCheckResourceAttr(resourceName, "subscription_id", "11111111-2222-3333-4444-111111111111"),
		resource.TestCheckResourceAttr(resourceName, "tenant_id", "11111111-2222-3333-4444-222222222222"),
		resource.TestCheckResourceAttr(resourceName, "client_id", "11111111-2222-3333-4444-333333333333"),
		resource.TestCheckResourceAttr(resourceName, "client_secret", "12345678901234567890"),
		resource.TestCheckResourceAttr(resourceName, "environment", "AzurePublicCloud"),
	}

	skipMSGraphCheck := provider.IsAPISupported(testProvider.Meta(), provider.VaultVersion112)
	if !skipMSGraphCheck {
		azureInitialCheckFuncs = append(azureInitialCheckFuncs,
			resource.TestCheckResourceAttr(resourceName, "use_microsoft_graph_api", "false"))
		azureUpdatedCheckFuncs = append(azureUpdatedCheckFuncs,
			resource.TestCheckResourceAttr(resourceName, "use_microsoft_graph_api", "false"))
	}

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeAzure, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAzureSecretBackend_initialConfig(path),
				Check:  resource.ComposeTestCheckFunc(azureInitialCheckFuncs...),
			},
			{
				Config: testAzureSecretBackend_initialConfig(updatedPath),
				Check:  resource.ComposeTestCheckFunc(azureInitialCheckFuncs...),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "client_secret", "disable_remount"),
		},
	})
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
