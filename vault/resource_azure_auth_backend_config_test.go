package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccAzureAuthBackendConfig_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("azure")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckAzureAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAzureAuthBackendConfig_basic(backend),
				Check:  testAccAzureAuthBackendConfigCheck_attrs(backend),
			},
			{
				ResourceName:            "vault_azure_auth_backend_config.config",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"client_secret"},
			},
		},
	})
}

func TestAccAzureAuthBackendConfig_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("azure")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccCheckAzureAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAzureAuthBackendConfig_basic(backend),
				Check:  testAccAzureAuthBackendConfigCheck_attrs(backend),
			},
			{
				Config: testAccAzureAuthBackendConfig_updated(backend),
				Check:  testAccAzureAuthBackendConfigCheck_attrs(backend),
			},
		},
	})
}

func testAccCheckAzureAuthBackendConfigDestroy(s *terraform.State) error {
	config := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_azure_auth_backend_config" {
			continue
		}
		secret, err := config.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for Azure auth backend %q config: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("Azure auth backend %q still configured", rs.Primary.ID)
		}
	}
	return nil
}

func testAccAzureAuthBackendConfig_basic(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "azure" {
  type = "azure"
  path = "%s"
  description = "Test auth backend for Azure backend config"
}

resource "vault_azure_auth_backend_config" "config" {
  backend = vault_auth_backend.azure.path
  tenant_id = "11111111-2222-3333-4444-555555555555"
  client_id = "11111111-2222-3333-4444-555555555555"
  client_secret = "12345678901234567890"
  resource = "http://vault.hashicorp.com"
}
`, backend)
}

func testAccAzureAuthBackendConfigCheck_attrs(backend string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_azure_auth_backend_config.config"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		endpoint := instanceState.ID

		if endpoint != "auth/"+backend+"/config" {
			return fmt.Errorf("expected ID to be %q, got %q", "auth/"+backend+"/config", endpoint)
		}

		config := testProvider.Meta().(*api.Client)
		resp, err := config.Logical().Read(endpoint)
		if err != nil {
			return fmt.Errorf("error reading back Azure auth config from %q: %s", endpoint, err)
		}
		if resp == nil {
			return fmt.Errorf("Azure auth not configured at %q", endpoint)
		}
		attrs := map[string]string{
			"tenant_id": "tenant_id",
			"client_id": "client_id",
			//"client_secret":              "client_secret",
			"resource":    "resource",
			"environment": "environment",
		}
		for stateAttr, apiAttr := range attrs {
			if resp.Data[apiAttr] == nil && instanceState.Attributes[stateAttr] == "" {
				continue
			}
			if resp.Data[apiAttr] != instanceState.Attributes[stateAttr] {
				return fmt.Errorf("expected %s (%s) of %q to be %q, got %q", apiAttr, stateAttr, endpoint, instanceState.Attributes[stateAttr], resp.Data[apiAttr])
			}
		}
		return nil
	}
}

func testAccAzureAuthBackendConfig_updated(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "azure" {
  path = "%s"
  type = "azure"
  description = "Test auth backend for Azure backend config"
}

resource "vault_azure_auth_backend_config" "config" {
  backend = vault_auth_backend.azure.path
  tenant_id = "11111111-2222-3333-4444-555555555555"
  client_id = "11111111-2222-3333-4444-555555555555"
  client_secret = "12345678901234567890"
  resource = "http://vault.hashicorp.com"
}`, backend)
}
