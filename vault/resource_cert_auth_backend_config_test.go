package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccCertAuthBackendConfig_import(t *testing.T) {
	backend := acctest.RandomWithPrefix("cert")
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccCheckCertAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCertAuthBackendConfig_basic(backend),
				Check:  testAccCertAuthBackendConfigCheck_attrs(backend),
			},
			{
				ResourceName:      "vault_cert_auth_backend_config.config",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccCertAuthBackendConfig_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("cert")
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccCheckCertAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCertAuthBackendConfig_basic(backend),
				Check:  testAccCertAuthBackendConfigCheck_attrs(backend),
			},
			{
				Config: testAccCertAuthBackendConfig_updated(backend),
				Check:  testAccCertAuthBackendConfigCheck_attrs(backend),
			},
		},
	})
}

func testAccCheckCertAuthBackendConfigDestroy(s *terraform.State) error {
	config := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_cert_auth_backend_config" {
			continue
		}
		secret, err := config.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for cert auth backend %q config: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("Cert auth backend %q still configured", rs.Primary.ID)
		}
	}
	return nil
}

func testAccCertAuthBackendConfig_basic(backend string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "cert" {
  type = "cert"
  path = "%s"
  description = "Test auth backend for cert backend config"
}

resource "vault_cert_auth_backend_config" "config" {
  disable_binding = false
  enable_identity_alias_metadata = true
}
`, backend)
}

func testAccCertAuthBackendConfigCheck_attrs(backend string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_cert_auth_backend_config.config"]
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

		config := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()
		resp, err := config.Logical().Read(endpoint)
		if err != nil {
			return fmt.Errorf("error reading back cert auth config from %q: %s", endpoint, err)
		}
		if resp == nil {
			return fmt.Errorf("Cert auth not configured at %q", endpoint)
		}
		attrs := map[string]string{
			"disable_binding":                "disable_binding",
			"enable_identity_alias_metadata": "enable_identity_alias_metadata",
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

func testAccCertAuthBackendConfig_updated(backend string) string {
	return fmt.Sprintf(`

resource "vault_auth_backend" "cert" {
  type = "cert"
  path = "%s"
  description = "Test auth backend for cert backend config"
}

resource "vault_cert_auth_backend_config" "config" {
  disable_binding = false
  enable_identity_alias_metadata = true"
`, backend)
}
