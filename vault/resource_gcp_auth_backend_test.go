package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

const gcpJSONCredentials string = `
{
  "type": "service_account",
  "project_id": "terraform-vault-provider-a13efc8a",
  "private_key_id": "b1e1f3cdd7fc134afsdg3547828dc2bb9dff8480",
  "private_key": "-----BEGIN PRIVATE KEY-----\nABC123\n-----END PRIVATE KEY-----\n",
  "client_email": "terraform-vault-user@terraform-vault-provider-adf134rfds.iam.gserviceaccount.com",
  "client_id": "123134135242342423",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/vault-auth-checker%40terraform-vault-provider-adf134rfds.iam.gserviceaccount.com"
  }
`

func TestGCPAuthBackend_basic(t *testing.T) {
	path := resource.PrefixedUniqueId("gcp-basic-")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { util.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testGCPAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testGCPAuthBackendConfig_basic(path, gcpJSONCredentials),
				Check:  testGCPAuthBackendCheck_attrs(),
			},
		},
	})
}

func TestGCPAuthBackend_import(t *testing.T) {
	path := resource.PrefixedUniqueId("gcp-import-")

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { util.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testGCPAuthBackendDestroy,
		Steps: []resource.TestStep{
			{
				Config: testGCPAuthBackendConfig_basic(path, gcpJSONCredentials),
				Check:  testGCPAuthBackendCheck_attrs(),
			},
			{
				ResourceName:      "vault_gcp_auth_backend.test",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"credentials",
				},
			},
		},
	})
}

func testGCPAuthBackendDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_gcp_auth_backend" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for gcp auth backend %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("gcp auth backend %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testGCPAuthBackendCheck_attrs() resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_gcp_auth_backend.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		return nil
	}
}

func testGCPAuthBackendConfig_basic(path, credentials string) string {
	return fmt.Sprintf(`
variable "json_credentials" {
  type = "string"
  default = %q
}

resource "vault_gcp_auth_backend" "test" {
  path                          = %q
  credentials                   = var.json_credentials
}
`, credentials, path)

}
