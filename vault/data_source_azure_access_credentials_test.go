package vault

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
)

func TestAccDataSourceAzureAccessCredentials_basic(t *testing.T) {
	// This test takes a while because it's testing a loop that
	// retries real credentials until they're eventually consistent.
	if testing.Short() {
		t.SkipNow()
	}
	mountPath := acctest.RandomWithPrefix("tf-test-azure")
	subscriptionID, tenantID, clientID, clientSecret, scope := getTestAzureCreds(t)
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceAzureAccessCredentialsConfigBasic(mountPath, subscriptionID, tenantID, clientID, clientSecret, scope),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.vault_azure_access_credentials.test", "client_id"),
					resource.TestCheckResourceAttrSet("data.vault_azure_access_credentials.test", "client_secret"),
					resource.TestCheckResourceAttrSet("data.vault_azure_access_credentials.test", "lease_id"),
				),
			},
		},
	})
}

func testAccDataSourceAzureAccessCredentialsConfigBasic(mountPath, subscriptionID, tenantID, clientID, clientSecret, scope string) string {
	template := `
resource "vault_azure_secret_backend" "test" {
	path = "{{mountPath}}"
	subscription_id = "{{subscriptionID}}"
	tenant_id = "{{tenantID}}"
	client_id = "{{clientID}}"
	client_secret = "{{clientSecret}}"
}

resource "vault_azure_secret_backend_role" "test" {
	backend = "${vault_azure_secret_backend.test.path}"
	role = "my-role"
	azure_roles {
		role_name = "Reader"
		scope = "{{scope}}"
	}
	ttl = 300
	max_ttl = 600
}

data "vault_azure_access_credentials" "test" {
    backend = "${vault_azure_secret_backend.test.path}"
    role = "${vault_azure_secret_backend_role.test.role}"
    validate_creds = true
	num_sequential_successes = 2
	num_seconds_between_tests = 1
	max_cred_validation_seconds = 20
	subscription_id = "{{subscriptionID}}"
	tenant_id = "{{tenantID}}"
}`

	parsed := strings.Replace(template, "{{mountPath}}", mountPath, -1)
	parsed = strings.Replace(parsed, "{{subscriptionID}}", subscriptionID, -1)
	parsed = strings.Replace(parsed, "{{tenantID}}", tenantID, -1)
	parsed = strings.Replace(parsed, "{{clientID}}", clientID, -1)
	parsed = strings.Replace(parsed, "{{clientSecret}}", clientSecret, -1)
	parsed = strings.Replace(parsed, "{{scope}}", scope, -1)
	return parsed
}
