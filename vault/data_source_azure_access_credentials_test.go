package vault

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccDataSourceAzureAccessCredentials_basic(t *testing.T) {
	// This test takes a while because it's testing a loop that
	// retries real credentials until they're eventually consistent.
	if testing.Short() {
		t.SkipNow()
	}
	mountPath := acctest.RandomWithPrefix("tf-test-azure")
	conf := getTestAzureConf(t)
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceAzureAccessCredentialsConfigBasic(mountPath, conf, 2, 20),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.vault_azure_access_credentials.test", "client_id"),
					resource.TestCheckResourceAttrSet("data.vault_azure_access_credentials.test", "client_secret"),
					resource.TestCheckResourceAttrSet("data.vault_azure_access_credentials.test", "lease_id"),
				),
			},
			{
				Config:      testAccDataSourceAzureAccessCredentialsConfigBasic(mountPath, conf, 1000, 5),
				ExpectError: regexp.MustCompile(`despite trying for 5 seconds, 1 seconds apart, we were never able to get 1000 successes in a row`),
			},
		},
	})
}

func testAccDataSourceAzureAccessCredentialsConfigBasic(mountPath string, conf *azureTestConf, numSuccesses, maxSecs int) string {
	template := `
resource "vault_azure_secret_backend" "test" {
	path = "{{mountPath}}"
	subscription_id = "{{subscriptionID}}"
	tenant_id = "{{tenantID}}"
	client_id = "{{clientID}}"
	client_secret = "{{clientSecret}}"
}

resource "vault_azure_secret_backend_role" "test" {
	backend = vault_azure_secret_backend.test.path
	role = "my-role"
	azure_roles {
		role_name = "Reader"
		scope = "{{scope}}"
	}
	ttl = 300
	max_ttl = 600
}

data "vault_azure_access_credentials" "test" {
    backend = vault_azure_secret_backend.test.path
    role = vault_azure_secret_backend_role.test.role
    validate_creds = true
	num_sequential_successes = {{numSequentialSuccesses}}
	num_seconds_between_tests = 1
	max_cred_validation_seconds = {{maxCredValidationSeconds}}
}`

	parsed := strings.Replace(template, "{{mountPath}}", mountPath, -1)
	parsed = strings.Replace(parsed, "{{subscriptionID}}", conf.SubscriptionID, -1)
	parsed = strings.Replace(parsed, "{{tenantID}}", conf.TenantID, -1)
	parsed = strings.Replace(parsed, "{{clientID}}", conf.ClientID, -1)
	parsed = strings.Replace(parsed, "{{clientSecret}}", conf.ClientSecret, -1)
	parsed = strings.Replace(parsed, "{{scope}}", conf.Scope, -1)
	parsed = strings.Replace(parsed, "{{numSequentialSuccesses}}", strconv.Itoa(numSuccesses), -1)
	parsed = strings.Replace(parsed, "{{maxCredValidationSeconds}}", strconv.Itoa(maxSecs), -1)
	return parsed
}
