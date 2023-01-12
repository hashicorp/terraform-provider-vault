package vault

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
	"golang.org/x/oauth2/google"
)

// This test requires that you pass credentials for a user or service account having the IAM rights
// listed at https://www.vaultproject.io/docs/secrets/gcp/index.html for the project you are testing
// on. The credentials must also allow setting IAM permissions on the project being tested.
func TestGCPSecretImpersonatedAccount(t *testing.T) {
	backend := "gcp"
	impersonatedAccount := acctest.RandomWithPrefix("tf-test")
	credentials, project := testutil.GetTestGCPCreds(t)

	// We will use the provided key as the impersonated account
	conf, err := google.JWTConfigFromJSON([]byte(credentials), "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		t.Fatalf("error decoding GCP Credentials: %v", err)
	}
	serviceAccountEmail := conf.Email

	noBindings := testGCPSecretImpersonatedAccount_accessToken(backend, impersonatedAccount, credentials, serviceAccountEmail)

	resourceName := "vault_gcp_secret_impersonated_account.test"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testGCPSecretImpersonatedAccountDestroy,
		Steps: []resource.TestStep{
			{
				Config: noBindings,
				Check: resource.ComposeTestCheckFunc(
					testGCPSecretImpersonatedAccount_attrs(backend, impersonatedAccount),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, "impersonated_account", impersonatedAccount),
					resource.TestCheckResourceAttr(resourceName, "service_account_email", serviceAccountEmail),
					resource.TestCheckResourceAttr(resourceName, "service_account_project", project),
					resource.TestCheckResourceAttr(resourceName, "token_scopes.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "token_scopes.0", "https://www.googleapis.com/auth/cloud-platform"),
				),
			},
			{
				ResourceName:            "vault_gcp_secret_impersonated_account.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{},
			},
		},
	})
}

func testGCPSecretImpersonatedAccount_attrs(backend, impersonatedAccount string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_gcp_secret_impersonated_account.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		endpoint := instanceState.ID

		if endpoint != backend+"/impersonated-account/"+impersonatedAccount {
			return fmt.Errorf("expected ID to be %q, got %q instead", backend+"/impersonated-account/"+impersonatedAccount, endpoint)
		}

		client := testProvider.Meta().(*provider.ProviderMeta).GetClient()
		resp, err := client.Logical().Read(endpoint)
		if err != nil {
			return fmt.Errorf("%q doesn't exist", endpoint)
		}

		attrs := map[string]string{
			"service_account_project": "service_account_project",
			"token_scopes":            "token_scopes",
			"service_account_email":   "service_account_email",
		}
		for stateAttr, apiAttr := range attrs {
			if resp.Data[apiAttr] == nil && instanceState.Attributes[stateAttr] == "" {
				continue
			}
			var match bool
			switch resp.Data[apiAttr].(type) {
			case json.Number:
				apiData, err := resp.Data[apiAttr].(json.Number).Int64()
				if err != nil {
					return fmt.Errorf("expected API field %s to be an int, was %q", apiAttr, resp.Data[apiAttr])
				}
				stateData, err := strconv.ParseInt(instanceState.Attributes[stateAttr], 10, 64)
				if err != nil {
					return fmt.Errorf("expected state field %s to be an int, was %q", stateAttr, instanceState.Attributes[stateAttr])
				}
				match = apiData == stateData
			case bool:
				if _, ok := resp.Data[apiAttr]; !ok && instanceState.Attributes[stateAttr] == "" {
					match = true
				} else {
					stateData, err := strconv.ParseBool(instanceState.Attributes[stateAttr])
					if err != nil {
						return fmt.Errorf("expected state field %s to be a bool, was %q", stateAttr, instanceState.Attributes[stateAttr])
					}
					match = resp.Data[apiAttr] == stateData
				}
			case []interface{}:
				apiData := resp.Data[apiAttr].([]interface{})
				length := instanceState.Attributes[stateAttr+".#"]
				if length == "" {
					if len(resp.Data[apiAttr].([]interface{})) != 0 {
						return fmt.Errorf("expected state field %s to have %d entries, had 0", stateAttr, len(apiData))
					}
					match = true
				} else {
					count, err := strconv.Atoi(length)
					if err != nil {
						return fmt.Errorf("expected %s.# to be a number, got %q", stateAttr, instanceState.Attributes[stateAttr+".#"])
					}
					if count != len(apiData) {
						return fmt.Errorf("expected %s to have %d entries in state, has %d", stateAttr, len(apiData), count)
					}

					for i := 0; i < count; i++ {
						found := false
						for stateKey, stateValue := range instanceState.Attributes {
							if strings.HasPrefix(stateKey, stateAttr) {
								if apiData[i] == stateValue {
									found = true
								}
							}
						}
						if !found {
							return fmt.Errorf("Expected item %d of %s (%s in state) of %q to be in state but wasn't", i, apiAttr, stateAttr, apiData[i])
						}
					}
					match = true
				}
			default:
				match = resp.Data[apiAttr] == instanceState.Attributes[stateAttr]
			}
			if !match {
				return fmt.Errorf("expected %s (%s in state) of %q to be %q, got %q", apiAttr, stateAttr, endpoint, instanceState.Attributes[stateAttr], resp.Data[apiAttr])
			}
		}

		return nil
	}
}

func testGCPSecretImpersonatedAccountDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*provider.ProviderMeta).GetClient()

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_gcp_secret_impersonated_account" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for GCP Secrets ImpersonatedAccount %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("GCP Secrets ImpersonatedAccount %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testGCPSecretImpersonatedAccount_accessToken(backend, impersonatedAccount, credentials, serviceAccountEmail string) string {
	return fmt.Sprintf(`

resource "vault_gcp_secret_impersonated_account" "test" {
	backend = "gcp" # vault_gcp_secret_backend.test.path
	impersonated_account = "%s"
	token_scopes   = ["https://www.googleapis.com/auth/cloud-platform"]
	service_account_email = "%s"
}
`, impersonatedAccount, serviceAccountEmail)
}
