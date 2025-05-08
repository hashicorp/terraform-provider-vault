// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"golang.org/x/oauth2/google"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// This test requires that you pass credentials for a user or service account having the IAM rights
// listed at https://www.vaultproject.io/docs/secrets/gcp/index.html for the project you are testing
// on. The credentials must also allow setting IAM permissions on the project being tested.
func TestGCPSecretImpersonatedAccount(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-gcp")
	impersonatedAccount := acctest.RandomWithPrefix("tf-test")
	credentials, project := testutil.GetTestGCPCreds(t)

	// We will use the provided key as the impersonated account
	conf, err := google.JWTConfigFromJSON([]byte(credentials), "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		t.Fatalf("error decoding GCP Credentials: %v", err)
	}
	serviceAccountEmail := conf.Email

	resourceName := "vault_gcp_secret_impersonated_account.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion113)
		},
		CheckDestroy: testGCPSecretImpersonatedAccountDestroy,
		Steps: []resource.TestStep{
			{
				Config: testGCPSecretImpersonatedAccount_initial(backend, impersonatedAccount, credentials, serviceAccountEmail),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, "impersonated_account", impersonatedAccount),
					resource.TestCheckResourceAttr(resourceName, "service_account_email", serviceAccountEmail),
					resource.TestCheckResourceAttr(resourceName, "service_account_project", project),
					resource.TestCheckResourceAttr(resourceName, "token_scopes.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "token_scopes.0", "https://www.googleapis.com/auth/cloud-platform"),
					resource.TestCheckResourceAttr(resourceName, "ttl", "700"),
				),
			},
			{
				Config: testGCPSecretImpersonatedAccount_updated(backend, impersonatedAccount, credentials, serviceAccountEmail),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, "impersonated_account", impersonatedAccount),
					resource.TestCheckResourceAttr(resourceName, "service_account_email", serviceAccountEmail),
					resource.TestCheckResourceAttr(resourceName, "service_account_project", project),
					resource.TestCheckResourceAttr(resourceName, "token_scopes.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "token_scopes.0", "https://www.googleapis.com/auth/cloud-platform"),
					resource.TestCheckResourceAttr(resourceName, "token_scopes.1", "https://www.googleapis.com/auth/cloud-platform.read-only"),
					resource.TestCheckResourceAttr(resourceName, "ttl", "700"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

func testGCPSecretImpersonatedAccountDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

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

func testGCPSecretImpersonatedAccount_initial(backend, impersonatedAccount, credentials, serviceAccountEmail string) string {
	return fmt.Sprintf(`
%s

resource "vault_gcp_secret_impersonated_account" "test" {
	backend = vault_gcp_secret_backend.test.path
	impersonated_account = "%s"
	token_scopes   = ["https://www.googleapis.com/auth/cloud-platform"]
	service_account_email = "%s"
	ttl = 700
}
`, testGCPSecretImpersonatedAccount_backend(backend, credentials), impersonatedAccount, serviceAccountEmail)
}

func testGCPSecretImpersonatedAccount_updated(backend, impersonatedAccount, credentials, serviceAccountEmail string) string {
	return fmt.Sprintf(`
%s

resource "vault_gcp_secret_impersonated_account" "test" {
	backend = vault_gcp_secret_backend.test.path
	impersonated_account = "%s"
	token_scopes   = [
        "https://www.googleapis.com/auth/cloud-platform.read-only",
        "https://www.googleapis.com/auth/cloud-platform",
    ]
	service_account_email = "%s"
	ttl = 700
}
`, testGCPSecretImpersonatedAccount_backend(backend, credentials), impersonatedAccount, serviceAccountEmail)
}

func testGCPSecretImpersonatedAccount_backend(path, credentials string) string {
	return fmt.Sprintf(`
resource "vault_gcp_secret_backend" "test" {
	path = "%s"
	credentials = <<CREDS
%s
CREDS
}`, path, credentials)
}
