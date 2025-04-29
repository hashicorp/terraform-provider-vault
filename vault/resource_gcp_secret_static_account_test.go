// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"golang.org/x/oauth2/google"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// This test requires that you pass credentials for a user or service account having the IAM rights
// listed at https://www.vaultproject.io/docs/secrets/gcp/index.html for the project you are testing
// on. The credentials must also allow setting IAM permissions on the project being tested.
func TestGCPSecretStaticAccount(t *testing.T) {
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("tf-test-gcp")
	staticAccount := acctest.RandomWithPrefix("tf-test")
	credentials, project := testutil.GetTestGCPCreds(t)

	projectBaseURI := "//cloudresourcemanager.googleapis.com/projects/"

	// We will use the provided key as the static account
	conf, err := google.JWTConfigFromJSON([]byte(credentials), "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		t.Fatalf("error decoding GCP Credentials: %v", err)
	}
	serviceAccountEmail := conf.Email

	noBindings := testGCPSecretStaticAccount_accessToken(backend, staticAccount, credentials, serviceAccountEmail, project)

	initialRole := "roles/viewer"
	initialConfig := testGCPSecretStaticAccount_accessTokenBinding(backend, staticAccount, credentials, serviceAccountEmail, project, initialRole)

	updatedRole := "roles/browser"
	updatedConfig := testGCPSecretStaticAccount_accessTokenBinding(backend, staticAccount, credentials, serviceAccountEmail, project, updatedRole)

	keyConfig := testGCPSecretStaticAccount_serviceAccountKey(backend, staticAccount, credentials, serviceAccountEmail, project, updatedRole)

	resourceNameBackend := "vault_gcp_secret_backend.test"
	resourceName := "vault_gcp_secret_static_account.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testGCPSecretStaticAccountDestroy,
		Steps: []resource.TestStep{
			{
				Config: noBindings,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameBackend, consts.FieldPath, backend),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "static_account", staticAccount),
					resource.TestCheckResourceAttr(resourceName, "secret_type", "access_token"),
					resource.TestCheckResourceAttr(resourceName, "service_account_email", serviceAccountEmail),
					resource.TestCheckResourceAttr(resourceName, "service_account_project", project),
					resource.TestCheckResourceAttr(resourceName, "token_scopes.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "token_scopes.0", "https://www.googleapis.com/auth/cloud-platform"),
					testGCPSecretStaticAccountAttrs(resourceName, backend, staticAccount),
				),
			},
			{
				Config: initialConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameBackend, consts.FieldPath, backend),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "static_account", staticAccount),
					resource.TestCheckResourceAttr(resourceName, "secret_type", "access_token"),
					resource.TestCheckResourceAttr(resourceName, "service_account_email", serviceAccountEmail),
					resource.TestCheckResourceAttr(resourceName, "service_account_project", project),
					resource.TestCheckResourceAttr(resourceName, "token_scopes.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "token_scopes.0", "https://www.googleapis.com/auth/cloud-platform"),
					resource.TestCheckResourceAttr(resourceName, "binding.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "binding.0.resource", projectBaseURI+project),
					resource.TestCheckResourceAttr(resourceName, "binding.0.roles.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "binding.0.roles.0", initialRole),
					testGCPSecretStaticAccountAttrs(resourceName, backend, staticAccount),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{},
			},
			{
				Config: updatedConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameBackend, consts.FieldPath, backend),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "static_account", staticAccount),
					resource.TestCheckResourceAttr(resourceName, "secret_type", "access_token"),
					resource.TestCheckResourceAttr(resourceName, "service_account_email", serviceAccountEmail),
					resource.TestCheckResourceAttr(resourceName, "service_account_project", project),
					resource.TestCheckResourceAttr(resourceName, "token_scopes.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "token_scopes.0", "https://www.googleapis.com/auth/cloud-platform"),
					resource.TestCheckResourceAttr(resourceName, "binding.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "binding.0.resource", fmt.Sprintf("//cloudresourcemanager.googleapis.com/projects/%s", project)),
					resource.TestCheckResourceAttr(resourceName, "binding.0.roles.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "binding.0.roles.0", updatedRole),
					testGCPSecretStaticAccountAttrs(resourceName, backend, staticAccount),
				),
			},
			{
				Config: keyConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameBackend, consts.FieldPath, backend),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "static_account", staticAccount),
					resource.TestCheckResourceAttr(resourceName, "secret_type", "service_account_key"),
					resource.TestCheckResourceAttr(resourceName, "service_account_email", serviceAccountEmail),
					resource.TestCheckResourceAttr(resourceName, "service_account_project", project),
					resource.TestCheckResourceAttr(resourceName, "binding.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "binding.0.resource", projectBaseURI+project),
					resource.TestCheckResourceAttr(resourceName, "binding.0.roles.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "binding.0.roles.0", updatedRole),
					testGCPSecretStaticAccountAttrs(resourceName, backend, staticAccount, "token_scopes"),
				),
			},
		},
	})
}

func testGCPSecretStaticAccountAttrs(resourceName, backend, staticAccount string, ignoreFields ...string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		client, err := provider.GetClient(rs.Primary, testProvider.Meta())
		if err != nil {
			return err
		}

		path := rs.Primary.ID

		expectedPath := backend + "/static-account/" + staticAccount
		if path != expectedPath {
			return fmt.Errorf("expected ID to be %q, got %q instead", expectedPath, path)
		}

		attrs := map[string]string{
			"secret_type":             "secret_type",
			"service_account_project": "service_account_project",
			"token_scopes":            "token_scopes",
			"service_account_email":   "service_account_email",
		}

		tAttrs := []*testutil.VaultStateTest{}
		for k, v := range attrs {
			var skip bool
			for _, f := range ignoreFields {
				if k == f {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
			ta := &testutil.VaultStateTest{
				ResourceName: resourceName,
				StateAttr:    k,
				VaultAttr:    v,
			}

			tAttrs = append(tAttrs, ta)
		}

		return testutil.AssertVaultState(client, s, path, tAttrs...)
	}
}

func testGCPSecretStaticAccountDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_gcp_secret_static_account" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for GCP Secrets StaticAccount %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("GCP Secrets StaticAccount %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testGCPSecretStaticAccount_accessToken(backend, staticAccount, credentials, serviceAccountEmail, project string) string {
	return fmt.Sprintf(`
resource "vault_gcp_secret_backend" "test" {
  path = "%s"
  credentials = <<CREDS
%s
CREDS
}

resource "vault_gcp_secret_static_account" "test" {
  backend 			 = vault_gcp_secret_backend.test.path
	static_account = "%s"
  secret_type 	 = "access_token"
  token_scopes   = ["https://www.googleapis.com/auth/cloud-platform"]

	service_account_email = "%s"
}
`, backend, credentials, staticAccount, serviceAccountEmail)
}

func testGCPSecretStaticAccount_accessTokenBinding(backend, staticAccount, credentials, serviceAccountEmail, project, role string) string {
	projectURI := fmt.Sprintf("//cloudresourcemanager.googleapis.com/projects/%s", project)
	config := fmt.Sprintf(`
resource "vault_gcp_secret_backend" "test" {
  path = "%s"
  credentials = <<CREDS
%s
CREDS
}

resource "vault_gcp_secret_static_account" "test" {
  backend 			 = vault_gcp_secret_backend.test.path
	static_account = "%s"
  secret_type 	 = "access_token"
  token_scopes   = ["https://www.googleapis.com/auth/cloud-platform"]

	service_account_email = "%s"

  binding {
    resource = "%s"
    roles = ["%s"]
  }
}
`, backend, credentials, staticAccount, serviceAccountEmail, projectURI, role)

	return config
}

func testGCPSecretStaticAccount_serviceAccountKey(backend, staticAccount, credentials, serviceAccountEmail, project, role string) string {
	projectURI := fmt.Sprintf("//cloudresourcemanager.googleapis.com/projects/%s", project)

	config := fmt.Sprintf(`
resource "vault_gcp_secret_backend" "test" {
  path = "%s"
  credentials = <<CREDS
%s
CREDS
}

resource "vault_gcp_secret_static_account" "test" {
  backend 			 = vault_gcp_secret_backend.test.path
	static_account = "%s"
  secret_type 	 = "service_account_key"
  token_scopes   = ["https://www.googleapis.com/auth/cloud-platform"]

	service_account_email = "%s"

  binding {
    resource = "%s"
    roles = ["%s"]
  }
}
`, backend, credentials, staticAccount, serviceAccountEmail, projectURI, role)

	return config
}
