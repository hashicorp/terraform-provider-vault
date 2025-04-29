// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// This test requires that you pass credentials for a user or service account having the IAM rights
// listed at https://www.vaultproject.io/docs/secrets/gcp/index.html for the project you are testing
// on. The credentials must also allow setting IAM permissions on the project being tested.
func TestGCPSecretRoleset(t *testing.T) {
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("tf-test-gcp")
	roleset := acctest.RandomWithPrefix("tf-test")
	credentials, project := testutil.GetTestGCPCreds(t)

	projectBaseURI := "//cloudresourcemanager.googleapis.com/projects/"

	initialRole := "roles/viewer"
	updatedRole := "roles/browser"

	resourceNameBackend := "vault_gcp_secret_backend.test"
	resourceName := "vault_gcp_secret_roleset.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testGCPSecretRolesetDestroy,
		Steps: []resource.TestStep{
			{
				Config: testGCPSecretRolesetConfig(backend, roleset, credentials, project, initialRole),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameBackend, consts.FieldPath, backend),
					resource.TestCheckResourceAttrSet(resourceName, "service_account_email"),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "roleset", roleset),
					resource.TestCheckResourceAttr(resourceName, "secret_type", "access_token"),
					resource.TestCheckResourceAttr(resourceName, "project", project),
					resource.TestCheckResourceAttr(resourceName, "token_scopes.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "token_scopes.0", "https://www.googleapis.com/auth/cloud-platform"),
					resource.TestCheckResourceAttr(resourceName, "binding.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "binding.0.resource", projectBaseURI+project),
					resource.TestCheckResourceAttr(resourceName, "binding.0.roles.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "binding.0.roles.0", initialRole),
					testGCPSecretRolesetAttrs(resourceName, backend, roleset),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{},
			},
			{
				Config: testGCPSecretRolesetConfig(backend, roleset, credentials, project, updatedRole),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameBackend, consts.FieldPath, backend),
					resource.TestCheckResourceAttrSet(resourceName, "service_account_email"),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "roleset", roleset),
					resource.TestCheckResourceAttr(resourceName, "secret_type", "access_token"),
					resource.TestCheckResourceAttr(resourceName, "project", project),
					resource.TestCheckResourceAttr(resourceName, "token_scopes.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "token_scopes.0", "https://www.googleapis.com/auth/cloud-platform"),
					resource.TestCheckResourceAttr(resourceName, "binding.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "binding.0.resource", projectBaseURI+project),
					resource.TestCheckResourceAttr(resourceName, "binding.0.roles.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "binding.0.roles.0", updatedRole),
					testGCPSecretRolesetAttrs(resourceName, backend, roleset),
				),
			},
			{
				Config: testGCPSecretRolesetServiceAccountKey(backend, roleset, credentials, project, updatedRole),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceNameBackend, consts.FieldPath, backend),
					resource.TestCheckResourceAttrSet(resourceName, "service_account_email"),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "roleset", roleset),
					resource.TestCheckResourceAttr(resourceName, "secret_type", "service_account_key"),
					resource.TestCheckResourceAttr(resourceName, "project", project),
					resource.TestCheckResourceAttr(resourceName, "binding.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "binding.0.resource", projectBaseURI+project),
					resource.TestCheckResourceAttr(resourceName, "binding.0.roles.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "binding.0.roles.0", updatedRole),
					testGCPSecretRolesetAttrs(resourceName, backend, roleset, "token_scopes"),
				),
			},
		},
	})
}

func testGCPSecretRolesetAttrs(resourceName, backend, roleset string, ignoreFields ...string) resource.TestCheckFunc {
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

		if path != backend+"/roleset/"+roleset {
			return fmt.Errorf("expected ID to be %q, got %q instead", backend+"/roleset/"+roleset, path)
		}

		attrs := map[string]string{
			"secret_type":           "secret_type",
			"project":               "project",
			"token_scopes":          "token_scopes",
			"service_account_email": "service_account_email",
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

		tAttrs = append(tAttrs,
			&testutil.VaultStateTest{
				ResourceName: resourceName,
				StateAttr:    "binding",
				VaultAttr:    "bindings",
				TransformVaultValue: func(st *testutil.VaultStateTest, resp *api.Secret) (interface{}, error) {
					result := []map[string]interface{}{}
					v, ok := resp.Data[st.VaultAttr]
					if !ok {
						return nil, fmt.Errorf("no value for %s", st)
					}

					for k, v := range v.(map[string]interface{}) {
						result = append(result, map[string]interface{}{
							"resource": k,
							"roles":    v,
						})
					}
					return result, nil
				},
			},
		)

		return testutil.AssertVaultState(client, s, path, tAttrs...)
	}
}

func testGCPSecretRolesetDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_gcp_secret_roleset" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for GCP Secrets Roleset %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("GCP Secrets Roleset %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testGCPSecretRolesetConfig(backend, roleSet, credentials, project, role string) string {
	projectURI := fmt.Sprintf("//cloudresourcemanager.googleapis.com/projects/%s", project)
	config := fmt.Sprintf(`
resource "vault_gcp_secret_backend" "test" {
  path = "%s"
  credentials = <<CREDS
%s
CREDS
}

resource "vault_gcp_secret_roleset" "test" {
  backend = vault_gcp_secret_backend.test.path
  roleset = "%s"
  secret_type = "access_token"
  project = "%s"
  token_scopes = ["https://www.googleapis.com/auth/cloud-platform"]

  binding {
    resource = "%s"
    roles = ["%s"]
  }
}
`, backend, credentials, roleSet, project, projectURI, role)

	return config
}

func testGCPSecretRolesetServiceAccountKey(backend, roleset, credentials, project, role string) string {
	projectURI := fmt.Sprintf("//cloudresourcemanager.googleapis.com/projects/%s", project)
	config := fmt.Sprintf(`
resource "vault_gcp_secret_backend" "test" {
  path = "%s"
  credentials = <<CREDS
%s
CREDS
}

resource "vault_gcp_secret_roleset" "test" {
  backend = vault_gcp_secret_backend.test.path
  roleset = "%s"
  secret_type = "service_account_key"
  project = "%s"

  binding {
    resource = "%s"
    roles = ["%s"]
  }
}
`, backend, credentials, roleset, project, projectURI, role)

	return config
}
