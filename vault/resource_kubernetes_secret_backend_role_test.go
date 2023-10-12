// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKubernetesSecretBackendRole(t *testing.T) {
	testutil.SkipTestEnvSet(t, testutil.EnvVarSkipVaultNext)

	resourceName := "vault_kubernetes_secret_backend_role.test"
	backend := acctest.RandomWithPrefix("tf-test-kubernetes")
	name := acctest.RandomWithPrefix("tf-test-role")

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:      testAccKubernetesSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testKubernetesSecretBackendRole_initialConfig(backend, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, fieldAllowedKubernetesNamespaces+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, fieldAllowedKubernetesNamespaces+".0", "*"),
					resource.TestCheckResourceAttr(resourceName, fieldServiceAccountName, "test-service-account-with-generated-token"),
					resource.TestCheckResourceAttr(resourceName, fieldTokenMaxTTL, "86400"),
					resource.TestCheckResourceAttr(resourceName, fieldTokenDefaultTTL, "43200"),
				),
			},
			{
				Config: testKubernetesSecretBackendRole_UpdateConfig1(backend, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, fieldAllowedKubernetesNamespaces+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, fieldAllowedKubernetesNamespaces+".0", "dev"),
					resource.TestCheckResourceAttr(resourceName, fieldAllowedKubernetesNamespaces+".1", "int"),
					resource.TestCheckResourceAttr(resourceName, fieldKubernetesRoleType, "Role"),
					resource.TestCheckResourceAttr(resourceName, fieldGeneratedRoleRules, "rules:\n- apiGroups: [\"\"]\n  resources: [\"pods\"]\n  verbs: [\"list\"]\n"),
					resource.TestCheckResourceAttr(resourceName, fieldServiceAccountName, ""),
					resource.TestCheckResourceAttr(resourceName, fieldTokenMaxTTL, "43200"),
					resource.TestCheckResourceAttr(resourceName, fieldTokenDefaultTTL, "21600"),
					resource.TestCheckResourceAttr(resourceName, fieldExtraLabels+".%", "2"),
					resource.TestCheckResourceAttr(resourceName, fieldExtraLabels+".id", "abc123"),
					resource.TestCheckResourceAttr(resourceName, fieldExtraLabels+".name", "some_name"),
					resource.TestCheckResourceAttr(resourceName, fieldExtraAnnotations+".%", "2"),
					resource.TestCheckResourceAttr(resourceName, fieldExtraAnnotations+".env", "development"),
					resource.TestCheckResourceAttr(resourceName, fieldExtraAnnotations+".location", "earth"),
				),
			},
			{
				Config: testKubernetesSecretBackendRole_UpdateConfig2(backend, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, fieldAllowedKubernetesNamespaces+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, fieldAllowedKubernetesNamespaces+".0", "*"),
					resource.TestCheckResourceAttr(resourceName, fieldGeneratedRoleRules, ""),
					resource.TestCheckResourceAttr(resourceName, fieldServiceAccountName, ""),
					resource.TestCheckResourceAttr(resourceName, fieldKubernetesRoleType, "Role"),
					resource.TestCheckResourceAttr(resourceName, fieldKubernetesRoleName, "existing_role"),
					resource.TestCheckResourceAttr(resourceName, fieldTokenMaxTTL, "0"),
					resource.TestCheckResourceAttr(resourceName, fieldTokenDefaultTTL, "0"),
					resource.TestCheckResourceAttr(resourceName, fieldExtraLabels+".%", "0"),
					resource.TestCheckResourceAttr(resourceName, fieldExtraAnnotations+".%", "0"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldServiceAccountJWT},
			},
		},
	})
}

func testAccKubernetesSecretBackendRoleCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_kubernetes_secret_backend_role" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for Kubernetes secret backend role %q: %s",
				rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("kubernetes secret backend role %q still exists", rs.Primary.ID)
		}
	}

	return nil
}

func testKubernetesSecretBackendRole_initialConfig(backend, name string) string {
	return fmt.Sprintf(`
resource "vault_kubernetes_secret_backend" "backend" {
  path = "%s"
}

resource "vault_kubernetes_secret_backend_role" "test" {
  backend                       = vault_kubernetes_secret_backend.backend.path
  name                          = "%s"
  allowed_kubernetes_namespaces = ["*"]
  service_account_name          = "test-service-account-with-generated-token"
  token_max_ttl                 = 86400
  token_default_ttl             = 43200
}
`, backend, name)
}

func testKubernetesSecretBackendRole_UpdateConfig1(backend, name string) string {
	return fmt.Sprintf(`
resource "vault_kubernetes_secret_backend" "backend" {
  path = "%s"
}

resource "vault_kubernetes_secret_backend_role" "test" {
  backend                       = vault_kubernetes_secret_backend.backend.path
  name                          = "%s"
  allowed_kubernetes_namespaces = ["dev", "int"]
  generated_role_rules          = "rules:\n- apiGroups: [\"\"]\n  resources: [\"pods\"]\n  verbs: [\"list\"]\n"
  kubernetes_role_type          = "Role"
  token_max_ttl                 = 43200
  token_default_ttl             = 21600
  extra_labels = {
    id = "abc123"
    name = "some_name"
  }
  extra_annotations = {
    env = "development"
    location = "earth"
  }
}
`, backend, name)
}

func testKubernetesSecretBackendRole_UpdateConfig2(backend, name string) string {
	return fmt.Sprintf(`
resource "vault_kubernetes_secret_backend" "backend" {
  path = "%s"
}

resource "vault_kubernetes_secret_backend_role" "test" {
  backend                       = vault_kubernetes_secret_backend.backend.path
  name                          = "%s"
  allowed_kubernetes_namespaces = ["*"]
  kubernetes_role_name          = "existing_role"
}
`, backend, name)
}
