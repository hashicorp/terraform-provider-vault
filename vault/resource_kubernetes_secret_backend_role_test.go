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

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccKubernetesSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testKubernetesSecretBackendRole_initialConfig(backend, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedKubernetesNamespaces+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedKubernetesNamespaces+".0", "*"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountName, "test-service-account-with-generated-token"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenMaxTTL, "86400"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenDefaultTTL, "43200"),
				),
			},
			{
				Config: testKubernetesSecretBackendRole_UpdateConfig1(backend, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedKubernetesNamespaces+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedKubernetesNamespaces+".0", "dev"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedKubernetesNamespaces+".1", "int"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKubernetesRoleType, "Role"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGeneratedRoleRules, "rules:\n- apiGroups: [\"\"]\n  resources: [\"pods\"]\n  verbs: [\"list\"]\n"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountName, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenMaxTTL, "43200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenDefaultTTL, "21600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExtraLabels+".%", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExtraLabels+".id", "abc123"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExtraLabels+".name", "some_name"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExtraAnnotations+".%", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExtraAnnotations+".env", "development"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExtraAnnotations+".location", "earth"),
				),
			},
			{
				Config: testKubernetesSecretBackendRole_UpdateConfig2(backend, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedKubernetesNamespaces+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedKubernetesNamespaces+".0", "*"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGeneratedRoleRules, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountName, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKubernetesRoleType, "Role"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKubernetesRoleName, "existing_role"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenMaxTTL, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenDefaultTTL, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExtraLabels+".%", "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExtraAnnotations+".%", "0"),
				),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !meta.IsAPISupported(provider.VaultVersion112), nil
				},
				Config: testKubernetesSecretBackendRole_UpdateConfig3(backend, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedKubernetesNamespaceSelector, "{\"matchLabels\":{\"team\":\"hades\"}}"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGeneratedRoleRules, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountName, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKubernetesRoleType, "Role"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKubernetesRoleName, "existing_role"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenMaxTTL, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenDefaultTTL, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExtraLabels+".%", "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExtraAnnotations+".%", "0"),
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

func TestAccKubernetesSecretBackendRole_TokenDefaultAudiences(t *testing.T) {
	testutil.SkipTestEnvSet(t, testutil.EnvVarSkipVaultNext)

	resourceName := "vault_kubernetes_secret_backend_role.test"
	backend := acctest.RandomWithPrefix("tf-test-kubernetes")
	name := acctest.RandomWithPrefix("tf-test-role")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccKubernetesSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !meta.IsAPISupported(provider.VaultVersion115), nil
				},
				Config: testKubernetesSecretBackendRole_TokenDefaultAudiencesConfig(backend, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTokenDefaultAudiences+".#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenDefaultAudiences+".*", "https://kubernetes.default.svc"),
					resource.TestCheckTypeSetElemAttr(resourceName, consts.FieldTokenDefaultAudiences+".*", "https://api.example.com"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldServiceAccountName, "test-service-account"),
				),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !meta.IsAPISupported(provider.VaultVersion115), nil
				},
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

func testKubernetesSecretBackendRole_UpdateConfig3(backend, name string) string {
	return fmt.Sprintf(`
resource "vault_kubernetes_secret_backend" "backend" {
  path = "%s"
}

resource "vault_kubernetes_secret_backend_role" "test" {
  backend                               = vault_kubernetes_secret_backend.backend.path
  name                                  = "%s"
  allowed_kubernetes_namespace_selector = "{\"matchLabels\":{\"team\":\"hades\"}}"
  kubernetes_role_name                  = "existing_role"
}
`, backend, name)
}

func testKubernetesSecretBackendRole_TokenDefaultAudiencesConfig(backend, name string) string {
	return fmt.Sprintf(`
resource "vault_kubernetes_secret_backend" "backend" {
  path = "%s"
}

resource "vault_kubernetes_secret_backend_role" "test" {
  backend                       = vault_kubernetes_secret_backend.backend.path
  name                          = "%s"
  allowed_kubernetes_namespaces = ["*"]
  service_account_name          = "test-service-account"
  token_default_audiences       = ["https://kubernetes.default.svc", "https://api.example.com"]
  token_max_ttl                 = 86400
  token_default_ttl             = 43200
}
`, backend, name)
}
